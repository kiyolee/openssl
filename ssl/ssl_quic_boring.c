/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ssl_local.h"
#include "internal/cryptlib.h"
#include "internal/refcount.h"

#ifdef OPENSSL_NO_QUIC_BORING
NON_EMPTY_TRANSLATION_UNIT
#else

int SSL_set_quic_boring_transport_params(SSL *ssl, const uint8_t *params,
                                         size_t params_len)
{
    uint8_t *tmp;
    SSL_CONNECTION* sc = SSL_CONNECTION_FROM_SSL(ssl);

    if (params == NULL || params_len == 0) {
        tmp = NULL;
        params_len = 0;
    } else {
        tmp = OPENSSL_memdup(params, params_len);
        if (tmp == NULL)
            return 0;
    }

    OPENSSL_free(sc->ext.quic_boring_transport_params);
    sc->ext.quic_boring_transport_params = tmp;
    sc->ext.quic_boring_transport_params_len = params_len;
    return 1;
}

void SSL_get_peer_quic_boring_transport_params(const SSL *ssl,
                                               const uint8_t **out_params,
                                               size_t *out_params_len)
{
    SSL_CONNECTION* sc = SSL_CONNECTION_FROM_SSL(ssl);
    if (sc->ext.peer_quic_boring_transport_params_v1_len) {
        *out_params = sc->ext.peer_quic_boring_transport_params_v1;
        *out_params_len = sc->ext.peer_quic_boring_transport_params_v1_len;
    } else {
        *out_params = sc->ext.peer_quic_boring_transport_params_draft;
        *out_params_len = sc->ext.peer_quic_boring_transport_params_draft_len;
    }
}

size_t SSL_quic_boring_max_handshake_flight_len(const SSL *ssl, OSSL_QUIC_BORING_ENCRYPTION_LEVEL level)
{
    /*
     * Limits flights to 16K by default when there are no large
     * (certificate-carrying) messages.
     */
    static const size_t DEFAULT_FLIGHT_LIMIT = 16384;
    SSL_CONNECTION* sc = SSL_CONNECTION_FROM_SSL(ssl);

    switch (level) {
    case ssl_quic_boring_encryption_initial:
        return DEFAULT_FLIGHT_LIMIT;
    case ssl_quic_boring_encryption_early_data:
        /* QUIC does not send EndOfEarlyData. */
        return 0;
    case ssl_quic_boring_encryption_handshake:
        if (sc->server) {
            /*
             * Servers may receive Certificate message if configured to request
             * client certificates.
             */
            if ((sc->verify_mode & SSL_VERIFY_PEER)
                    && sc->max_cert_list > DEFAULT_FLIGHT_LIMIT)
                return sc->max_cert_list;
        } else {
            /*
             * Clients may receive both Certificate message and a CertificateRequest
             * message.
             */
            if (2*sc->max_cert_list > DEFAULT_FLIGHT_LIMIT)
                return 2 * sc->max_cert_list;
        }
        return DEFAULT_FLIGHT_LIMIT;
    case ssl_quic_boring_encryption_application:
        return DEFAULT_FLIGHT_LIMIT;
    }

    return 0;
}

OSSL_QUIC_BORING_ENCRYPTION_LEVEL SSL_quic_boring_read_level(const SSL *ssl)
{
    return SSL_CONNECTION_FROM_SSL(ssl)->quic_boring_read_level;
}

OSSL_QUIC_BORING_ENCRYPTION_LEVEL SSL_quic_boring_write_level(const SSL *ssl)
{
    return SSL_CONNECTION_FROM_SSL(ssl)->quic_boring_write_level;
}

int SSL_provide_quic_boring_data(SSL *ssl, OSSL_QUIC_BORING_ENCRYPTION_LEVEL level,
                                 const uint8_t *data, size_t len)
{
    size_t l;
    QUIC_BORING_DATA *qd;
    SSL_CONNECTION* sc = SSL_CONNECTION_FROM_SSL(ssl);

    if (!SSL_CONNECTION_IS_QUIC_BORING(sc)) {
        SSLerr(SSL_F_SSL_PROVIDE_QUIC_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    /* Level can be different than the current read, but not less */
    if (level < sc->quic_boring_read_level
            || (sc->quic_boring_input_data_tail != NULL && level < sc->quic_boring_input_data_tail->level)) {
        SSLerr(SSL_F_SSL_PROVIDE_QUIC_DATA, SSL_R_QUIC_BORING_WRONG_ENCRYPTION_LEVEL_RECEIVED);
        return 0;
    }

    if (len == 0) {
      return 1;
    }

    /* Check for an incomplete block */
    qd = sc->quic_boring_input_data_tail;
    if (qd != NULL) {
        l = qd->length - qd->offset;
        if (l != 0) {
            /* we still need to copy `l` bytes into the last data block */
            if (l > len)
                l = len;
            memcpy((char *)(qd + 1) + qd->offset, data, l);
            qd->offset += l;
            len -= l;
            data += l;
        }
    }

    /* Split the QUIC messages up, if necessary */
    while (len > 0) {
        QUIC_BORING_DATA *qd;
        const uint8_t *p;
        uint8_t *dst;

        if (sc->quic_boring_msg_hd_offset != 0) {
            /* If we have already buffered premature message header,
               try to add new data to it to form complete message
               header. */
            size_t nread =
                SSL3_HM_HEADER_LENGTH - sc->quic_boring_msg_hd_offset;
            if (len < nread) {
                nread = len;
            }
            memcpy(sc->quic_boring_msg_hd + sc->quic_boring_msg_hd_offset, data, nread);
            sc->quic_boring_msg_hd_offset += nread;

            if (sc->quic_boring_msg_hd_offset < SSL3_HM_HEADER_LENGTH) {
                /* We still have premature message header. */
                break;
            }
            data += nread;
            len -= nread;
            p = sc->quic_boring_msg_hd + 1;
            n2l3(p, l);
        } else if (len < SSL3_HM_HEADER_LENGTH) {
            /* We don't get complete message header.  Just buffer the
               received data and wait for the next data to arrive. */
            memcpy(sc->quic_boring_msg_hd, data, len);
            sc->quic_boring_msg_hd_offset += len;
            break;
        } else {
            /* We have complete message header in data. */
            p = data + 1;
            n2l3(p, l);
        }
        l += SSL3_HM_HEADER_LENGTH;

        qd = OPENSSL_zalloc(sizeof(QUIC_BORING_DATA) + l);
        if (qd == NULL) {
            SSLerr(SSL_F_SSL_PROVIDE_QUIC_DATA, SSL_R_QUIC_BORING_INTERNAL_ERROR);
            return 0;
        }

        qd->next = NULL;
        qd->length = l;
        qd->level = level;

        dst = (uint8_t *)(qd + 1);
        if (sc->quic_boring_msg_hd_offset) {
            memcpy(dst, sc->quic_boring_msg_hd, sc->quic_boring_msg_hd_offset);
            dst += sc->quic_boring_msg_hd_offset;
            l -= SSL3_HM_HEADER_LENGTH;
            if (l > len)
                l = len;
            qd->offset = SSL3_HM_HEADER_LENGTH + l;
            memcpy(dst, data, l);
        } else {
            /* partial data received? */
            if (l > len)
                l = len;
            qd->offset = l;
            memcpy(dst, data, l);
        }
        if (sc->quic_boring_input_data_tail != NULL)
            sc->quic_boring_input_data_tail->next = qd;
        else
            sc->quic_boring_input_data_head = qd;
        sc->quic_boring_input_data_tail = qd;

        data += l;
        len -= l;

        sc->quic_boring_msg_hd_offset = 0;
    }

    return 1;
}

int SSL_CTX_set_quic_boring_method(SSL_CTX *ctx, const SSL_QUIC_BORING_METHOD *quic_boring_method)
{
    switch (ctx->method->version) {
    case DTLS1_VERSION:
    case DTLS1_2_VERSION:
    case DTLS_ANY_VERSION:
    case DTLS1_BAD_VER:
        return 0;
    default:
        break;
    }
    ctx->quic_boring_method = quic_boring_method;
    ctx->options &= ~SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
    return 1;
}

int SSL_set_quic_boring_method(SSL *ssl, const SSL_QUIC_BORING_METHOD *quic_boring_method)
{
    SSL_CONNECTION* sc = SSL_CONNECTION_FROM_SSL(ssl);
    switch (ssl->method->version) {
    case DTLS1_VERSION:
    case DTLS1_2_VERSION:
    case DTLS_ANY_VERSION:
    case DTLS1_BAD_VER:
        return 0;
    default:
        break;
    }
    sc->quic_boring_method = quic_boring_method;
    sc->options &= ~SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
    return 1;
}

int quic_boring_set_encryption_secrets(SSL_CONNECTION *sc, OSSL_QUIC_BORING_ENCRYPTION_LEVEL level)
{
    uint8_t *c2s_secret = NULL;
    uint8_t *s2c_secret = NULL;
    size_t len;
    const EVP_MD *md;

    if (!SSL_CONNECTION_IS_QUIC_BORING(sc))
        return 1;

    /* secrets from the POV of the client */
    switch (level) {
    case ssl_quic_boring_encryption_early_data:
        c2s_secret = sc->quic_boring_client_early_traffic_secret;
        break;
    case ssl_quic_boring_encryption_handshake:
        c2s_secret = sc->quic_boring_client_hand_traffic_secret;
        s2c_secret = sc->quic_boring_server_hand_traffic_secret;
        break;
    case ssl_quic_boring_encryption_application:
        c2s_secret = sc->client_app_traffic_secret;
        s2c_secret = sc->server_app_traffic_secret;
        break;
    default:
        return 1;
    }

    md = ssl_handshake_md(sc);
    if (md == NULL) {
        /* May not have selected cipher, yet */
        const SSL_CIPHER *c = NULL;

        if (sc->session != NULL)
            c = SSL_SESSION_get0_cipher(sc->session);
        else if (sc->psksession != NULL)
            c = SSL_SESSION_get0_cipher(sc->psksession);

        if (c != NULL)
            md = SSL_CIPHER_get_handshake_digest(c);
    }

    if ((len = EVP_MD_size(md)) <= 0) {
        SSLfatal(sc, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    if (sc->server) {
        if (!sc->quic_boring_method->set_encryption_secrets(SSL_CONNECTION_GET_SSL(sc), level, c2s_secret,
                                                            s2c_secret, len)) {
            SSLfatal(sc, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        if (!sc->quic_boring_method->set_encryption_secrets(SSL_CONNECTION_GET_SSL(sc), level, s2c_secret,
                                                            c2s_secret, len)) {
            SSLfatal(sc, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return 1;
}

int SSL_process_quic_boring_post_handshake(SSL *ssl)
{
    int ret;
    SSL_CONNECTION* sc = SSL_CONNECTION_FROM_SSL(ssl);

    if (SSL_in_init(ssl) || !SSL_CONNECTION_IS_QUIC_BORING(sc)) {
        SSLerr(SSL_F_SSL_PROCESS_QUIC_POST_HANDSHAKE, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    ossl_statem_set_in_init(sc, 1);
    ret = sc->handshake_func(ssl);
    ossl_statem_set_in_init(sc, 0);

    if (ret <= 0)
        return 0;
    return 1;
}

int SSL_is_quic_boring(const SSL *ssl)
{
    return SSL_CONNECTION_IS_QUIC_BORING(SSL_CONNECTION_FROM_SSL(ssl));
}

void SSL_set_quic_boring_early_data_enabled(SSL *ssl, int enabled)
{
    SSL_CONNECTION* sc = SSL_CONNECTION_FROM_SSL(ssl);

    if (!SSL_is_quic_boring(ssl) || !SSL_in_before(ssl))
        return;

    if (sc->server) {
        sc->early_data_state = SSL_EARLY_DATA_ACCEPTING;
        return;
    }

    if (((sc->session == NULL || sc->session->ext.max_early_data == 0)
         && (sc->psk_use_session_cb == NULL)))
        return;

    sc->early_data_state = SSL_EARLY_DATA_CONNECTING;
}

#endif