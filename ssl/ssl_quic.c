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

int SSL_set_quic_transport_params(SSL *ssl, const uint8_t *params,
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

    OPENSSL_free(sc->ext.quic_transport_params);
    sc->ext.quic_transport_params = tmp;
    sc->ext.quic_transport_params_len = params_len;
    return 1;
}

void SSL_get_peer_quic_transport_params(const SSL *ssl,
                                        const uint8_t **out_params,
                                        size_t *out_params_len)
{
    SSL_CONNECTION* sc = SSL_CONNECTION_FROM_SSL(ssl);
    *out_params = sc->ext.peer_quic_transport_params;
    *out_params_len = sc->ext.peer_quic_transport_params_len;
}

size_t SSL_quic_max_handshake_flight_len(const SSL *ssl, OSSL_ENCRYPTION_LEVEL level)
{
    /*
     * Limits flights to 16K by default when there are no large
     * (certificate-carrying) messages.
     */
    static const size_t DEFAULT_FLIGHT_LIMIT = 16384;
    SSL_CONNECTION* sc = SSL_CONNECTION_FROM_SSL(ssl);

    switch (level) {
    case ssl_encryption_initial:
        return DEFAULT_FLIGHT_LIMIT;
    case ssl_encryption_early_data:
        /* QUIC does not send EndOfEarlyData. */
        return 0;
    case ssl_encryption_handshake:
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
    case ssl_encryption_application:
        return DEFAULT_FLIGHT_LIMIT;
    }

    return 0;
}

OSSL_ENCRYPTION_LEVEL SSL_quic_read_level(const SSL *ssl)
{
    return SSL_CONNECTION_FROM_SSL(ssl)->quic_read_level;
}

OSSL_ENCRYPTION_LEVEL SSL_quic_write_level(const SSL *ssl)
{
    return SSL_CONNECTION_FROM_SSL(ssl)->quic_write_level;
}

int SSL_provide_quic_data(SSL *ssl, OSSL_ENCRYPTION_LEVEL level,
                          const uint8_t *data, size_t len)
{
    size_t l;
    SSL_CONNECTION* sc = SSL_CONNECTION_FROM_SSL(ssl);

    if (!SSL_CONNECTION_IS_QUIC(sc)) {
        SSLerr(SSL_F_SSL_PROVIDE_QUIC_DATA, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
        return 0;
    }

    /* Level can be different than the current read, but not less */
    if (level < sc->quic_read_level
            || (sc->quic_input_data_tail != NULL && level < sc->quic_input_data_tail->level)) {
        SSLerr(SSL_F_SSL_PROVIDE_QUIC_DATA, SSL_R_WRONG_ENCRYPTION_LEVEL_RECEIVED);
        return 0;
    }

    /* Split the QUIC messages up, if necessary */
    while (len > 0) {
        QUIC_DATA *qd;
        const uint8_t *p = data + 1;

        n2l3(p, l);
        l += SSL3_HM_HEADER_LENGTH;

        qd = OPENSSL_zalloc(sizeof(QUIC_DATA) + l);
        if (qd == NULL) {
            SSLerr(SSL_F_SSL_PROVIDE_QUIC_DATA, SSL_R_INTERNAL_ERROR);
            return 0;
        }

        qd->next = NULL;
        qd->length = l;
        qd->level = level;
        memcpy((void*)(qd + 1), data, l);
        if (sc->quic_input_data_tail != NULL)
            sc->quic_input_data_tail->next = qd;
        else
            sc->quic_input_data_head = qd;
        sc->quic_input_data_tail = qd;

        data += l;
        len -= l;
    }

    return 1;
}

int SSL_CTX_set_quic_method(SSL_CTX *ctx, const SSL_QUIC_METHOD *quic_method)
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
    ctx->quic_method = quic_method;
    ctx->options &= SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
    return 1;
}

int SSL_set_quic_method(SSL *ssl, const SSL_QUIC_METHOD *quic_method)
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
    sc->quic_method = quic_method;
    sc->options &= SSL_OP_ENABLE_MIDDLEBOX_COMPAT;
    return 1;
}

int quic_set_encryption_secrets(SSL_CONNECTION *sc, OSSL_ENCRYPTION_LEVEL level)
{
    uint8_t *c2s_secret = NULL;
    uint8_t *s2c_secret = NULL;
    size_t len;
    const EVP_MD *md;
    static const unsigned char zeros[EVP_MAX_MD_SIZE];

    if (!SSL_CONNECTION_IS_QUIC(sc))
        return 1;

    /* secrets from the POV of the client */
    switch (level) {
    case ssl_encryption_early_data:
        s2c_secret = sc->early_secret;
        break;
    case ssl_encryption_handshake:
        c2s_secret = sc->client_hand_traffic_secret;
        s2c_secret = sc->server_hand_traffic_secret;
        break;
    case ssl_encryption_application:
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

    /* In some cases, we want to set the secret only when BOTH are non-zero */
    if (c2s_secret != NULL && s2c_secret != NULL
            && !memcmp(c2s_secret, zeros, len)
            && !memcmp(s2c_secret, zeros, len))
        return 1;

    if (sc->server) {
        if (!sc->quic_method->set_encryption_secrets(SSL_CONNECTION_GET_SSL(sc), level, c2s_secret,
                                                     s2c_secret, len)) {
            SSLfatal(sc, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    } else {
        if (!sc->quic_method->set_encryption_secrets(SSL_CONNECTION_GET_SSL(sc), level, s2c_secret,
                                                     c2s_secret, len)) {
            SSLfatal(sc, SSL_AD_INTERNAL_ERROR, ERR_R_INTERNAL_ERROR);
            return 0;
        }
    }

    return 1;
}

int SSL_process_quic_post_handshake(SSL *ssl)
{
    int ret;
    SSL_CONNECTION* sc = SSL_CONNECTION_FROM_SSL(ssl);

    if (SSL_in_init(ssl) || !SSL_CONNECTION_IS_QUIC(sc)) {
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

int SSL_is_quic(SSL* ssl)
{
    return SSL_CONNECTION_IS_QUIC(SSL_CONNECTION_FROM_SSL(ssl));
}

#endif
