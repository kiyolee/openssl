/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*
 * Generated from der_slh_dsa.h.in for https://github.com/kiyolee/openssl.git.
 */

#include "internal/der.h"
#include "crypto/slh_dsa.h"

/* Well known OIDs precompiled */

/*
 * id-slh-dsa-sha2-128s OBJECT IDENTIFIER ::= { sigAlgs 20 }
 */
#define DER_OID_V_id_slh_dsa_sha2_128s DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14
#define DER_OID_SZ_id_slh_dsa_sha2_128s 11
extern const unsigned char ossl_der_oid_id_slh_dsa_sha2_128s[DER_OID_SZ_id_slh_dsa_sha2_128s];

/*
 * id-slh-dsa-sha2-128f OBJECT IDENTIFIER ::= { sigAlgs 21 }
 */
#define DER_OID_V_id_slh_dsa_sha2_128f DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x15
#define DER_OID_SZ_id_slh_dsa_sha2_128f 11
extern const unsigned char ossl_der_oid_id_slh_dsa_sha2_128f[DER_OID_SZ_id_slh_dsa_sha2_128f];

/*
 * id-slh-dsa-sha2-192s OBJECT IDENTIFIER ::= { sigAlgs 22 }
 */
#define DER_OID_V_id_slh_dsa_sha2_192s DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x16
#define DER_OID_SZ_id_slh_dsa_sha2_192s 11
extern const unsigned char ossl_der_oid_id_slh_dsa_sha2_192s[DER_OID_SZ_id_slh_dsa_sha2_192s];

/*
 * id-slh-dsa-sha2-192f OBJECT IDENTIFIER ::= { sigAlgs 23 }
 */
#define DER_OID_V_id_slh_dsa_sha2_192f DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x17
#define DER_OID_SZ_id_slh_dsa_sha2_192f 11
extern const unsigned char ossl_der_oid_id_slh_dsa_sha2_192f[DER_OID_SZ_id_slh_dsa_sha2_192f];

/*
 * id-slh-dsa-sha2-256s OBJECT IDENTIFIER ::= { sigAlgs 24 }
 */
#define DER_OID_V_id_slh_dsa_sha2_256s DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x18
#define DER_OID_SZ_id_slh_dsa_sha2_256s 11
extern const unsigned char ossl_der_oid_id_slh_dsa_sha2_256s[DER_OID_SZ_id_slh_dsa_sha2_256s];

/*
 * id-slh-dsa-sha2-256f OBJECT IDENTIFIER ::= { sigAlgs 25 }
 */
#define DER_OID_V_id_slh_dsa_sha2_256f DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x19
#define DER_OID_SZ_id_slh_dsa_sha2_256f 11
extern const unsigned char ossl_der_oid_id_slh_dsa_sha2_256f[DER_OID_SZ_id_slh_dsa_sha2_256f];

/*
 * id-slh-dsa-shake-128s OBJECT IDENTIFIER ::= { sigAlgs 26 }
 */
#define DER_OID_V_id_slh_dsa_shake_128s DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1A
#define DER_OID_SZ_id_slh_dsa_shake_128s 11
extern const unsigned char ossl_der_oid_id_slh_dsa_shake_128s[DER_OID_SZ_id_slh_dsa_shake_128s];

/*
 * id-slh-dsa-shake-128f OBJECT IDENTIFIER ::= { sigAlgs 27 }
 */
#define DER_OID_V_id_slh_dsa_shake_128f DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1B
#define DER_OID_SZ_id_slh_dsa_shake_128f 11
extern const unsigned char ossl_der_oid_id_slh_dsa_shake_128f[DER_OID_SZ_id_slh_dsa_shake_128f];

/*
 * id-slh-dsa-shake-192s OBJECT IDENTIFIER ::= { sigAlgs 28 }
 */
#define DER_OID_V_id_slh_dsa_shake_192s DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1C
#define DER_OID_SZ_id_slh_dsa_shake_192s 11
extern const unsigned char ossl_der_oid_id_slh_dsa_shake_192s[DER_OID_SZ_id_slh_dsa_shake_192s];

/*
 * id-slh-dsa-shake-192f OBJECT IDENTIFIER ::= { sigAlgs 29 }
 */
#define DER_OID_V_id_slh_dsa_shake_192f DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1D
#define DER_OID_SZ_id_slh_dsa_shake_192f 11
extern const unsigned char ossl_der_oid_id_slh_dsa_shake_192f[DER_OID_SZ_id_slh_dsa_shake_192f];

/*
 * id-slh-dsa-shake-256s OBJECT IDENTIFIER ::= { sigAlgs 30 }
 */
#define DER_OID_V_id_slh_dsa_shake_256s DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1E
#define DER_OID_SZ_id_slh_dsa_shake_256s 11
extern const unsigned char ossl_der_oid_id_slh_dsa_shake_256s[DER_OID_SZ_id_slh_dsa_shake_256s];

/*
 * id-slh-dsa-shake-256f OBJECT IDENTIFIER ::= { sigAlgs 31 }
 */
#define DER_OID_V_id_slh_dsa_shake_256f DER_P_OBJECT, 9, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x1F
#define DER_OID_SZ_id_slh_dsa_shake_256f 11
extern const unsigned char ossl_der_oid_id_slh_dsa_shake_256f[DER_OID_SZ_id_slh_dsa_shake_256f];


int ossl_DER_w_algorithmIdentifier_SLH_DSA(WPACKET *pkt, int tag, SLH_DSA_KEY *key);
