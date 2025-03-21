/*
 * Copyright 2020-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*
 * Generated from der_ec_gen.c.in for https://github.com/kiyolee/openssl.git.
 */

#include "prov/der_ec.h"

/* Well known OIDs precompiled */

/*
 * ecdsa-with-SHA1 OBJECT IDENTIFIER ::= { id-ecSigType 1 }
 */
const unsigned char ossl_der_oid_ecdsa_with_SHA1[DER_OID_SZ_ecdsa_with_SHA1] = {
    DER_OID_V_ecdsa_with_SHA1
};

/*
 * id-ecPublicKey OBJECT IDENTIFIER ::= { id-publicKeyType 1 }
 */
const unsigned char ossl_der_oid_id_ecPublicKey[DER_OID_SZ_id_ecPublicKey] = {
    DER_OID_V_id_ecPublicKey
};

/*
 * c2pnb163v1  OBJECT IDENTIFIER  ::=  { c-TwoCurve  1 }
 */
const unsigned char ossl_der_oid_c2pnb163v1[DER_OID_SZ_c2pnb163v1] = {
    DER_OID_V_c2pnb163v1
};

/*
 * c2pnb163v2  OBJECT IDENTIFIER  ::=  { c-TwoCurve  2 }
 */
const unsigned char ossl_der_oid_c2pnb163v2[DER_OID_SZ_c2pnb163v2] = {
    DER_OID_V_c2pnb163v2
};

/*
 * c2pnb163v3  OBJECT IDENTIFIER  ::=  { c-TwoCurve  3 }
 */
const unsigned char ossl_der_oid_c2pnb163v3[DER_OID_SZ_c2pnb163v3] = {
    DER_OID_V_c2pnb163v3
};

/*
 * c2pnb176w1  OBJECT IDENTIFIER  ::=  { c-TwoCurve  4 }
 */
const unsigned char ossl_der_oid_c2pnb176w1[DER_OID_SZ_c2pnb176w1] = {
    DER_OID_V_c2pnb176w1
};

/*
 * c2tnb191v1  OBJECT IDENTIFIER  ::=  { c-TwoCurve  5 }
 */
const unsigned char ossl_der_oid_c2tnb191v1[DER_OID_SZ_c2tnb191v1] = {
    DER_OID_V_c2tnb191v1
};

/*
 * c2tnb191v2  OBJECT IDENTIFIER  ::=  { c-TwoCurve  6 }
 */
const unsigned char ossl_der_oid_c2tnb191v2[DER_OID_SZ_c2tnb191v2] = {
    DER_OID_V_c2tnb191v2
};

/*
 * c2tnb191v3  OBJECT IDENTIFIER  ::=  { c-TwoCurve  7 }
 */
const unsigned char ossl_der_oid_c2tnb191v3[DER_OID_SZ_c2tnb191v3] = {
    DER_OID_V_c2tnb191v3
};

/*
 * c2onb191v4  OBJECT IDENTIFIER  ::=  { c-TwoCurve  8 }
 */
const unsigned char ossl_der_oid_c2onb191v4[DER_OID_SZ_c2onb191v4] = {
    DER_OID_V_c2onb191v4
};

/*
 * c2onb191v5  OBJECT IDENTIFIER  ::=  { c-TwoCurve  9 }
 */
const unsigned char ossl_der_oid_c2onb191v5[DER_OID_SZ_c2onb191v5] = {
    DER_OID_V_c2onb191v5
};

/*
 * c2pnb208w1  OBJECT IDENTIFIER  ::=  { c-TwoCurve 10 }
 */
const unsigned char ossl_der_oid_c2pnb208w1[DER_OID_SZ_c2pnb208w1] = {
    DER_OID_V_c2pnb208w1
};

/*
 * c2tnb239v1  OBJECT IDENTIFIER  ::=  { c-TwoCurve 11 }
 */
const unsigned char ossl_der_oid_c2tnb239v1[DER_OID_SZ_c2tnb239v1] = {
    DER_OID_V_c2tnb239v1
};

/*
 * c2tnb239v2  OBJECT IDENTIFIER  ::=  { c-TwoCurve 12 }
 */
const unsigned char ossl_der_oid_c2tnb239v2[DER_OID_SZ_c2tnb239v2] = {
    DER_OID_V_c2tnb239v2
};

/*
 * c2tnb239v3  OBJECT IDENTIFIER  ::=  { c-TwoCurve 13 }
 */
const unsigned char ossl_der_oid_c2tnb239v3[DER_OID_SZ_c2tnb239v3] = {
    DER_OID_V_c2tnb239v3
};

/*
 * c2onb239v4  OBJECT IDENTIFIER  ::=  { c-TwoCurve 14 }
 */
const unsigned char ossl_der_oid_c2onb239v4[DER_OID_SZ_c2onb239v4] = {
    DER_OID_V_c2onb239v4
};

/*
 * c2onb239v5  OBJECT IDENTIFIER  ::=  { c-TwoCurve 15 }
 */
const unsigned char ossl_der_oid_c2onb239v5[DER_OID_SZ_c2onb239v5] = {
    DER_OID_V_c2onb239v5
};

/*
 * c2pnb272w1  OBJECT IDENTIFIER  ::=  { c-TwoCurve 16 }
 */
const unsigned char ossl_der_oid_c2pnb272w1[DER_OID_SZ_c2pnb272w1] = {
    DER_OID_V_c2pnb272w1
};

/*
 * c2pnb304w1  OBJECT IDENTIFIER  ::=  { c-TwoCurve 17 }
 */
const unsigned char ossl_der_oid_c2pnb304w1[DER_OID_SZ_c2pnb304w1] = {
    DER_OID_V_c2pnb304w1
};

/*
 * c2tnb359v1  OBJECT IDENTIFIER  ::=  { c-TwoCurve 18 }
 */
const unsigned char ossl_der_oid_c2tnb359v1[DER_OID_SZ_c2tnb359v1] = {
    DER_OID_V_c2tnb359v1
};

/*
 * c2pnb368w1  OBJECT IDENTIFIER  ::=  { c-TwoCurve 19 }
 */
const unsigned char ossl_der_oid_c2pnb368w1[DER_OID_SZ_c2pnb368w1] = {
    DER_OID_V_c2pnb368w1
};

/*
 * c2tnb431r1  OBJECT IDENTIFIER  ::=  { c-TwoCurve 20 }
 */
const unsigned char ossl_der_oid_c2tnb431r1[DER_OID_SZ_c2tnb431r1] = {
    DER_OID_V_c2tnb431r1
};

/*
 * prime192v1  OBJECT IDENTIFIER  ::=  { primeCurve  1 }
 */
const unsigned char ossl_der_oid_prime192v1[DER_OID_SZ_prime192v1] = {
    DER_OID_V_prime192v1
};

/*
 * prime192v2  OBJECT IDENTIFIER  ::=  { primeCurve  2 }
 */
const unsigned char ossl_der_oid_prime192v2[DER_OID_SZ_prime192v2] = {
    DER_OID_V_prime192v2
};

/*
 * prime192v3  OBJECT IDENTIFIER  ::=  { primeCurve  3 }
 */
const unsigned char ossl_der_oid_prime192v3[DER_OID_SZ_prime192v3] = {
    DER_OID_V_prime192v3
};

/*
 * prime239v1  OBJECT IDENTIFIER  ::=  { primeCurve  4 }
 */
const unsigned char ossl_der_oid_prime239v1[DER_OID_SZ_prime239v1] = {
    DER_OID_V_prime239v1
};

/*
 * prime239v2  OBJECT IDENTIFIER  ::=  { primeCurve  5 }
 */
const unsigned char ossl_der_oid_prime239v2[DER_OID_SZ_prime239v2] = {
    DER_OID_V_prime239v2
};

/*
 * prime239v3  OBJECT IDENTIFIER  ::=  { primeCurve  6 }
 */
const unsigned char ossl_der_oid_prime239v3[DER_OID_SZ_prime239v3] = {
    DER_OID_V_prime239v3
};

/*
 * prime256v1  OBJECT IDENTIFIER  ::=  { primeCurve  7 }
 */
const unsigned char ossl_der_oid_prime256v1[DER_OID_SZ_prime256v1] = {
    DER_OID_V_prime256v1
};

/*
 * ecdsa-with-SHA224 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *      us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 1 }
 */
const unsigned char ossl_der_oid_ecdsa_with_SHA224[DER_OID_SZ_ecdsa_with_SHA224] = {
    DER_OID_V_ecdsa_with_SHA224
};

/*
 * ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *      us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
 */
const unsigned char ossl_der_oid_ecdsa_with_SHA256[DER_OID_SZ_ecdsa_with_SHA256] = {
    DER_OID_V_ecdsa_with_SHA256
};

/*
 * ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *      us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
 */
const unsigned char ossl_der_oid_ecdsa_with_SHA384[DER_OID_SZ_ecdsa_with_SHA384] = {
    DER_OID_V_ecdsa_with_SHA384
};

/*
 * ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *      us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }
 */
const unsigned char ossl_der_oid_ecdsa_with_SHA512[DER_OID_SZ_ecdsa_with_SHA512] = {
    DER_OID_V_ecdsa_with_SHA512
};

/*
 * id-ecdsa-with-sha3-224 OBJECT IDENTIFIER ::= { sigAlgs 9 }
 */
const unsigned char ossl_der_oid_id_ecdsa_with_sha3_224[DER_OID_SZ_id_ecdsa_with_sha3_224] = {
    DER_OID_V_id_ecdsa_with_sha3_224
};

/*
 * id-ecdsa-with-sha3-256 OBJECT IDENTIFIER ::= { sigAlgs 10 }
 */
const unsigned char ossl_der_oid_id_ecdsa_with_sha3_256[DER_OID_SZ_id_ecdsa_with_sha3_256] = {
    DER_OID_V_id_ecdsa_with_sha3_256
};

/*
 * id-ecdsa-with-sha3-384 OBJECT IDENTIFIER ::= { sigAlgs 11 }
 */
const unsigned char ossl_der_oid_id_ecdsa_with_sha3_384[DER_OID_SZ_id_ecdsa_with_sha3_384] = {
    DER_OID_V_id_ecdsa_with_sha3_384
};

/*
 * id-ecdsa-with-sha3-512 OBJECT IDENTIFIER ::= { sigAlgs 12 }
 */
const unsigned char ossl_der_oid_id_ecdsa_with_sha3_512[DER_OID_SZ_id_ecdsa_with_sha3_512] = {
    DER_OID_V_id_ecdsa_with_sha3_512
};

