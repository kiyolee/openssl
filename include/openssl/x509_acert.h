/*
 * Copyright 2022-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*
 * Generated from x509_acert.h.in for https://github.com/kiyolee/openssl.git.
 */



#ifndef OPENSSL_X509_ACERT_H
# define OPENSSL_X509_ACERT_H
# pragma once

# include <openssl/x509v3.h>
# include <openssl/x509.h>
# include <openssl/pem.h>

typedef struct X509_acert_st X509_ACERT;
typedef struct X509_acert_info_st X509_ACERT_INFO;
typedef struct ossl_object_digest_info_st OSSL_OBJECT_DIGEST_INFO;
typedef struct ossl_issuer_serial_st OSSL_ISSUER_SERIAL;
typedef struct X509_acert_issuer_v2form_st X509_ACERT_ISSUER_V2FORM;

DECLARE_ASN1_FUNCTIONS(X509_ACERT)
DECLARE_ASN1_DUP_FUNCTION(X509_ACERT)
DECLARE_ASN1_ITEM(X509_ACERT_INFO)
DECLARE_ASN1_ALLOC_FUNCTIONS(X509_ACERT_INFO)
DECLARE_ASN1_ALLOC_FUNCTIONS(OSSL_OBJECT_DIGEST_INFO)
DECLARE_ASN1_ALLOC_FUNCTIONS(OSSL_ISSUER_SERIAL)
DECLARE_ASN1_ALLOC_FUNCTIONS(X509_ACERT_ISSUER_V2FORM)

# ifndef OPENSSL_NO_STDIO
X509_ACERT *d2i_X509_ACERT_fp(FILE *fp, X509_ACERT **acert);
int i2d_X509_ACERT_fp(FILE *fp, const X509_ACERT *acert);
# endif

DECLARE_PEM_rw(X509_ACERT, X509_ACERT)

X509_ACERT *d2i_X509_ACERT_bio(BIO *bp, X509_ACERT **acert);
int i2d_X509_ACERT_bio(BIO *bp, const X509_ACERT *acert);

int X509_ACERT_sign(X509_ACERT *x, EVP_PKEY *pkey, const EVP_MD *md);
int X509_ACERT_sign_ctx(X509_ACERT *x, EVP_MD_CTX *ctx);
int X509_ACERT_verify(X509_ACERT *a, EVP_PKEY *r);

# define X509_ACERT_VERSION_2 1

const GENERAL_NAMES *X509_ACERT_get0_holder_entityName(const X509_ACERT *x);
const OSSL_ISSUER_SERIAL *X509_ACERT_get0_holder_baseCertId(const X509_ACERT *x);
const OSSL_OBJECT_DIGEST_INFO * X509_ACERT_get0_holder_digest(const X509_ACERT *x);
const X509_NAME *X509_ACERT_get0_issuerName(const X509_ACERT *x);
long X509_ACERT_get_version(const X509_ACERT *x);
void X509_ACERT_get0_signature(const X509_ACERT *x,
                               const ASN1_BIT_STRING **psig,
                               const X509_ALGOR **palg);
int X509_ACERT_get_signature_nid(const X509_ACERT *x);
const X509_ALGOR *X509_ACERT_get0_info_sigalg(const X509_ACERT *x);
const ASN1_INTEGER *X509_ACERT_get0_serialNumber(const X509_ACERT *x);
const ASN1_TIME *X509_ACERT_get0_notBefore(const X509_ACERT *x);
const ASN1_TIME *X509_ACERT_get0_notAfter(const X509_ACERT *x);
const ASN1_BIT_STRING *X509_ACERT_get0_issuerUID(const X509_ACERT *x);

int X509_ACERT_print(BIO *bp, X509_ACERT *x);
int X509_ACERT_print_ex(BIO *bp, X509_ACERT *x, unsigned long nmflags,
                        unsigned long cflag);

int X509_ACERT_get_attr_count(const X509_ACERT *x);
int X509_ACERT_get_attr_by_NID(const X509_ACERT *x, int nid, int lastpos);
int X509_ACERT_get_attr_by_OBJ(const X509_ACERT *x, const ASN1_OBJECT *obj,
                               int lastpos);
X509_ATTRIBUTE *X509_ACERT_get_attr(const X509_ACERT *x, int loc);
X509_ATTRIBUTE *X509_ACERT_delete_attr(X509_ACERT *x, int loc);

void *X509_ACERT_get_ext_d2i(const X509_ACERT *x, int nid, int *crit, int *idx);
int X509_ACERT_add1_ext_i2d(X509_ACERT *x, int nid, void *value, int crit,
                            unsigned long flags);
const STACK_OF(X509_EXTENSION) *X509_ACERT_get0_extensions(const X509_ACERT *x);

# define OSSL_OBJECT_DIGEST_INFO_PUBLIC_KEY        0
# define OSSL_OBJECT_DIGEST_INFO_PUBLIC_KEY_CERT   1
# define OSSL_OBJECT_DIGEST_INFO_OTHER             2  /* must not be used in RFC 5755 profile */
int X509_ACERT_set_version(X509_ACERT *x, long version);
void X509_ACERT_set0_holder_entityName(X509_ACERT *x, GENERAL_NAMES *name);
void X509_ACERT_set0_holder_baseCertId(X509_ACERT *x, OSSL_ISSUER_SERIAL *isss);
void X509_ACERT_set0_holder_digest(X509_ACERT *x,
                                   OSSL_OBJECT_DIGEST_INFO *dinfo);

int X509_ACERT_add1_attr(X509_ACERT *x, X509_ATTRIBUTE *attr);
int X509_ACERT_add1_attr_by_OBJ(X509_ACERT *x, const ASN1_OBJECT *obj,
                                int type, const void *bytes, int len);
int X509_ACERT_add1_attr_by_NID(X509_ACERT *x, int nid, int type,
                                const void *bytes, int len);
int X509_ACERT_add1_attr_by_txt(X509_ACERT *x, const char *attrname, int type,
                                const unsigned char *bytes, int len);
int X509_ACERT_add_attr_nconf(CONF *conf, const char *section,
                              X509_ACERT *acert);

int X509_ACERT_set1_issuerName(X509_ACERT *x, const X509_NAME *name);
int X509_ACERT_set1_serialNumber(X509_ACERT *x, const ASN1_INTEGER *serial);
int X509_ACERT_set1_notBefore(X509_ACERT *x, const ASN1_GENERALIZEDTIME *time);
int X509_ACERT_set1_notAfter(X509_ACERT *x, const ASN1_GENERALIZEDTIME *time);

void OSSL_OBJECT_DIGEST_INFO_get0_digest(const OSSL_OBJECT_DIGEST_INFO *o,
                                         int *digestedObjectType,
                                         const X509_ALGOR **digestAlgorithm,
                                         const ASN1_BIT_STRING **digest);

int OSSL_OBJECT_DIGEST_INFO_set1_digest(OSSL_OBJECT_DIGEST_INFO *o,
                                        int digestedObjectType,
                                        X509_ALGOR *digestAlgorithm,
                                        ASN1_BIT_STRING *digest);

const X509_NAME *OSSL_ISSUER_SERIAL_get0_issuer(const OSSL_ISSUER_SERIAL *isss);
const ASN1_INTEGER *OSSL_ISSUER_SERIAL_get0_serial(const OSSL_ISSUER_SERIAL *isss);
const ASN1_BIT_STRING *OSSL_ISSUER_SERIAL_get0_issuerUID(const OSSL_ISSUER_SERIAL *isss);

int OSSL_ISSUER_SERIAL_set1_issuer(OSSL_ISSUER_SERIAL *isss,
                                   const X509_NAME *issuer);
int OSSL_ISSUER_SERIAL_set1_serial(OSSL_ISSUER_SERIAL *isss,
                                   const ASN1_INTEGER *serial);
int OSSL_ISSUER_SERIAL_set1_issuerUID(OSSL_ISSUER_SERIAL *isss,
                                   const ASN1_BIT_STRING *uid);

# define OSSL_IETFAS_OCTETS     0
# define OSSL_IETFAS_OID        1
# define OSSL_IETFAS_STRING     2

typedef struct OSSL_IETF_ATTR_SYNTAX_VALUE_st OSSL_IETF_ATTR_SYNTAX_VALUE;
typedef struct OSSL_IETF_ATTR_SYNTAX_st OSSL_IETF_ATTR_SYNTAX;
SKM_DEFINE_STACK_OF_INTERNAL(OSSL_IETF_ATTR_SYNTAX_VALUE, OSSL_IETF_ATTR_SYNTAX_VALUE, OSSL_IETF_ATTR_SYNTAX_VALUE)
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_num(sk) OPENSSL_sk_num(ossl_check_const_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_value(sk, idx) ((OSSL_IETF_ATTR_SYNTAX_VALUE *)OPENSSL_sk_value(ossl_check_const_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), (idx)))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_new(cmp) ((STACK_OF(OSSL_IETF_ATTR_SYNTAX_VALUE) *)OPENSSL_sk_new(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_compfunc_type(cmp)))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_new_null() ((STACK_OF(OSSL_IETF_ATTR_SYNTAX_VALUE) *)OPENSSL_sk_new_null())
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_new_reserve(cmp, n) ((STACK_OF(OSSL_IETF_ATTR_SYNTAX_VALUE) *)OPENSSL_sk_new_reserve(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_compfunc_type(cmp), (n)))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), (n))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_free(sk) OPENSSL_sk_free(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_zero(sk) OPENSSL_sk_zero(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_delete(sk, i) ((OSSL_IETF_ATTR_SYNTAX_VALUE *)OPENSSL_sk_delete(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), (i)))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_delete_ptr(sk, ptr) ((OSSL_IETF_ATTR_SYNTAX_VALUE *)OPENSSL_sk_delete_ptr(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr)))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_push(sk, ptr) OPENSSL_sk_push(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_pop(sk) ((OSSL_IETF_ATTR_SYNTAX_VALUE *)OPENSSL_sk_pop(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk)))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_shift(sk) ((OSSL_IETF_ATTR_SYNTAX_VALUE *)OPENSSL_sk_shift(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk)))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_freefunc_type(freefunc))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr), (idx))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_set(sk, idx, ptr) ((OSSL_IETF_ATTR_SYNTAX_VALUE *)OPENSSL_sk_set(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), (idx), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr)))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_find(sk, ptr) OPENSSL_sk_find(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_type(ptr), pnum)
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_sort(sk) OPENSSL_sk_sort(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_dup(sk) ((STACK_OF(OSSL_IETF_ATTR_SYNTAX_VALUE) *)OPENSSL_sk_dup(ossl_check_const_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk)))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OSSL_IETF_ATTR_SYNTAX_VALUE) *)OPENSSL_sk_deep_copy(ossl_check_const_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_copyfunc_type(copyfunc), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_freefunc_type(freefunc)))
#define sk_OSSL_IETF_ATTR_SYNTAX_VALUE_set_cmp_func(sk, cmp) ((sk_OSSL_IETF_ATTR_SYNTAX_VALUE_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_sk_type(sk), ossl_check_OSSL_IETF_ATTR_SYNTAX_VALUE_compfunc_type(cmp)))


DECLARE_ASN1_ITEM(OSSL_IETF_ATTR_SYNTAX_VALUE)
DECLARE_ASN1_ALLOC_FUNCTIONS(OSSL_IETF_ATTR_SYNTAX_VALUE)
DECLARE_ASN1_FUNCTIONS(OSSL_IETF_ATTR_SYNTAX)

const GENERAL_NAMES *
OSSL_IETF_ATTR_SYNTAX_get0_policyAuthority(const OSSL_IETF_ATTR_SYNTAX *a);
void OSSL_IETF_ATTR_SYNTAX_set0_policyAuthority(OSSL_IETF_ATTR_SYNTAX *a,
		                                        GENERAL_NAMES *names);

int OSSL_IETF_ATTR_SYNTAX_get_value_num(const OSSL_IETF_ATTR_SYNTAX *a);
void *OSSL_IETF_ATTR_SYNTAX_get0_value(const OSSL_IETF_ATTR_SYNTAX *a,
		                               int ind, int *type);
int OSSL_IETF_ATTR_SYNTAX_add1_value(OSSL_IETF_ATTR_SYNTAX *a, int type,
		                             void *data);
int OSSL_IETF_ATTR_SYNTAX_print(BIO *bp, OSSL_IETF_ATTR_SYNTAX *a, int indent);

struct TARGET_CERT_st {
    OSSL_ISSUER_SERIAL *targetCertificate;
    GENERAL_NAME *targetName;
    OSSL_OBJECT_DIGEST_INFO *certDigestInfo;
};

typedef struct TARGET_CERT_st OSSL_TARGET_CERT;

# define OSSL_TGT_TARGET_NAME  0
# define OSSL_TGT_TARGET_GROUP 1
# define OSSL_TGT_TARGET_CERT  2

typedef struct TARGET_st {
    int type;
    union {
        GENERAL_NAME *targetName;
        GENERAL_NAME *targetGroup;
        OSSL_TARGET_CERT *targetCert;
    } choice;
} OSSL_TARGET;

typedef STACK_OF(OSSL_TARGET) OSSL_TARGETS;
typedef STACK_OF(OSSL_TARGETS) OSSL_TARGETING_INFORMATION;

SKM_DEFINE_STACK_OF_INTERNAL(OSSL_TARGET, OSSL_TARGET, OSSL_TARGET)
#define sk_OSSL_TARGET_num(sk) OPENSSL_sk_num(ossl_check_const_OSSL_TARGET_sk_type(sk))
#define sk_OSSL_TARGET_value(sk, idx) ((OSSL_TARGET *)OPENSSL_sk_value(ossl_check_const_OSSL_TARGET_sk_type(sk), (idx)))
#define sk_OSSL_TARGET_new(cmp) ((STACK_OF(OSSL_TARGET) *)OPENSSL_sk_new(ossl_check_OSSL_TARGET_compfunc_type(cmp)))
#define sk_OSSL_TARGET_new_null() ((STACK_OF(OSSL_TARGET) *)OPENSSL_sk_new_null())
#define sk_OSSL_TARGET_new_reserve(cmp, n) ((STACK_OF(OSSL_TARGET) *)OPENSSL_sk_new_reserve(ossl_check_OSSL_TARGET_compfunc_type(cmp), (n)))
#define sk_OSSL_TARGET_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OSSL_TARGET_sk_type(sk), (n))
#define sk_OSSL_TARGET_free(sk) OPENSSL_sk_free(ossl_check_OSSL_TARGET_sk_type(sk))
#define sk_OSSL_TARGET_zero(sk) OPENSSL_sk_zero(ossl_check_OSSL_TARGET_sk_type(sk))
#define sk_OSSL_TARGET_delete(sk, i) ((OSSL_TARGET *)OPENSSL_sk_delete(ossl_check_OSSL_TARGET_sk_type(sk), (i)))
#define sk_OSSL_TARGET_delete_ptr(sk, ptr) ((OSSL_TARGET *)OPENSSL_sk_delete_ptr(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr)))
#define sk_OSSL_TARGET_push(sk, ptr) OPENSSL_sk_push(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr))
#define sk_OSSL_TARGET_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr))
#define sk_OSSL_TARGET_pop(sk) ((OSSL_TARGET *)OPENSSL_sk_pop(ossl_check_OSSL_TARGET_sk_type(sk)))
#define sk_OSSL_TARGET_shift(sk) ((OSSL_TARGET *)OPENSSL_sk_shift(ossl_check_OSSL_TARGET_sk_type(sk)))
#define sk_OSSL_TARGET_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_freefunc_type(freefunc))
#define sk_OSSL_TARGET_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr), (idx))
#define sk_OSSL_TARGET_set(sk, idx, ptr) ((OSSL_TARGET *)OPENSSL_sk_set(ossl_check_OSSL_TARGET_sk_type(sk), (idx), ossl_check_OSSL_TARGET_type(ptr)))
#define sk_OSSL_TARGET_find(sk, ptr) OPENSSL_sk_find(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr))
#define sk_OSSL_TARGET_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr))
#define sk_OSSL_TARGET_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_type(ptr), pnum)
#define sk_OSSL_TARGET_sort(sk) OPENSSL_sk_sort(ossl_check_OSSL_TARGET_sk_type(sk))
#define sk_OSSL_TARGET_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OSSL_TARGET_sk_type(sk))
#define sk_OSSL_TARGET_dup(sk) ((STACK_OF(OSSL_TARGET) *)OPENSSL_sk_dup(ossl_check_const_OSSL_TARGET_sk_type(sk)))
#define sk_OSSL_TARGET_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OSSL_TARGET) *)OPENSSL_sk_deep_copy(ossl_check_const_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_copyfunc_type(copyfunc), ossl_check_OSSL_TARGET_freefunc_type(freefunc)))
#define sk_OSSL_TARGET_set_cmp_func(sk, cmp) ((sk_OSSL_TARGET_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OSSL_TARGET_sk_type(sk), ossl_check_OSSL_TARGET_compfunc_type(cmp)))


SKM_DEFINE_STACK_OF_INTERNAL(OSSL_TARGETS, OSSL_TARGETS, OSSL_TARGETS)
#define sk_OSSL_TARGETS_num(sk) OPENSSL_sk_num(ossl_check_const_OSSL_TARGETS_sk_type(sk))
#define sk_OSSL_TARGETS_value(sk, idx) ((OSSL_TARGETS *)OPENSSL_sk_value(ossl_check_const_OSSL_TARGETS_sk_type(sk), (idx)))
#define sk_OSSL_TARGETS_new(cmp) ((STACK_OF(OSSL_TARGETS) *)OPENSSL_sk_new(ossl_check_OSSL_TARGETS_compfunc_type(cmp)))
#define sk_OSSL_TARGETS_new_null() ((STACK_OF(OSSL_TARGETS) *)OPENSSL_sk_new_null())
#define sk_OSSL_TARGETS_new_reserve(cmp, n) ((STACK_OF(OSSL_TARGETS) *)OPENSSL_sk_new_reserve(ossl_check_OSSL_TARGETS_compfunc_type(cmp), (n)))
#define sk_OSSL_TARGETS_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OSSL_TARGETS_sk_type(sk), (n))
#define sk_OSSL_TARGETS_free(sk) OPENSSL_sk_free(ossl_check_OSSL_TARGETS_sk_type(sk))
#define sk_OSSL_TARGETS_zero(sk) OPENSSL_sk_zero(ossl_check_OSSL_TARGETS_sk_type(sk))
#define sk_OSSL_TARGETS_delete(sk, i) ((OSSL_TARGETS *)OPENSSL_sk_delete(ossl_check_OSSL_TARGETS_sk_type(sk), (i)))
#define sk_OSSL_TARGETS_delete_ptr(sk, ptr) ((OSSL_TARGETS *)OPENSSL_sk_delete_ptr(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr)))
#define sk_OSSL_TARGETS_push(sk, ptr) OPENSSL_sk_push(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr))
#define sk_OSSL_TARGETS_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr))
#define sk_OSSL_TARGETS_pop(sk) ((OSSL_TARGETS *)OPENSSL_sk_pop(ossl_check_OSSL_TARGETS_sk_type(sk)))
#define sk_OSSL_TARGETS_shift(sk) ((OSSL_TARGETS *)OPENSSL_sk_shift(ossl_check_OSSL_TARGETS_sk_type(sk)))
#define sk_OSSL_TARGETS_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_freefunc_type(freefunc))
#define sk_OSSL_TARGETS_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr), (idx))
#define sk_OSSL_TARGETS_set(sk, idx, ptr) ((OSSL_TARGETS *)OPENSSL_sk_set(ossl_check_OSSL_TARGETS_sk_type(sk), (idx), ossl_check_OSSL_TARGETS_type(ptr)))
#define sk_OSSL_TARGETS_find(sk, ptr) OPENSSL_sk_find(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr))
#define sk_OSSL_TARGETS_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr))
#define sk_OSSL_TARGETS_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_type(ptr), pnum)
#define sk_OSSL_TARGETS_sort(sk) OPENSSL_sk_sort(ossl_check_OSSL_TARGETS_sk_type(sk))
#define sk_OSSL_TARGETS_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OSSL_TARGETS_sk_type(sk))
#define sk_OSSL_TARGETS_dup(sk) ((STACK_OF(OSSL_TARGETS) *)OPENSSL_sk_dup(ossl_check_const_OSSL_TARGETS_sk_type(sk)))
#define sk_OSSL_TARGETS_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OSSL_TARGETS) *)OPENSSL_sk_deep_copy(ossl_check_const_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_copyfunc_type(copyfunc), ossl_check_OSSL_TARGETS_freefunc_type(freefunc)))
#define sk_OSSL_TARGETS_set_cmp_func(sk, cmp) ((sk_OSSL_TARGETS_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OSSL_TARGETS_sk_type(sk), ossl_check_OSSL_TARGETS_compfunc_type(cmp)))


DECLARE_ASN1_FUNCTIONS(OSSL_TARGET)
DECLARE_ASN1_FUNCTIONS(OSSL_TARGETS)
DECLARE_ASN1_FUNCTIONS(OSSL_TARGETING_INFORMATION)

typedef STACK_OF(OSSL_ISSUER_SERIAL) OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX;
DECLARE_ASN1_FUNCTIONS(OSSL_AUTHORITY_ATTRIBUTE_ID_SYNTAX)

SKM_DEFINE_STACK_OF_INTERNAL(OSSL_ISSUER_SERIAL, OSSL_ISSUER_SERIAL, OSSL_ISSUER_SERIAL)
#define sk_OSSL_ISSUER_SERIAL_num(sk) OPENSSL_sk_num(ossl_check_const_OSSL_ISSUER_SERIAL_sk_type(sk))
#define sk_OSSL_ISSUER_SERIAL_value(sk, idx) ((OSSL_ISSUER_SERIAL *)OPENSSL_sk_value(ossl_check_const_OSSL_ISSUER_SERIAL_sk_type(sk), (idx)))
#define sk_OSSL_ISSUER_SERIAL_new(cmp) ((STACK_OF(OSSL_ISSUER_SERIAL) *)OPENSSL_sk_new(ossl_check_OSSL_ISSUER_SERIAL_compfunc_type(cmp)))
#define sk_OSSL_ISSUER_SERIAL_new_null() ((STACK_OF(OSSL_ISSUER_SERIAL) *)OPENSSL_sk_new_null())
#define sk_OSSL_ISSUER_SERIAL_new_reserve(cmp, n) ((STACK_OF(OSSL_ISSUER_SERIAL) *)OPENSSL_sk_new_reserve(ossl_check_OSSL_ISSUER_SERIAL_compfunc_type(cmp), (n)))
#define sk_OSSL_ISSUER_SERIAL_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), (n))
#define sk_OSSL_ISSUER_SERIAL_free(sk) OPENSSL_sk_free(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk))
#define sk_OSSL_ISSUER_SERIAL_zero(sk) OPENSSL_sk_zero(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk))
#define sk_OSSL_ISSUER_SERIAL_delete(sk, i) ((OSSL_ISSUER_SERIAL *)OPENSSL_sk_delete(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), (i)))
#define sk_OSSL_ISSUER_SERIAL_delete_ptr(sk, ptr) ((OSSL_ISSUER_SERIAL *)OPENSSL_sk_delete_ptr(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr)))
#define sk_OSSL_ISSUER_SERIAL_push(sk, ptr) OPENSSL_sk_push(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr))
#define sk_OSSL_ISSUER_SERIAL_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr))
#define sk_OSSL_ISSUER_SERIAL_pop(sk) ((OSSL_ISSUER_SERIAL *)OPENSSL_sk_pop(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk)))
#define sk_OSSL_ISSUER_SERIAL_shift(sk) ((OSSL_ISSUER_SERIAL *)OPENSSL_sk_shift(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk)))
#define sk_OSSL_ISSUER_SERIAL_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_freefunc_type(freefunc))
#define sk_OSSL_ISSUER_SERIAL_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr), (idx))
#define sk_OSSL_ISSUER_SERIAL_set(sk, idx, ptr) ((OSSL_ISSUER_SERIAL *)OPENSSL_sk_set(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), (idx), ossl_check_OSSL_ISSUER_SERIAL_type(ptr)))
#define sk_OSSL_ISSUER_SERIAL_find(sk, ptr) OPENSSL_sk_find(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr))
#define sk_OSSL_ISSUER_SERIAL_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr))
#define sk_OSSL_ISSUER_SERIAL_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_type(ptr), pnum)
#define sk_OSSL_ISSUER_SERIAL_sort(sk) OPENSSL_sk_sort(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk))
#define sk_OSSL_ISSUER_SERIAL_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_OSSL_ISSUER_SERIAL_sk_type(sk))
#define sk_OSSL_ISSUER_SERIAL_dup(sk) ((STACK_OF(OSSL_ISSUER_SERIAL) *)OPENSSL_sk_dup(ossl_check_const_OSSL_ISSUER_SERIAL_sk_type(sk)))
#define sk_OSSL_ISSUER_SERIAL_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(OSSL_ISSUER_SERIAL) *)OPENSSL_sk_deep_copy(ossl_check_const_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_copyfunc_type(copyfunc), ossl_check_OSSL_ISSUER_SERIAL_freefunc_type(freefunc)))
#define sk_OSSL_ISSUER_SERIAL_set_cmp_func(sk, cmp) ((sk_OSSL_ISSUER_SERIAL_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_OSSL_ISSUER_SERIAL_sk_type(sk), ossl_check_OSSL_ISSUER_SERIAL_compfunc_type(cmp)))


#endif
