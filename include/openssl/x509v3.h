/*
 * Copyright 1999-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*
 * Generated from x509v3.h.in for https://github.com/kiyolee/openssl.git.
 */



#ifndef OPENSSL_X509V3_H
# define OPENSSL_X509V3_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_X509V3_H
# endif

# include <openssl/bio.h>
# include <openssl/x509.h>
# include <openssl/conf.h>
# include <openssl/x509v3err.h>
# ifndef OPENSSL_NO_STDIO
#  include <stdio.h>
# endif

#ifdef __cplusplus
extern "C" {
#endif

/* Forward reference */
struct v3_ext_method;
struct v3_ext_ctx;

/* Useful typedefs */

typedef void *(*X509V3_EXT_NEW)(void);
typedef void (*X509V3_EXT_FREE) (void *);
typedef void *(*X509V3_EXT_D2I)(void *, const unsigned char **, long);
typedef int (*X509V3_EXT_I2D) (const void *, unsigned char **);
typedef STACK_OF(CONF_VALUE) *
    (*X509V3_EXT_I2V) (const struct v3_ext_method *method, void *ext,
                       STACK_OF(CONF_VALUE) *extlist);
typedef void *(*X509V3_EXT_V2I)(const struct v3_ext_method *method,
                                struct v3_ext_ctx *ctx,
                                STACK_OF(CONF_VALUE) *values);
typedef char *(*X509V3_EXT_I2S)(const struct v3_ext_method *method,
                                void *ext);
typedef void *(*X509V3_EXT_S2I)(const struct v3_ext_method *method,
                                struct v3_ext_ctx *ctx, const char *str);
typedef int (*X509V3_EXT_I2R) (const struct v3_ext_method *method, void *ext,
                               BIO *out, int indent);
typedef void *(*X509V3_EXT_R2I)(const struct v3_ext_method *method,
                                struct v3_ext_ctx *ctx, const char *str);

/* V3 extension structure */

struct v3_ext_method {
    int ext_nid;
    int ext_flags;
/* If this is set the following four fields are ignored */
    ASN1_ITEM_EXP *it;
/* Old style ASN1 calls */
    X509V3_EXT_NEW ext_new;
    X509V3_EXT_FREE ext_free;
    X509V3_EXT_D2I d2i;
    X509V3_EXT_I2D i2d;
/* The following pair is used for string extensions */
    X509V3_EXT_I2S i2s;
    X509V3_EXT_S2I s2i;
/* The following pair is used for multi-valued extensions */
    X509V3_EXT_I2V i2v;
    X509V3_EXT_V2I v2i;
/* The following are used for raw extensions */
    X509V3_EXT_I2R i2r;
    X509V3_EXT_R2I r2i;
    void *usr_data;             /* Any extension specific data */
};

typedef struct X509V3_CONF_METHOD_st {
    char *(*get_string) (void *db, const char *section, const char *value);
    STACK_OF(CONF_VALUE) *(*get_section) (void *db, const char *section);
    void (*free_string) (void *db, char *string);
    void (*free_section) (void *db, STACK_OF(CONF_VALUE) *section);
} X509V3_CONF_METHOD;

/* Context specific info for producing X509 v3 extensions*/
struct v3_ext_ctx {
# define X509V3_CTX_TEST 0x1
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define CTX_TEST X509V3_CTX_TEST
# endif
# define X509V3_CTX_REPLACE 0x2
    int flags;
    X509 *issuer_cert;
    X509 *subject_cert;
    X509_REQ *subject_req;
    X509_CRL *crl;
    X509V3_CONF_METHOD *db_meth;
    void *db;
    EVP_PKEY *issuer_pkey;
/* Maybe more here */
};

typedef struct v3_ext_method X509V3_EXT_METHOD;

SKM_DEFINE_STACK_OF_INTERNAL(X509V3_EXT_METHOD, X509V3_EXT_METHOD, X509V3_EXT_METHOD)
#define sk_X509V3_EXT_METHOD_num(sk) OPENSSL_sk_num(ossl_check_const_X509V3_EXT_METHOD_sk_type(sk))
#define sk_X509V3_EXT_METHOD_value(sk, idx) ((X509V3_EXT_METHOD *)OPENSSL_sk_value(ossl_check_const_X509V3_EXT_METHOD_sk_type(sk), (idx)))
#define sk_X509V3_EXT_METHOD_new(cmp) ((STACK_OF(X509V3_EXT_METHOD) *)OPENSSL_sk_new(ossl_check_X509V3_EXT_METHOD_compfunc_type(cmp)))
#define sk_X509V3_EXT_METHOD_new_null() ((STACK_OF(X509V3_EXT_METHOD) *)OPENSSL_sk_new_null())
#define sk_X509V3_EXT_METHOD_new_reserve(cmp, n) ((STACK_OF(X509V3_EXT_METHOD) *)OPENSSL_sk_new_reserve(ossl_check_X509V3_EXT_METHOD_compfunc_type(cmp), (n)))
#define sk_X509V3_EXT_METHOD_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509V3_EXT_METHOD_sk_type(sk), (n))
#define sk_X509V3_EXT_METHOD_free(sk) OPENSSL_sk_free(ossl_check_X509V3_EXT_METHOD_sk_type(sk))
#define sk_X509V3_EXT_METHOD_zero(sk) OPENSSL_sk_zero(ossl_check_X509V3_EXT_METHOD_sk_type(sk))
#define sk_X509V3_EXT_METHOD_delete(sk, i) ((X509V3_EXT_METHOD *)OPENSSL_sk_delete(ossl_check_X509V3_EXT_METHOD_sk_type(sk), (i)))
#define sk_X509V3_EXT_METHOD_delete_ptr(sk, ptr) ((X509V3_EXT_METHOD *)OPENSSL_sk_delete_ptr(ossl_check_X509V3_EXT_METHOD_sk_type(sk), ossl_check_X509V3_EXT_METHOD_type(ptr)))
#define sk_X509V3_EXT_METHOD_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509V3_EXT_METHOD_sk_type(sk), ossl_check_X509V3_EXT_METHOD_type(ptr))
#define sk_X509V3_EXT_METHOD_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509V3_EXT_METHOD_sk_type(sk), ossl_check_X509V3_EXT_METHOD_type(ptr))
#define sk_X509V3_EXT_METHOD_pop(sk) ((X509V3_EXT_METHOD *)OPENSSL_sk_pop(ossl_check_X509V3_EXT_METHOD_sk_type(sk)))
#define sk_X509V3_EXT_METHOD_shift(sk) ((X509V3_EXT_METHOD *)OPENSSL_sk_shift(ossl_check_X509V3_EXT_METHOD_sk_type(sk)))
#define sk_X509V3_EXT_METHOD_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509V3_EXT_METHOD_sk_type(sk),ossl_check_X509V3_EXT_METHOD_freefunc_type(freefunc))
#define sk_X509V3_EXT_METHOD_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509V3_EXT_METHOD_sk_type(sk), ossl_check_X509V3_EXT_METHOD_type(ptr), (idx))
#define sk_X509V3_EXT_METHOD_set(sk, idx, ptr) ((X509V3_EXT_METHOD *)OPENSSL_sk_set(ossl_check_X509V3_EXT_METHOD_sk_type(sk), (idx), ossl_check_X509V3_EXT_METHOD_type(ptr)))
#define sk_X509V3_EXT_METHOD_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509V3_EXT_METHOD_sk_type(sk), ossl_check_X509V3_EXT_METHOD_type(ptr))
#define sk_X509V3_EXT_METHOD_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509V3_EXT_METHOD_sk_type(sk), ossl_check_X509V3_EXT_METHOD_type(ptr))
#define sk_X509V3_EXT_METHOD_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509V3_EXT_METHOD_sk_type(sk), ossl_check_X509V3_EXT_METHOD_type(ptr), pnum)
#define sk_X509V3_EXT_METHOD_sort(sk) OPENSSL_sk_sort(ossl_check_X509V3_EXT_METHOD_sk_type(sk))
#define sk_X509V3_EXT_METHOD_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509V3_EXT_METHOD_sk_type(sk))
#define sk_X509V3_EXT_METHOD_dup(sk) ((STACK_OF(X509V3_EXT_METHOD) *)OPENSSL_sk_dup(ossl_check_const_X509V3_EXT_METHOD_sk_type(sk)))
#define sk_X509V3_EXT_METHOD_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509V3_EXT_METHOD) *)OPENSSL_sk_deep_copy(ossl_check_const_X509V3_EXT_METHOD_sk_type(sk), ossl_check_X509V3_EXT_METHOD_copyfunc_type(copyfunc), ossl_check_X509V3_EXT_METHOD_freefunc_type(freefunc)))
#define sk_X509V3_EXT_METHOD_set_cmp_func(sk, cmp) ((sk_X509V3_EXT_METHOD_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509V3_EXT_METHOD_sk_type(sk), ossl_check_X509V3_EXT_METHOD_compfunc_type(cmp)))


/* ext_flags values */
# define X509V3_EXT_DYNAMIC      0x1
# define X509V3_EXT_CTX_DEP      0x2
# define X509V3_EXT_MULTILINE    0x4

typedef BIT_STRING_BITNAME ENUMERATED_NAMES;

typedef struct BASIC_CONSTRAINTS_st {
    int ca;
    ASN1_INTEGER *pathlen;
} BASIC_CONSTRAINTS;

typedef struct PKEY_USAGE_PERIOD_st {
    ASN1_GENERALIZEDTIME *notBefore;
    ASN1_GENERALIZEDTIME *notAfter;
} PKEY_USAGE_PERIOD;

typedef struct otherName_st {
    ASN1_OBJECT *type_id;
    ASN1_TYPE *value;
} OTHERNAME;

typedef struct EDIPartyName_st {
    ASN1_STRING *nameAssigner;
    ASN1_STRING *partyName;
} EDIPARTYNAME;

typedef struct GENERAL_NAME_st {
# define GEN_OTHERNAME   0
# define GEN_EMAIL       1
# define GEN_DNS         2
# define GEN_X400        3
# define GEN_DIRNAME     4
# define GEN_EDIPARTY    5
# define GEN_URI         6
# define GEN_IPADD       7
# define GEN_RID         8
    int type;
    union {
        char *ptr;
        OTHERNAME *otherName;   /* otherName */
        ASN1_IA5STRING *rfc822Name;
        ASN1_IA5STRING *dNSName;
        ASN1_STRING *x400Address;
        X509_NAME *directoryName;
        EDIPARTYNAME *ediPartyName;
        ASN1_IA5STRING *uniformResourceIdentifier;
        ASN1_OCTET_STRING *iPAddress;
        ASN1_OBJECT *registeredID;
        /* Old names */
        ASN1_OCTET_STRING *ip;  /* iPAddress */
        X509_NAME *dirn;        /* dirn */
        ASN1_IA5STRING *ia5;    /* rfc822Name, dNSName,
                                 * uniformResourceIdentifier */
        ASN1_OBJECT *rid;       /* registeredID */
        ASN1_TYPE *other;       /* x400Address */
    } d;
} GENERAL_NAME;

typedef struct ACCESS_DESCRIPTION_st {
    ASN1_OBJECT *method;
    GENERAL_NAME *location;
} ACCESS_DESCRIPTION;

SKM_DEFINE_STACK_OF_INTERNAL(ACCESS_DESCRIPTION, ACCESS_DESCRIPTION, ACCESS_DESCRIPTION)
#define sk_ACCESS_DESCRIPTION_num(sk) OPENSSL_sk_num(ossl_check_const_ACCESS_DESCRIPTION_sk_type(sk))
#define sk_ACCESS_DESCRIPTION_value(sk, idx) ((ACCESS_DESCRIPTION *)OPENSSL_sk_value(ossl_check_const_ACCESS_DESCRIPTION_sk_type(sk), (idx)))
#define sk_ACCESS_DESCRIPTION_new(cmp) ((STACK_OF(ACCESS_DESCRIPTION) *)OPENSSL_sk_new(ossl_check_ACCESS_DESCRIPTION_compfunc_type(cmp)))
#define sk_ACCESS_DESCRIPTION_new_null() ((STACK_OF(ACCESS_DESCRIPTION) *)OPENSSL_sk_new_null())
#define sk_ACCESS_DESCRIPTION_new_reserve(cmp, n) ((STACK_OF(ACCESS_DESCRIPTION) *)OPENSSL_sk_new_reserve(ossl_check_ACCESS_DESCRIPTION_compfunc_type(cmp), (n)))
#define sk_ACCESS_DESCRIPTION_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_ACCESS_DESCRIPTION_sk_type(sk), (n))
#define sk_ACCESS_DESCRIPTION_free(sk) OPENSSL_sk_free(ossl_check_ACCESS_DESCRIPTION_sk_type(sk))
#define sk_ACCESS_DESCRIPTION_zero(sk) OPENSSL_sk_zero(ossl_check_ACCESS_DESCRIPTION_sk_type(sk))
#define sk_ACCESS_DESCRIPTION_delete(sk, i) ((ACCESS_DESCRIPTION *)OPENSSL_sk_delete(ossl_check_ACCESS_DESCRIPTION_sk_type(sk), (i)))
#define sk_ACCESS_DESCRIPTION_delete_ptr(sk, ptr) ((ACCESS_DESCRIPTION *)OPENSSL_sk_delete_ptr(ossl_check_ACCESS_DESCRIPTION_sk_type(sk), ossl_check_ACCESS_DESCRIPTION_type(ptr)))
#define sk_ACCESS_DESCRIPTION_push(sk, ptr) OPENSSL_sk_push(ossl_check_ACCESS_DESCRIPTION_sk_type(sk), ossl_check_ACCESS_DESCRIPTION_type(ptr))
#define sk_ACCESS_DESCRIPTION_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_ACCESS_DESCRIPTION_sk_type(sk), ossl_check_ACCESS_DESCRIPTION_type(ptr))
#define sk_ACCESS_DESCRIPTION_pop(sk) ((ACCESS_DESCRIPTION *)OPENSSL_sk_pop(ossl_check_ACCESS_DESCRIPTION_sk_type(sk)))
#define sk_ACCESS_DESCRIPTION_shift(sk) ((ACCESS_DESCRIPTION *)OPENSSL_sk_shift(ossl_check_ACCESS_DESCRIPTION_sk_type(sk)))
#define sk_ACCESS_DESCRIPTION_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_ACCESS_DESCRIPTION_sk_type(sk),ossl_check_ACCESS_DESCRIPTION_freefunc_type(freefunc))
#define sk_ACCESS_DESCRIPTION_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_ACCESS_DESCRIPTION_sk_type(sk), ossl_check_ACCESS_DESCRIPTION_type(ptr), (idx))
#define sk_ACCESS_DESCRIPTION_set(sk, idx, ptr) ((ACCESS_DESCRIPTION *)OPENSSL_sk_set(ossl_check_ACCESS_DESCRIPTION_sk_type(sk), (idx), ossl_check_ACCESS_DESCRIPTION_type(ptr)))
#define sk_ACCESS_DESCRIPTION_find(sk, ptr) OPENSSL_sk_find(ossl_check_ACCESS_DESCRIPTION_sk_type(sk), ossl_check_ACCESS_DESCRIPTION_type(ptr))
#define sk_ACCESS_DESCRIPTION_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_ACCESS_DESCRIPTION_sk_type(sk), ossl_check_ACCESS_DESCRIPTION_type(ptr))
#define sk_ACCESS_DESCRIPTION_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_ACCESS_DESCRIPTION_sk_type(sk), ossl_check_ACCESS_DESCRIPTION_type(ptr), pnum)
#define sk_ACCESS_DESCRIPTION_sort(sk) OPENSSL_sk_sort(ossl_check_ACCESS_DESCRIPTION_sk_type(sk))
#define sk_ACCESS_DESCRIPTION_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_ACCESS_DESCRIPTION_sk_type(sk))
#define sk_ACCESS_DESCRIPTION_dup(sk) ((STACK_OF(ACCESS_DESCRIPTION) *)OPENSSL_sk_dup(ossl_check_const_ACCESS_DESCRIPTION_sk_type(sk)))
#define sk_ACCESS_DESCRIPTION_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(ACCESS_DESCRIPTION) *)OPENSSL_sk_deep_copy(ossl_check_const_ACCESS_DESCRIPTION_sk_type(sk), ossl_check_ACCESS_DESCRIPTION_copyfunc_type(copyfunc), ossl_check_ACCESS_DESCRIPTION_freefunc_type(freefunc)))
#define sk_ACCESS_DESCRIPTION_set_cmp_func(sk, cmp) ((sk_ACCESS_DESCRIPTION_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_ACCESS_DESCRIPTION_sk_type(sk), ossl_check_ACCESS_DESCRIPTION_compfunc_type(cmp)))
SKM_DEFINE_STACK_OF_INTERNAL(GENERAL_NAME, GENERAL_NAME, GENERAL_NAME)
#define sk_GENERAL_NAME_num(sk) OPENSSL_sk_num(ossl_check_const_GENERAL_NAME_sk_type(sk))
#define sk_GENERAL_NAME_value(sk, idx) ((GENERAL_NAME *)OPENSSL_sk_value(ossl_check_const_GENERAL_NAME_sk_type(sk), (idx)))
#define sk_GENERAL_NAME_new(cmp) ((STACK_OF(GENERAL_NAME) *)OPENSSL_sk_new(ossl_check_GENERAL_NAME_compfunc_type(cmp)))
#define sk_GENERAL_NAME_new_null() ((STACK_OF(GENERAL_NAME) *)OPENSSL_sk_new_null())
#define sk_GENERAL_NAME_new_reserve(cmp, n) ((STACK_OF(GENERAL_NAME) *)OPENSSL_sk_new_reserve(ossl_check_GENERAL_NAME_compfunc_type(cmp), (n)))
#define sk_GENERAL_NAME_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_GENERAL_NAME_sk_type(sk), (n))
#define sk_GENERAL_NAME_free(sk) OPENSSL_sk_free(ossl_check_GENERAL_NAME_sk_type(sk))
#define sk_GENERAL_NAME_zero(sk) OPENSSL_sk_zero(ossl_check_GENERAL_NAME_sk_type(sk))
#define sk_GENERAL_NAME_delete(sk, i) ((GENERAL_NAME *)OPENSSL_sk_delete(ossl_check_GENERAL_NAME_sk_type(sk), (i)))
#define sk_GENERAL_NAME_delete_ptr(sk, ptr) ((GENERAL_NAME *)OPENSSL_sk_delete_ptr(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr)))
#define sk_GENERAL_NAME_push(sk, ptr) OPENSSL_sk_push(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr))
#define sk_GENERAL_NAME_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr))
#define sk_GENERAL_NAME_pop(sk) ((GENERAL_NAME *)OPENSSL_sk_pop(ossl_check_GENERAL_NAME_sk_type(sk)))
#define sk_GENERAL_NAME_shift(sk) ((GENERAL_NAME *)OPENSSL_sk_shift(ossl_check_GENERAL_NAME_sk_type(sk)))
#define sk_GENERAL_NAME_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_GENERAL_NAME_sk_type(sk),ossl_check_GENERAL_NAME_freefunc_type(freefunc))
#define sk_GENERAL_NAME_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr), (idx))
#define sk_GENERAL_NAME_set(sk, idx, ptr) ((GENERAL_NAME *)OPENSSL_sk_set(ossl_check_GENERAL_NAME_sk_type(sk), (idx), ossl_check_GENERAL_NAME_type(ptr)))
#define sk_GENERAL_NAME_find(sk, ptr) OPENSSL_sk_find(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr))
#define sk_GENERAL_NAME_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr))
#define sk_GENERAL_NAME_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr), pnum)
#define sk_GENERAL_NAME_sort(sk) OPENSSL_sk_sort(ossl_check_GENERAL_NAME_sk_type(sk))
#define sk_GENERAL_NAME_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_GENERAL_NAME_sk_type(sk))
#define sk_GENERAL_NAME_dup(sk) ((STACK_OF(GENERAL_NAME) *)OPENSSL_sk_dup(ossl_check_const_GENERAL_NAME_sk_type(sk)))
#define sk_GENERAL_NAME_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(GENERAL_NAME) *)OPENSSL_sk_deep_copy(ossl_check_const_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_copyfunc_type(copyfunc), ossl_check_GENERAL_NAME_freefunc_type(freefunc)))
#define sk_GENERAL_NAME_set_cmp_func(sk, cmp) ((sk_GENERAL_NAME_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_compfunc_type(cmp)))


typedef STACK_OF(ACCESS_DESCRIPTION) AUTHORITY_INFO_ACCESS;
typedef STACK_OF(ASN1_OBJECT) EXTENDED_KEY_USAGE;
typedef STACK_OF(ASN1_INTEGER) TLS_FEATURE;
typedef STACK_OF(GENERAL_NAME) GENERAL_NAMES;

SKM_DEFINE_STACK_OF_INTERNAL(GENERAL_NAMES, GENERAL_NAMES, GENERAL_NAMES)
#define sk_GENERAL_NAMES_num(sk) OPENSSL_sk_num(ossl_check_const_GENERAL_NAMES_sk_type(sk))
#define sk_GENERAL_NAMES_value(sk, idx) ((GENERAL_NAMES *)OPENSSL_sk_value(ossl_check_const_GENERAL_NAMES_sk_type(sk), (idx)))
#define sk_GENERAL_NAMES_new(cmp) ((STACK_OF(GENERAL_NAMES) *)OPENSSL_sk_new(ossl_check_GENERAL_NAMES_compfunc_type(cmp)))
#define sk_GENERAL_NAMES_new_null() ((STACK_OF(GENERAL_NAMES) *)OPENSSL_sk_new_null())
#define sk_GENERAL_NAMES_new_reserve(cmp, n) ((STACK_OF(GENERAL_NAMES) *)OPENSSL_sk_new_reserve(ossl_check_GENERAL_NAMES_compfunc_type(cmp), (n)))
#define sk_GENERAL_NAMES_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_GENERAL_NAMES_sk_type(sk), (n))
#define sk_GENERAL_NAMES_free(sk) OPENSSL_sk_free(ossl_check_GENERAL_NAMES_sk_type(sk))
#define sk_GENERAL_NAMES_zero(sk) OPENSSL_sk_zero(ossl_check_GENERAL_NAMES_sk_type(sk))
#define sk_GENERAL_NAMES_delete(sk, i) ((GENERAL_NAMES *)OPENSSL_sk_delete(ossl_check_GENERAL_NAMES_sk_type(sk), (i)))
#define sk_GENERAL_NAMES_delete_ptr(sk, ptr) ((GENERAL_NAMES *)OPENSSL_sk_delete_ptr(ossl_check_GENERAL_NAMES_sk_type(sk), ossl_check_GENERAL_NAMES_type(ptr)))
#define sk_GENERAL_NAMES_push(sk, ptr) OPENSSL_sk_push(ossl_check_GENERAL_NAMES_sk_type(sk), ossl_check_GENERAL_NAMES_type(ptr))
#define sk_GENERAL_NAMES_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_GENERAL_NAMES_sk_type(sk), ossl_check_GENERAL_NAMES_type(ptr))
#define sk_GENERAL_NAMES_pop(sk) ((GENERAL_NAMES *)OPENSSL_sk_pop(ossl_check_GENERAL_NAMES_sk_type(sk)))
#define sk_GENERAL_NAMES_shift(sk) ((GENERAL_NAMES *)OPENSSL_sk_shift(ossl_check_GENERAL_NAMES_sk_type(sk)))
#define sk_GENERAL_NAMES_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_GENERAL_NAMES_sk_type(sk),ossl_check_GENERAL_NAMES_freefunc_type(freefunc))
#define sk_GENERAL_NAMES_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_GENERAL_NAMES_sk_type(sk), ossl_check_GENERAL_NAMES_type(ptr), (idx))
#define sk_GENERAL_NAMES_set(sk, idx, ptr) ((GENERAL_NAMES *)OPENSSL_sk_set(ossl_check_GENERAL_NAMES_sk_type(sk), (idx), ossl_check_GENERAL_NAMES_type(ptr)))
#define sk_GENERAL_NAMES_find(sk, ptr) OPENSSL_sk_find(ossl_check_GENERAL_NAMES_sk_type(sk), ossl_check_GENERAL_NAMES_type(ptr))
#define sk_GENERAL_NAMES_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_GENERAL_NAMES_sk_type(sk), ossl_check_GENERAL_NAMES_type(ptr))
#define sk_GENERAL_NAMES_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_GENERAL_NAMES_sk_type(sk), ossl_check_GENERAL_NAMES_type(ptr), pnum)
#define sk_GENERAL_NAMES_sort(sk) OPENSSL_sk_sort(ossl_check_GENERAL_NAMES_sk_type(sk))
#define sk_GENERAL_NAMES_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_GENERAL_NAMES_sk_type(sk))
#define sk_GENERAL_NAMES_dup(sk) ((STACK_OF(GENERAL_NAMES) *)OPENSSL_sk_dup(ossl_check_const_GENERAL_NAMES_sk_type(sk)))
#define sk_GENERAL_NAMES_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(GENERAL_NAMES) *)OPENSSL_sk_deep_copy(ossl_check_const_GENERAL_NAMES_sk_type(sk), ossl_check_GENERAL_NAMES_copyfunc_type(copyfunc), ossl_check_GENERAL_NAMES_freefunc_type(freefunc)))
#define sk_GENERAL_NAMES_set_cmp_func(sk, cmp) ((sk_GENERAL_NAMES_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_GENERAL_NAMES_sk_type(sk), ossl_check_GENERAL_NAMES_compfunc_type(cmp)))


typedef struct DIST_POINT_NAME_st {
    int type;
    union {
        GENERAL_NAMES *fullname;
        STACK_OF(X509_NAME_ENTRY) *relativename;
    } name;
/* If relativename then this contains the full distribution point name */
    X509_NAME *dpname;
} DIST_POINT_NAME;
/* All existing reasons */
# define CRLDP_ALL_REASONS       0x807f

# define CRL_REASON_NONE                         -1
# define CRL_REASON_UNSPECIFIED                  0
# define CRL_REASON_KEY_COMPROMISE               1
# define CRL_REASON_CA_COMPROMISE                2
# define CRL_REASON_AFFILIATION_CHANGED          3
# define CRL_REASON_SUPERSEDED                   4
# define CRL_REASON_CESSATION_OF_OPERATION       5
# define CRL_REASON_CERTIFICATE_HOLD             6
# define CRL_REASON_REMOVE_FROM_CRL              8
# define CRL_REASON_PRIVILEGE_WITHDRAWN          9
# define CRL_REASON_AA_COMPROMISE                10

struct DIST_POINT_st {
    DIST_POINT_NAME *distpoint;
    ASN1_BIT_STRING *reasons;
    GENERAL_NAMES *CRLissuer;
    int dp_reasons;
};

SKM_DEFINE_STACK_OF_INTERNAL(DIST_POINT, DIST_POINT, DIST_POINT)
#define sk_DIST_POINT_num(sk) OPENSSL_sk_num(ossl_check_const_DIST_POINT_sk_type(sk))
#define sk_DIST_POINT_value(sk, idx) ((DIST_POINT *)OPENSSL_sk_value(ossl_check_const_DIST_POINT_sk_type(sk), (idx)))
#define sk_DIST_POINT_new(cmp) ((STACK_OF(DIST_POINT) *)OPENSSL_sk_new(ossl_check_DIST_POINT_compfunc_type(cmp)))
#define sk_DIST_POINT_new_null() ((STACK_OF(DIST_POINT) *)OPENSSL_sk_new_null())
#define sk_DIST_POINT_new_reserve(cmp, n) ((STACK_OF(DIST_POINT) *)OPENSSL_sk_new_reserve(ossl_check_DIST_POINT_compfunc_type(cmp), (n)))
#define sk_DIST_POINT_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_DIST_POINT_sk_type(sk), (n))
#define sk_DIST_POINT_free(sk) OPENSSL_sk_free(ossl_check_DIST_POINT_sk_type(sk))
#define sk_DIST_POINT_zero(sk) OPENSSL_sk_zero(ossl_check_DIST_POINT_sk_type(sk))
#define sk_DIST_POINT_delete(sk, i) ((DIST_POINT *)OPENSSL_sk_delete(ossl_check_DIST_POINT_sk_type(sk), (i)))
#define sk_DIST_POINT_delete_ptr(sk, ptr) ((DIST_POINT *)OPENSSL_sk_delete_ptr(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr)))
#define sk_DIST_POINT_push(sk, ptr) OPENSSL_sk_push(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr))
#define sk_DIST_POINT_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr))
#define sk_DIST_POINT_pop(sk) ((DIST_POINT *)OPENSSL_sk_pop(ossl_check_DIST_POINT_sk_type(sk)))
#define sk_DIST_POINT_shift(sk) ((DIST_POINT *)OPENSSL_sk_shift(ossl_check_DIST_POINT_sk_type(sk)))
#define sk_DIST_POINT_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_DIST_POINT_sk_type(sk),ossl_check_DIST_POINT_freefunc_type(freefunc))
#define sk_DIST_POINT_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr), (idx))
#define sk_DIST_POINT_set(sk, idx, ptr) ((DIST_POINT *)OPENSSL_sk_set(ossl_check_DIST_POINT_sk_type(sk), (idx), ossl_check_DIST_POINT_type(ptr)))
#define sk_DIST_POINT_find(sk, ptr) OPENSSL_sk_find(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr))
#define sk_DIST_POINT_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr))
#define sk_DIST_POINT_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr), pnum)
#define sk_DIST_POINT_sort(sk) OPENSSL_sk_sort(ossl_check_DIST_POINT_sk_type(sk))
#define sk_DIST_POINT_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_DIST_POINT_sk_type(sk))
#define sk_DIST_POINT_dup(sk) ((STACK_OF(DIST_POINT) *)OPENSSL_sk_dup(ossl_check_const_DIST_POINT_sk_type(sk)))
#define sk_DIST_POINT_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(DIST_POINT) *)OPENSSL_sk_deep_copy(ossl_check_const_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_copyfunc_type(copyfunc), ossl_check_DIST_POINT_freefunc_type(freefunc)))
#define sk_DIST_POINT_set_cmp_func(sk, cmp) ((sk_DIST_POINT_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_compfunc_type(cmp)))


typedef STACK_OF(DIST_POINT) CRL_DIST_POINTS;

struct AUTHORITY_KEYID_st {
    ASN1_OCTET_STRING *keyid;
    GENERAL_NAMES *issuer;
    ASN1_INTEGER *serial;
};

/* Strong extranet structures */

typedef struct SXNET_ID_st {
    ASN1_INTEGER *zone;
    ASN1_OCTET_STRING *user;
} SXNETID;

SKM_DEFINE_STACK_OF_INTERNAL(SXNETID, SXNETID, SXNETID)
#define sk_SXNETID_num(sk) OPENSSL_sk_num(ossl_check_const_SXNETID_sk_type(sk))
#define sk_SXNETID_value(sk, idx) ((SXNETID *)OPENSSL_sk_value(ossl_check_const_SXNETID_sk_type(sk), (idx)))
#define sk_SXNETID_new(cmp) ((STACK_OF(SXNETID) *)OPENSSL_sk_new(ossl_check_SXNETID_compfunc_type(cmp)))
#define sk_SXNETID_new_null() ((STACK_OF(SXNETID) *)OPENSSL_sk_new_null())
#define sk_SXNETID_new_reserve(cmp, n) ((STACK_OF(SXNETID) *)OPENSSL_sk_new_reserve(ossl_check_SXNETID_compfunc_type(cmp), (n)))
#define sk_SXNETID_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_SXNETID_sk_type(sk), (n))
#define sk_SXNETID_free(sk) OPENSSL_sk_free(ossl_check_SXNETID_sk_type(sk))
#define sk_SXNETID_zero(sk) OPENSSL_sk_zero(ossl_check_SXNETID_sk_type(sk))
#define sk_SXNETID_delete(sk, i) ((SXNETID *)OPENSSL_sk_delete(ossl_check_SXNETID_sk_type(sk), (i)))
#define sk_SXNETID_delete_ptr(sk, ptr) ((SXNETID *)OPENSSL_sk_delete_ptr(ossl_check_SXNETID_sk_type(sk), ossl_check_SXNETID_type(ptr)))
#define sk_SXNETID_push(sk, ptr) OPENSSL_sk_push(ossl_check_SXNETID_sk_type(sk), ossl_check_SXNETID_type(ptr))
#define sk_SXNETID_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_SXNETID_sk_type(sk), ossl_check_SXNETID_type(ptr))
#define sk_SXNETID_pop(sk) ((SXNETID *)OPENSSL_sk_pop(ossl_check_SXNETID_sk_type(sk)))
#define sk_SXNETID_shift(sk) ((SXNETID *)OPENSSL_sk_shift(ossl_check_SXNETID_sk_type(sk)))
#define sk_SXNETID_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_SXNETID_sk_type(sk),ossl_check_SXNETID_freefunc_type(freefunc))
#define sk_SXNETID_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_SXNETID_sk_type(sk), ossl_check_SXNETID_type(ptr), (idx))
#define sk_SXNETID_set(sk, idx, ptr) ((SXNETID *)OPENSSL_sk_set(ossl_check_SXNETID_sk_type(sk), (idx), ossl_check_SXNETID_type(ptr)))
#define sk_SXNETID_find(sk, ptr) OPENSSL_sk_find(ossl_check_SXNETID_sk_type(sk), ossl_check_SXNETID_type(ptr))
#define sk_SXNETID_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_SXNETID_sk_type(sk), ossl_check_SXNETID_type(ptr))
#define sk_SXNETID_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_SXNETID_sk_type(sk), ossl_check_SXNETID_type(ptr), pnum)
#define sk_SXNETID_sort(sk) OPENSSL_sk_sort(ossl_check_SXNETID_sk_type(sk))
#define sk_SXNETID_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_SXNETID_sk_type(sk))
#define sk_SXNETID_dup(sk) ((STACK_OF(SXNETID) *)OPENSSL_sk_dup(ossl_check_const_SXNETID_sk_type(sk)))
#define sk_SXNETID_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(SXNETID) *)OPENSSL_sk_deep_copy(ossl_check_const_SXNETID_sk_type(sk), ossl_check_SXNETID_copyfunc_type(copyfunc), ossl_check_SXNETID_freefunc_type(freefunc)))
#define sk_SXNETID_set_cmp_func(sk, cmp) ((sk_SXNETID_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_SXNETID_sk_type(sk), ossl_check_SXNETID_compfunc_type(cmp)))



typedef struct SXNET_st {
    ASN1_INTEGER *version;
    STACK_OF(SXNETID) *ids;
} SXNET;

typedef struct ISSUER_SIGN_TOOL_st {
    ASN1_UTF8STRING *signTool;
    ASN1_UTF8STRING *cATool;
    ASN1_UTF8STRING *signToolCert;
    ASN1_UTF8STRING *cAToolCert;
} ISSUER_SIGN_TOOL;

typedef struct NOTICEREF_st {
    ASN1_STRING *organization;
    STACK_OF(ASN1_INTEGER) *noticenos;
} NOTICEREF;

typedef struct USERNOTICE_st {
    NOTICEREF *noticeref;
    ASN1_STRING *exptext;
} USERNOTICE;

typedef struct POLICYQUALINFO_st {
    ASN1_OBJECT *pqualid;
    union {
        ASN1_IA5STRING *cpsuri;
        USERNOTICE *usernotice;
        ASN1_TYPE *other;
    } d;
} POLICYQUALINFO;

SKM_DEFINE_STACK_OF_INTERNAL(POLICYQUALINFO, POLICYQUALINFO, POLICYQUALINFO)
#define sk_POLICYQUALINFO_num(sk) OPENSSL_sk_num(ossl_check_const_POLICYQUALINFO_sk_type(sk))
#define sk_POLICYQUALINFO_value(sk, idx) ((POLICYQUALINFO *)OPENSSL_sk_value(ossl_check_const_POLICYQUALINFO_sk_type(sk), (idx)))
#define sk_POLICYQUALINFO_new(cmp) ((STACK_OF(POLICYQUALINFO) *)OPENSSL_sk_new(ossl_check_POLICYQUALINFO_compfunc_type(cmp)))
#define sk_POLICYQUALINFO_new_null() ((STACK_OF(POLICYQUALINFO) *)OPENSSL_sk_new_null())
#define sk_POLICYQUALINFO_new_reserve(cmp, n) ((STACK_OF(POLICYQUALINFO) *)OPENSSL_sk_new_reserve(ossl_check_POLICYQUALINFO_compfunc_type(cmp), (n)))
#define sk_POLICYQUALINFO_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_POLICYQUALINFO_sk_type(sk), (n))
#define sk_POLICYQUALINFO_free(sk) OPENSSL_sk_free(ossl_check_POLICYQUALINFO_sk_type(sk))
#define sk_POLICYQUALINFO_zero(sk) OPENSSL_sk_zero(ossl_check_POLICYQUALINFO_sk_type(sk))
#define sk_POLICYQUALINFO_delete(sk, i) ((POLICYQUALINFO *)OPENSSL_sk_delete(ossl_check_POLICYQUALINFO_sk_type(sk), (i)))
#define sk_POLICYQUALINFO_delete_ptr(sk, ptr) ((POLICYQUALINFO *)OPENSSL_sk_delete_ptr(ossl_check_POLICYQUALINFO_sk_type(sk), ossl_check_POLICYQUALINFO_type(ptr)))
#define sk_POLICYQUALINFO_push(sk, ptr) OPENSSL_sk_push(ossl_check_POLICYQUALINFO_sk_type(sk), ossl_check_POLICYQUALINFO_type(ptr))
#define sk_POLICYQUALINFO_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_POLICYQUALINFO_sk_type(sk), ossl_check_POLICYQUALINFO_type(ptr))
#define sk_POLICYQUALINFO_pop(sk) ((POLICYQUALINFO *)OPENSSL_sk_pop(ossl_check_POLICYQUALINFO_sk_type(sk)))
#define sk_POLICYQUALINFO_shift(sk) ((POLICYQUALINFO *)OPENSSL_sk_shift(ossl_check_POLICYQUALINFO_sk_type(sk)))
#define sk_POLICYQUALINFO_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_POLICYQUALINFO_sk_type(sk),ossl_check_POLICYQUALINFO_freefunc_type(freefunc))
#define sk_POLICYQUALINFO_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_POLICYQUALINFO_sk_type(sk), ossl_check_POLICYQUALINFO_type(ptr), (idx))
#define sk_POLICYQUALINFO_set(sk, idx, ptr) ((POLICYQUALINFO *)OPENSSL_sk_set(ossl_check_POLICYQUALINFO_sk_type(sk), (idx), ossl_check_POLICYQUALINFO_type(ptr)))
#define sk_POLICYQUALINFO_find(sk, ptr) OPENSSL_sk_find(ossl_check_POLICYQUALINFO_sk_type(sk), ossl_check_POLICYQUALINFO_type(ptr))
#define sk_POLICYQUALINFO_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_POLICYQUALINFO_sk_type(sk), ossl_check_POLICYQUALINFO_type(ptr))
#define sk_POLICYQUALINFO_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_POLICYQUALINFO_sk_type(sk), ossl_check_POLICYQUALINFO_type(ptr), pnum)
#define sk_POLICYQUALINFO_sort(sk) OPENSSL_sk_sort(ossl_check_POLICYQUALINFO_sk_type(sk))
#define sk_POLICYQUALINFO_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_POLICYQUALINFO_sk_type(sk))
#define sk_POLICYQUALINFO_dup(sk) ((STACK_OF(POLICYQUALINFO) *)OPENSSL_sk_dup(ossl_check_const_POLICYQUALINFO_sk_type(sk)))
#define sk_POLICYQUALINFO_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(POLICYQUALINFO) *)OPENSSL_sk_deep_copy(ossl_check_const_POLICYQUALINFO_sk_type(sk), ossl_check_POLICYQUALINFO_copyfunc_type(copyfunc), ossl_check_POLICYQUALINFO_freefunc_type(freefunc)))
#define sk_POLICYQUALINFO_set_cmp_func(sk, cmp) ((sk_POLICYQUALINFO_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_POLICYQUALINFO_sk_type(sk), ossl_check_POLICYQUALINFO_compfunc_type(cmp)))



typedef struct POLICYINFO_st {
    ASN1_OBJECT *policyid;
    STACK_OF(POLICYQUALINFO) *qualifiers;
} POLICYINFO;

SKM_DEFINE_STACK_OF_INTERNAL(POLICYINFO, POLICYINFO, POLICYINFO)
#define sk_POLICYINFO_num(sk) OPENSSL_sk_num(ossl_check_const_POLICYINFO_sk_type(sk))
#define sk_POLICYINFO_value(sk, idx) ((POLICYINFO *)OPENSSL_sk_value(ossl_check_const_POLICYINFO_sk_type(sk), (idx)))
#define sk_POLICYINFO_new(cmp) ((STACK_OF(POLICYINFO) *)OPENSSL_sk_new(ossl_check_POLICYINFO_compfunc_type(cmp)))
#define sk_POLICYINFO_new_null() ((STACK_OF(POLICYINFO) *)OPENSSL_sk_new_null())
#define sk_POLICYINFO_new_reserve(cmp, n) ((STACK_OF(POLICYINFO) *)OPENSSL_sk_new_reserve(ossl_check_POLICYINFO_compfunc_type(cmp), (n)))
#define sk_POLICYINFO_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_POLICYINFO_sk_type(sk), (n))
#define sk_POLICYINFO_free(sk) OPENSSL_sk_free(ossl_check_POLICYINFO_sk_type(sk))
#define sk_POLICYINFO_zero(sk) OPENSSL_sk_zero(ossl_check_POLICYINFO_sk_type(sk))
#define sk_POLICYINFO_delete(sk, i) ((POLICYINFO *)OPENSSL_sk_delete(ossl_check_POLICYINFO_sk_type(sk), (i)))
#define sk_POLICYINFO_delete_ptr(sk, ptr) ((POLICYINFO *)OPENSSL_sk_delete_ptr(ossl_check_POLICYINFO_sk_type(sk), ossl_check_POLICYINFO_type(ptr)))
#define sk_POLICYINFO_push(sk, ptr) OPENSSL_sk_push(ossl_check_POLICYINFO_sk_type(sk), ossl_check_POLICYINFO_type(ptr))
#define sk_POLICYINFO_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_POLICYINFO_sk_type(sk), ossl_check_POLICYINFO_type(ptr))
#define sk_POLICYINFO_pop(sk) ((POLICYINFO *)OPENSSL_sk_pop(ossl_check_POLICYINFO_sk_type(sk)))
#define sk_POLICYINFO_shift(sk) ((POLICYINFO *)OPENSSL_sk_shift(ossl_check_POLICYINFO_sk_type(sk)))
#define sk_POLICYINFO_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_POLICYINFO_sk_type(sk),ossl_check_POLICYINFO_freefunc_type(freefunc))
#define sk_POLICYINFO_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_POLICYINFO_sk_type(sk), ossl_check_POLICYINFO_type(ptr), (idx))
#define sk_POLICYINFO_set(sk, idx, ptr) ((POLICYINFO *)OPENSSL_sk_set(ossl_check_POLICYINFO_sk_type(sk), (idx), ossl_check_POLICYINFO_type(ptr)))
#define sk_POLICYINFO_find(sk, ptr) OPENSSL_sk_find(ossl_check_POLICYINFO_sk_type(sk), ossl_check_POLICYINFO_type(ptr))
#define sk_POLICYINFO_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_POLICYINFO_sk_type(sk), ossl_check_POLICYINFO_type(ptr))
#define sk_POLICYINFO_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_POLICYINFO_sk_type(sk), ossl_check_POLICYINFO_type(ptr), pnum)
#define sk_POLICYINFO_sort(sk) OPENSSL_sk_sort(ossl_check_POLICYINFO_sk_type(sk))
#define sk_POLICYINFO_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_POLICYINFO_sk_type(sk))
#define sk_POLICYINFO_dup(sk) ((STACK_OF(POLICYINFO) *)OPENSSL_sk_dup(ossl_check_const_POLICYINFO_sk_type(sk)))
#define sk_POLICYINFO_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(POLICYINFO) *)OPENSSL_sk_deep_copy(ossl_check_const_POLICYINFO_sk_type(sk), ossl_check_POLICYINFO_copyfunc_type(copyfunc), ossl_check_POLICYINFO_freefunc_type(freefunc)))
#define sk_POLICYINFO_set_cmp_func(sk, cmp) ((sk_POLICYINFO_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_POLICYINFO_sk_type(sk), ossl_check_POLICYINFO_compfunc_type(cmp)))


typedef STACK_OF(POLICYINFO) CERTIFICATEPOLICIES;

typedef struct POLICY_MAPPING_st {
    ASN1_OBJECT *issuerDomainPolicy;
    ASN1_OBJECT *subjectDomainPolicy;
} POLICY_MAPPING;

SKM_DEFINE_STACK_OF_INTERNAL(POLICY_MAPPING, POLICY_MAPPING, POLICY_MAPPING)
#define sk_POLICY_MAPPING_num(sk) OPENSSL_sk_num(ossl_check_const_POLICY_MAPPING_sk_type(sk))
#define sk_POLICY_MAPPING_value(sk, idx) ((POLICY_MAPPING *)OPENSSL_sk_value(ossl_check_const_POLICY_MAPPING_sk_type(sk), (idx)))
#define sk_POLICY_MAPPING_new(cmp) ((STACK_OF(POLICY_MAPPING) *)OPENSSL_sk_new(ossl_check_POLICY_MAPPING_compfunc_type(cmp)))
#define sk_POLICY_MAPPING_new_null() ((STACK_OF(POLICY_MAPPING) *)OPENSSL_sk_new_null())
#define sk_POLICY_MAPPING_new_reserve(cmp, n) ((STACK_OF(POLICY_MAPPING) *)OPENSSL_sk_new_reserve(ossl_check_POLICY_MAPPING_compfunc_type(cmp), (n)))
#define sk_POLICY_MAPPING_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_POLICY_MAPPING_sk_type(sk), (n))
#define sk_POLICY_MAPPING_free(sk) OPENSSL_sk_free(ossl_check_POLICY_MAPPING_sk_type(sk))
#define sk_POLICY_MAPPING_zero(sk) OPENSSL_sk_zero(ossl_check_POLICY_MAPPING_sk_type(sk))
#define sk_POLICY_MAPPING_delete(sk, i) ((POLICY_MAPPING *)OPENSSL_sk_delete(ossl_check_POLICY_MAPPING_sk_type(sk), (i)))
#define sk_POLICY_MAPPING_delete_ptr(sk, ptr) ((POLICY_MAPPING *)OPENSSL_sk_delete_ptr(ossl_check_POLICY_MAPPING_sk_type(sk), ossl_check_POLICY_MAPPING_type(ptr)))
#define sk_POLICY_MAPPING_push(sk, ptr) OPENSSL_sk_push(ossl_check_POLICY_MAPPING_sk_type(sk), ossl_check_POLICY_MAPPING_type(ptr))
#define sk_POLICY_MAPPING_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_POLICY_MAPPING_sk_type(sk), ossl_check_POLICY_MAPPING_type(ptr))
#define sk_POLICY_MAPPING_pop(sk) ((POLICY_MAPPING *)OPENSSL_sk_pop(ossl_check_POLICY_MAPPING_sk_type(sk)))
#define sk_POLICY_MAPPING_shift(sk) ((POLICY_MAPPING *)OPENSSL_sk_shift(ossl_check_POLICY_MAPPING_sk_type(sk)))
#define sk_POLICY_MAPPING_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_POLICY_MAPPING_sk_type(sk),ossl_check_POLICY_MAPPING_freefunc_type(freefunc))
#define sk_POLICY_MAPPING_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_POLICY_MAPPING_sk_type(sk), ossl_check_POLICY_MAPPING_type(ptr), (idx))
#define sk_POLICY_MAPPING_set(sk, idx, ptr) ((POLICY_MAPPING *)OPENSSL_sk_set(ossl_check_POLICY_MAPPING_sk_type(sk), (idx), ossl_check_POLICY_MAPPING_type(ptr)))
#define sk_POLICY_MAPPING_find(sk, ptr) OPENSSL_sk_find(ossl_check_POLICY_MAPPING_sk_type(sk), ossl_check_POLICY_MAPPING_type(ptr))
#define sk_POLICY_MAPPING_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_POLICY_MAPPING_sk_type(sk), ossl_check_POLICY_MAPPING_type(ptr))
#define sk_POLICY_MAPPING_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_POLICY_MAPPING_sk_type(sk), ossl_check_POLICY_MAPPING_type(ptr), pnum)
#define sk_POLICY_MAPPING_sort(sk) OPENSSL_sk_sort(ossl_check_POLICY_MAPPING_sk_type(sk))
#define sk_POLICY_MAPPING_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_POLICY_MAPPING_sk_type(sk))
#define sk_POLICY_MAPPING_dup(sk) ((STACK_OF(POLICY_MAPPING) *)OPENSSL_sk_dup(ossl_check_const_POLICY_MAPPING_sk_type(sk)))
#define sk_POLICY_MAPPING_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(POLICY_MAPPING) *)OPENSSL_sk_deep_copy(ossl_check_const_POLICY_MAPPING_sk_type(sk), ossl_check_POLICY_MAPPING_copyfunc_type(copyfunc), ossl_check_POLICY_MAPPING_freefunc_type(freefunc)))
#define sk_POLICY_MAPPING_set_cmp_func(sk, cmp) ((sk_POLICY_MAPPING_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_POLICY_MAPPING_sk_type(sk), ossl_check_POLICY_MAPPING_compfunc_type(cmp)))


typedef STACK_OF(POLICY_MAPPING) POLICY_MAPPINGS;

typedef struct GENERAL_SUBTREE_st {
    GENERAL_NAME *base;
    ASN1_INTEGER *minimum;
    ASN1_INTEGER *maximum;
} GENERAL_SUBTREE;

SKM_DEFINE_STACK_OF_INTERNAL(GENERAL_SUBTREE, GENERAL_SUBTREE, GENERAL_SUBTREE)
#define sk_GENERAL_SUBTREE_num(sk) OPENSSL_sk_num(ossl_check_const_GENERAL_SUBTREE_sk_type(sk))
#define sk_GENERAL_SUBTREE_value(sk, idx) ((GENERAL_SUBTREE *)OPENSSL_sk_value(ossl_check_const_GENERAL_SUBTREE_sk_type(sk), (idx)))
#define sk_GENERAL_SUBTREE_new(cmp) ((STACK_OF(GENERAL_SUBTREE) *)OPENSSL_sk_new(ossl_check_GENERAL_SUBTREE_compfunc_type(cmp)))
#define sk_GENERAL_SUBTREE_new_null() ((STACK_OF(GENERAL_SUBTREE) *)OPENSSL_sk_new_null())
#define sk_GENERAL_SUBTREE_new_reserve(cmp, n) ((STACK_OF(GENERAL_SUBTREE) *)OPENSSL_sk_new_reserve(ossl_check_GENERAL_SUBTREE_compfunc_type(cmp), (n)))
#define sk_GENERAL_SUBTREE_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_GENERAL_SUBTREE_sk_type(sk), (n))
#define sk_GENERAL_SUBTREE_free(sk) OPENSSL_sk_free(ossl_check_GENERAL_SUBTREE_sk_type(sk))
#define sk_GENERAL_SUBTREE_zero(sk) OPENSSL_sk_zero(ossl_check_GENERAL_SUBTREE_sk_type(sk))
#define sk_GENERAL_SUBTREE_delete(sk, i) ((GENERAL_SUBTREE *)OPENSSL_sk_delete(ossl_check_GENERAL_SUBTREE_sk_type(sk), (i)))
#define sk_GENERAL_SUBTREE_delete_ptr(sk, ptr) ((GENERAL_SUBTREE *)OPENSSL_sk_delete_ptr(ossl_check_GENERAL_SUBTREE_sk_type(sk), ossl_check_GENERAL_SUBTREE_type(ptr)))
#define sk_GENERAL_SUBTREE_push(sk, ptr) OPENSSL_sk_push(ossl_check_GENERAL_SUBTREE_sk_type(sk), ossl_check_GENERAL_SUBTREE_type(ptr))
#define sk_GENERAL_SUBTREE_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_GENERAL_SUBTREE_sk_type(sk), ossl_check_GENERAL_SUBTREE_type(ptr))
#define sk_GENERAL_SUBTREE_pop(sk) ((GENERAL_SUBTREE *)OPENSSL_sk_pop(ossl_check_GENERAL_SUBTREE_sk_type(sk)))
#define sk_GENERAL_SUBTREE_shift(sk) ((GENERAL_SUBTREE *)OPENSSL_sk_shift(ossl_check_GENERAL_SUBTREE_sk_type(sk)))
#define sk_GENERAL_SUBTREE_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_GENERAL_SUBTREE_sk_type(sk),ossl_check_GENERAL_SUBTREE_freefunc_type(freefunc))
#define sk_GENERAL_SUBTREE_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_GENERAL_SUBTREE_sk_type(sk), ossl_check_GENERAL_SUBTREE_type(ptr), (idx))
#define sk_GENERAL_SUBTREE_set(sk, idx, ptr) ((GENERAL_SUBTREE *)OPENSSL_sk_set(ossl_check_GENERAL_SUBTREE_sk_type(sk), (idx), ossl_check_GENERAL_SUBTREE_type(ptr)))
#define sk_GENERAL_SUBTREE_find(sk, ptr) OPENSSL_sk_find(ossl_check_GENERAL_SUBTREE_sk_type(sk), ossl_check_GENERAL_SUBTREE_type(ptr))
#define sk_GENERAL_SUBTREE_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_GENERAL_SUBTREE_sk_type(sk), ossl_check_GENERAL_SUBTREE_type(ptr))
#define sk_GENERAL_SUBTREE_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_GENERAL_SUBTREE_sk_type(sk), ossl_check_GENERAL_SUBTREE_type(ptr), pnum)
#define sk_GENERAL_SUBTREE_sort(sk) OPENSSL_sk_sort(ossl_check_GENERAL_SUBTREE_sk_type(sk))
#define sk_GENERAL_SUBTREE_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_GENERAL_SUBTREE_sk_type(sk))
#define sk_GENERAL_SUBTREE_dup(sk) ((STACK_OF(GENERAL_SUBTREE) *)OPENSSL_sk_dup(ossl_check_const_GENERAL_SUBTREE_sk_type(sk)))
#define sk_GENERAL_SUBTREE_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(GENERAL_SUBTREE) *)OPENSSL_sk_deep_copy(ossl_check_const_GENERAL_SUBTREE_sk_type(sk), ossl_check_GENERAL_SUBTREE_copyfunc_type(copyfunc), ossl_check_GENERAL_SUBTREE_freefunc_type(freefunc)))
#define sk_GENERAL_SUBTREE_set_cmp_func(sk, cmp) ((sk_GENERAL_SUBTREE_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_GENERAL_SUBTREE_sk_type(sk), ossl_check_GENERAL_SUBTREE_compfunc_type(cmp)))


struct NAME_CONSTRAINTS_st {
    STACK_OF(GENERAL_SUBTREE) *permittedSubtrees;
    STACK_OF(GENERAL_SUBTREE) *excludedSubtrees;
};

typedef struct POLICY_CONSTRAINTS_st {
    ASN1_INTEGER *requireExplicitPolicy;
    ASN1_INTEGER *inhibitPolicyMapping;
} POLICY_CONSTRAINTS;

/* Proxy certificate structures, see RFC 3820 */
typedef struct PROXY_POLICY_st {
    ASN1_OBJECT *policyLanguage;
    ASN1_OCTET_STRING *policy;
} PROXY_POLICY;

typedef struct PROXY_CERT_INFO_EXTENSION_st {
    ASN1_INTEGER *pcPathLengthConstraint;
    PROXY_POLICY *proxyPolicy;
} PROXY_CERT_INFO_EXTENSION;

DECLARE_ASN1_FUNCTIONS(PROXY_POLICY)
DECLARE_ASN1_FUNCTIONS(PROXY_CERT_INFO_EXTENSION)

struct ISSUING_DIST_POINT_st {
    DIST_POINT_NAME *distpoint;
    int onlyuser;
    int onlyCA;
    ASN1_BIT_STRING *onlysomereasons;
    int indirectCRL;
    int onlyattr;
};

/* Values in idp_flags field */
/* IDP present */
# define IDP_PRESENT     0x1
/* IDP values inconsistent */
# define IDP_INVALID     0x2
/* onlyuser true */
# define IDP_ONLYUSER    0x4
/* onlyCA true */
# define IDP_ONLYCA      0x8
/* onlyattr true */
# define IDP_ONLYATTR    0x10
/* indirectCRL true */
# define IDP_INDIRECT    0x20
/* onlysomereasons present */
# define IDP_REASONS     0x40

# define X509V3_conf_err(val) ERR_add_error_data(6, \
                        "section:", (val)->section, \
                        ",name:", (val)->name, ",value:", (val)->value)

# define X509V3_set_ctx_test(ctx) \
    X509V3_set_ctx(ctx, NULL, NULL, NULL, NULL, X509V3_CTX_TEST)
# define X509V3_set_ctx_nodb(ctx) (ctx)->db = NULL;

# define EXT_BITSTRING(nid, table) { nid, 0, ASN1_ITEM_ref(ASN1_BIT_STRING), \
                        0,0,0,0, \
                        0,0, \
                        (X509V3_EXT_I2V)i2v_ASN1_BIT_STRING, \
                        (X509V3_EXT_V2I)v2i_ASN1_BIT_STRING, \
                        NULL, NULL, \
                        table}

# define EXT_IA5STRING(nid) { nid, 0, ASN1_ITEM_ref(ASN1_IA5STRING), \
                        0,0,0,0, \
                        (X509V3_EXT_I2S)i2s_ASN1_IA5STRING, \
                        (X509V3_EXT_S2I)s2i_ASN1_IA5STRING, \
                        0,0,0,0, \
                        NULL}

#define EXT_UTF8STRING(nid) { nid, 0, ASN1_ITEM_ref(ASN1_UTF8STRING), \
                        0,0,0,0, \
                        (X509V3_EXT_I2S)i2s_ASN1_UTF8STRING, \
                        (X509V3_EXT_S2I)s2i_ASN1_UTF8STRING, \
                        0,0,0,0, \
                        NULL}

# define EXT_END { -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

/* X509_PURPOSE stuff */

# define EXFLAG_BCONS            0x1
# define EXFLAG_KUSAGE           0x2
# define EXFLAG_XKUSAGE          0x4
# define EXFLAG_NSCERT           0x8

# define EXFLAG_CA               0x10
# define EXFLAG_SI               0x20 /* self-issued, maybe not self-signed */
# define EXFLAG_V1               0x40
# define EXFLAG_INVALID          0x80
/* EXFLAG_SET is set to indicate that some values have been precomputed */
# define EXFLAG_SET              0x100
# define EXFLAG_CRITICAL         0x200
# define EXFLAG_PROXY            0x400

# define EXFLAG_INVALID_POLICY   0x800
# define EXFLAG_FRESHEST         0x1000
# define EXFLAG_SS               0x2000 /* cert is apparently self-signed */

# define EXFLAG_BCONS_CRITICAL   0x10000
# define EXFLAG_AKID_CRITICAL    0x20000
# define EXFLAG_SKID_CRITICAL    0x40000
# define EXFLAG_SAN_CRITICAL     0x80000
# define EXFLAG_NO_FINGERPRINT   0x100000

/* https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3 */
# define KU_DIGITAL_SIGNATURE    X509v3_KU_DIGITAL_SIGNATURE
# define KU_NON_REPUDIATION      X509v3_KU_NON_REPUDIATION
# define KU_KEY_ENCIPHERMENT     X509v3_KU_KEY_ENCIPHERMENT
# define KU_DATA_ENCIPHERMENT    X509v3_KU_DATA_ENCIPHERMENT
# define KU_KEY_AGREEMENT        X509v3_KU_KEY_AGREEMENT
# define KU_KEY_CERT_SIGN        X509v3_KU_KEY_CERT_SIGN
# define KU_CRL_SIGN             X509v3_KU_CRL_SIGN
# define KU_ENCIPHER_ONLY        X509v3_KU_ENCIPHER_ONLY
# define KU_DECIPHER_ONLY        X509v3_KU_DECIPHER_ONLY

# define NS_SSL_CLIENT           0x80
# define NS_SSL_SERVER           0x40
# define NS_SMIME                0x20
# define NS_OBJSIGN              0x10
# define NS_SSL_CA               0x04
# define NS_SMIME_CA             0x02
# define NS_OBJSIGN_CA           0x01
# define NS_ANY_CA               (NS_SSL_CA|NS_SMIME_CA|NS_OBJSIGN_CA)

# define XKU_SSL_SERVER          0x1
# define XKU_SSL_CLIENT          0x2
# define XKU_SMIME               0x4
# define XKU_CODE_SIGN           0x8
# define XKU_SGC                 0x10 /* Netscape or MS Server-Gated Crypto */
# define XKU_OCSP_SIGN           0x20
# define XKU_TIMESTAMP           0x40
# define XKU_DVCS                0x80
# define XKU_ANYEKU              0x100

# define X509_PURPOSE_DYNAMIC    0x1
# define X509_PURPOSE_DYNAMIC_NAME       0x2

typedef struct x509_purpose_st {
    int purpose;
    int trust;                  /* Default trust ID */
    int flags;
    int (*check_purpose) (const struct x509_purpose_st *, const X509 *, int);
    char *name;
    char *sname;
    void *usr_data;
} X509_PURPOSE;

SKM_DEFINE_STACK_OF_INTERNAL(X509_PURPOSE, X509_PURPOSE, X509_PURPOSE)
#define sk_X509_PURPOSE_num(sk) OPENSSL_sk_num(ossl_check_const_X509_PURPOSE_sk_type(sk))
#define sk_X509_PURPOSE_value(sk, idx) ((X509_PURPOSE *)OPENSSL_sk_value(ossl_check_const_X509_PURPOSE_sk_type(sk), (idx)))
#define sk_X509_PURPOSE_new(cmp) ((STACK_OF(X509_PURPOSE) *)OPENSSL_sk_new(ossl_check_X509_PURPOSE_compfunc_type(cmp)))
#define sk_X509_PURPOSE_new_null() ((STACK_OF(X509_PURPOSE) *)OPENSSL_sk_new_null())
#define sk_X509_PURPOSE_new_reserve(cmp, n) ((STACK_OF(X509_PURPOSE) *)OPENSSL_sk_new_reserve(ossl_check_X509_PURPOSE_compfunc_type(cmp), (n)))
#define sk_X509_PURPOSE_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_PURPOSE_sk_type(sk), (n))
#define sk_X509_PURPOSE_free(sk) OPENSSL_sk_free(ossl_check_X509_PURPOSE_sk_type(sk))
#define sk_X509_PURPOSE_zero(sk) OPENSSL_sk_zero(ossl_check_X509_PURPOSE_sk_type(sk))
#define sk_X509_PURPOSE_delete(sk, i) ((X509_PURPOSE *)OPENSSL_sk_delete(ossl_check_X509_PURPOSE_sk_type(sk), (i)))
#define sk_X509_PURPOSE_delete_ptr(sk, ptr) ((X509_PURPOSE *)OPENSSL_sk_delete_ptr(ossl_check_X509_PURPOSE_sk_type(sk), ossl_check_X509_PURPOSE_type(ptr)))
#define sk_X509_PURPOSE_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_PURPOSE_sk_type(sk), ossl_check_X509_PURPOSE_type(ptr))
#define sk_X509_PURPOSE_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_PURPOSE_sk_type(sk), ossl_check_X509_PURPOSE_type(ptr))
#define sk_X509_PURPOSE_pop(sk) ((X509_PURPOSE *)OPENSSL_sk_pop(ossl_check_X509_PURPOSE_sk_type(sk)))
#define sk_X509_PURPOSE_shift(sk) ((X509_PURPOSE *)OPENSSL_sk_shift(ossl_check_X509_PURPOSE_sk_type(sk)))
#define sk_X509_PURPOSE_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_PURPOSE_sk_type(sk),ossl_check_X509_PURPOSE_freefunc_type(freefunc))
#define sk_X509_PURPOSE_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_PURPOSE_sk_type(sk), ossl_check_X509_PURPOSE_type(ptr), (idx))
#define sk_X509_PURPOSE_set(sk, idx, ptr) ((X509_PURPOSE *)OPENSSL_sk_set(ossl_check_X509_PURPOSE_sk_type(sk), (idx), ossl_check_X509_PURPOSE_type(ptr)))
#define sk_X509_PURPOSE_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_PURPOSE_sk_type(sk), ossl_check_X509_PURPOSE_type(ptr))
#define sk_X509_PURPOSE_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_PURPOSE_sk_type(sk), ossl_check_X509_PURPOSE_type(ptr))
#define sk_X509_PURPOSE_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_PURPOSE_sk_type(sk), ossl_check_X509_PURPOSE_type(ptr), pnum)
#define sk_X509_PURPOSE_sort(sk) OPENSSL_sk_sort(ossl_check_X509_PURPOSE_sk_type(sk))
#define sk_X509_PURPOSE_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_PURPOSE_sk_type(sk))
#define sk_X509_PURPOSE_dup(sk) ((STACK_OF(X509_PURPOSE) *)OPENSSL_sk_dup(ossl_check_const_X509_PURPOSE_sk_type(sk)))
#define sk_X509_PURPOSE_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_PURPOSE) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_PURPOSE_sk_type(sk), ossl_check_X509_PURPOSE_copyfunc_type(copyfunc), ossl_check_X509_PURPOSE_freefunc_type(freefunc)))
#define sk_X509_PURPOSE_set_cmp_func(sk, cmp) ((sk_X509_PURPOSE_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_PURPOSE_sk_type(sk), ossl_check_X509_PURPOSE_compfunc_type(cmp)))



# define X509_PURPOSE_SSL_CLIENT         1
# define X509_PURPOSE_SSL_SERVER         2
# define X509_PURPOSE_NS_SSL_SERVER      3
# define X509_PURPOSE_SMIME_SIGN         4
# define X509_PURPOSE_SMIME_ENCRYPT      5
# define X509_PURPOSE_CRL_SIGN           6
# define X509_PURPOSE_ANY                7
# define X509_PURPOSE_OCSP_HELPER        8
# define X509_PURPOSE_TIMESTAMP_SIGN     9
# define X509_PURPOSE_CODE_SIGN         10

# define X509_PURPOSE_MIN                1
# define X509_PURPOSE_MAX               10

/* Flags for X509V3_EXT_print() */

# define X509V3_EXT_UNKNOWN_MASK         (0xfL << 16)
/* Return error for unknown extensions */
# define X509V3_EXT_DEFAULT              0
/* Print error for unknown extensions */
# define X509V3_EXT_ERROR_UNKNOWN        (1L << 16)
/* ASN1 parse unknown extensions */
# define X509V3_EXT_PARSE_UNKNOWN        (2L << 16)
/* BIO_dump unknown extensions */
# define X509V3_EXT_DUMP_UNKNOWN         (3L << 16)

/* Flags for X509V3_add1_i2d */

# define X509V3_ADD_OP_MASK              0xfL
# define X509V3_ADD_DEFAULT              0L
# define X509V3_ADD_APPEND               1L
# define X509V3_ADD_REPLACE              2L
# define X509V3_ADD_REPLACE_EXISTING     3L
# define X509V3_ADD_KEEP_EXISTING        4L
# define X509V3_ADD_DELETE               5L
# define X509V3_ADD_SILENT               0x10

DECLARE_ASN1_FUNCTIONS(BASIC_CONSTRAINTS)

DECLARE_ASN1_FUNCTIONS(SXNET)
DECLARE_ASN1_FUNCTIONS(SXNETID)

DECLARE_ASN1_FUNCTIONS(ISSUER_SIGN_TOOL)

int SXNET_add_id_asc(SXNET **psx, const char *zone, const char *user, int userlen);
int SXNET_add_id_ulong(SXNET **psx, unsigned long lzone, const char *user,
                       int userlen);
int SXNET_add_id_INTEGER(SXNET **psx, ASN1_INTEGER *izone, const char *user,
                         int userlen);

ASN1_OCTET_STRING *SXNET_get_id_asc(SXNET *sx, const char *zone);
ASN1_OCTET_STRING *SXNET_get_id_ulong(SXNET *sx, unsigned long lzone);
ASN1_OCTET_STRING *SXNET_get_id_INTEGER(SXNET *sx, ASN1_INTEGER *zone);

DECLARE_ASN1_FUNCTIONS(AUTHORITY_KEYID)

DECLARE_ASN1_FUNCTIONS(PKEY_USAGE_PERIOD)

DECLARE_ASN1_FUNCTIONS(GENERAL_NAME)
DECLARE_ASN1_DUP_FUNCTION(GENERAL_NAME)
int GENERAL_NAME_cmp(GENERAL_NAME *a, GENERAL_NAME *b);

ASN1_BIT_STRING *v2i_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,
                                     X509V3_CTX *ctx,
                                     STACK_OF(CONF_VALUE) *nval);
STACK_OF(CONF_VALUE) *i2v_ASN1_BIT_STRING(X509V3_EXT_METHOD *method,
                                          ASN1_BIT_STRING *bits,
                                          STACK_OF(CONF_VALUE) *extlist);
char *i2s_ASN1_IA5STRING(X509V3_EXT_METHOD *method, ASN1_IA5STRING *ia5);
ASN1_IA5STRING *s2i_ASN1_IA5STRING(X509V3_EXT_METHOD *method,
                                   X509V3_CTX *ctx, const char *str);
char *i2s_ASN1_UTF8STRING(X509V3_EXT_METHOD *method, ASN1_UTF8STRING *utf8);
ASN1_UTF8STRING *s2i_ASN1_UTF8STRING(X509V3_EXT_METHOD *method,
                                   X509V3_CTX *ctx, const char *str);

STACK_OF(CONF_VALUE) *i2v_GENERAL_NAME(X509V3_EXT_METHOD *method,
                                       GENERAL_NAME *gen,
                                       STACK_OF(CONF_VALUE) *ret);
int GENERAL_NAME_print(BIO *out, GENERAL_NAME *gen);

DECLARE_ASN1_FUNCTIONS(GENERAL_NAMES)

STACK_OF(CONF_VALUE) *i2v_GENERAL_NAMES(X509V3_EXT_METHOD *method,
                                        GENERAL_NAMES *gen,
                                        STACK_OF(CONF_VALUE) *extlist);
GENERAL_NAMES *v2i_GENERAL_NAMES(const X509V3_EXT_METHOD *method,
                                 X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *nval);

DECLARE_ASN1_FUNCTIONS(OTHERNAME)
DECLARE_ASN1_FUNCTIONS(EDIPARTYNAME)
int OTHERNAME_cmp(OTHERNAME *a, OTHERNAME *b);
void GENERAL_NAME_set0_value(GENERAL_NAME *a, int type, void *value);
void *GENERAL_NAME_get0_value(const GENERAL_NAME *a, int *ptype);
int GENERAL_NAME_set0_othername(GENERAL_NAME *gen,
                                ASN1_OBJECT *oid, ASN1_TYPE *value);
int GENERAL_NAME_get0_otherName(const GENERAL_NAME *gen,
                                ASN1_OBJECT **poid, ASN1_TYPE **pvalue);

char *i2s_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method,
                            const ASN1_OCTET_STRING *ia5);
ASN1_OCTET_STRING *s2i_ASN1_OCTET_STRING(X509V3_EXT_METHOD *method,
                                         X509V3_CTX *ctx, const char *str);

DECLARE_ASN1_FUNCTIONS(EXTENDED_KEY_USAGE)
int i2a_ACCESS_DESCRIPTION(BIO *bp, const ACCESS_DESCRIPTION *a);

DECLARE_ASN1_ALLOC_FUNCTIONS(TLS_FEATURE)

DECLARE_ASN1_FUNCTIONS(CERTIFICATEPOLICIES)
DECLARE_ASN1_FUNCTIONS(POLICYINFO)
DECLARE_ASN1_FUNCTIONS(POLICYQUALINFO)
DECLARE_ASN1_FUNCTIONS(USERNOTICE)
DECLARE_ASN1_FUNCTIONS(NOTICEREF)

DECLARE_ASN1_FUNCTIONS(CRL_DIST_POINTS)
DECLARE_ASN1_FUNCTIONS(DIST_POINT)
DECLARE_ASN1_FUNCTIONS(DIST_POINT_NAME)
DECLARE_ASN1_FUNCTIONS(ISSUING_DIST_POINT)

int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, const X509_NAME *iname);

int NAME_CONSTRAINTS_check(X509 *x, NAME_CONSTRAINTS *nc);
int NAME_CONSTRAINTS_check_CN(X509 *x, NAME_CONSTRAINTS *nc);

DECLARE_ASN1_FUNCTIONS(ACCESS_DESCRIPTION)
DECLARE_ASN1_FUNCTIONS(AUTHORITY_INFO_ACCESS)

DECLARE_ASN1_ITEM(POLICY_MAPPING)
DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_MAPPING)
DECLARE_ASN1_ITEM(POLICY_MAPPINGS)

DECLARE_ASN1_ITEM(GENERAL_SUBTREE)
DECLARE_ASN1_ALLOC_FUNCTIONS(GENERAL_SUBTREE)

DECLARE_ASN1_ITEM(NAME_CONSTRAINTS)
DECLARE_ASN1_ALLOC_FUNCTIONS(NAME_CONSTRAINTS)

DECLARE_ASN1_ALLOC_FUNCTIONS(POLICY_CONSTRAINTS)
DECLARE_ASN1_ITEM(POLICY_CONSTRAINTS)

GENERAL_NAME *a2i_GENERAL_NAME(GENERAL_NAME *out,
                               const X509V3_EXT_METHOD *method,
                               X509V3_CTX *ctx, int gen_type,
                               const char *value, int is_nc);

# ifdef OPENSSL_CONF_H
GENERAL_NAME *v2i_GENERAL_NAME(const X509V3_EXT_METHOD *method,
                               X509V3_CTX *ctx, CONF_VALUE *cnf);
GENERAL_NAME *v2i_GENERAL_NAME_ex(GENERAL_NAME *out,
                                  const X509V3_EXT_METHOD *method,
                                  X509V3_CTX *ctx, CONF_VALUE *cnf,
                                  int is_nc);

void X509V3_conf_free(CONF_VALUE *val);

X509_EXTENSION *X509V3_EXT_nconf_nid(CONF *conf, X509V3_CTX *ctx, int ext_nid,
                                     const char *value);
X509_EXTENSION *X509V3_EXT_nconf(CONF *conf, X509V3_CTX *ctx, const char *name,
                                 const char *value);
int X509V3_EXT_add_nconf_sk(CONF *conf, X509V3_CTX *ctx, const char *section,
                            STACK_OF(X509_EXTENSION) **sk);
int X509V3_EXT_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section,
                         X509 *cert);
int X509V3_EXT_REQ_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section,
                             X509_REQ *req);
int X509V3_EXT_CRL_add_nconf(CONF *conf, X509V3_CTX *ctx, const char *section,
                             X509_CRL *crl);

X509_EXTENSION *X509V3_EXT_conf_nid(LHASH_OF(CONF_VALUE) *conf,
                                    X509V3_CTX *ctx, int ext_nid,
                                    const char *value);
X509_EXTENSION *X509V3_EXT_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
                                const char *name, const char *value);
int X509V3_EXT_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
                        const char *section, X509 *cert);
int X509V3_EXT_REQ_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
                            const char *section, X509_REQ *req);
int X509V3_EXT_CRL_add_conf(LHASH_OF(CONF_VALUE) *conf, X509V3_CTX *ctx,
                            const char *section, X509_CRL *crl);

int X509V3_add_value_bool_nf(const char *name, int asn1_bool,
                             STACK_OF(CONF_VALUE) **extlist);
int X509V3_get_value_bool(const CONF_VALUE *value, int *asn1_bool);
int X509V3_get_value_int(const CONF_VALUE *value, ASN1_INTEGER **aint);
void X509V3_set_nconf(X509V3_CTX *ctx, CONF *conf);
void X509V3_set_conf_lhash(X509V3_CTX *ctx, LHASH_OF(CONF_VALUE) *lhash);
# endif

char *X509V3_get_string(X509V3_CTX *ctx, const char *name, const char *section);
STACK_OF(CONF_VALUE) *X509V3_get_section(X509V3_CTX *ctx, const char *section);
void X509V3_string_free(X509V3_CTX *ctx, char *str);
void X509V3_section_free(X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *section);
void X509V3_set_ctx(X509V3_CTX *ctx, X509 *issuer, X509 *subject,
                    X509_REQ *req, X509_CRL *crl, int flags);
/* For API backward compatibility, this is separate from X509V3_set_ctx(): */
int X509V3_set_issuer_pkey(X509V3_CTX *ctx, EVP_PKEY *pkey);

int X509V3_add_value(const char *name, const char *value,
                     STACK_OF(CONF_VALUE) **extlist);
int X509V3_add_value_uchar(const char *name, const unsigned char *value,
                           STACK_OF(CONF_VALUE) **extlist);
int X509V3_add_value_bool(const char *name, int asn1_bool,
                          STACK_OF(CONF_VALUE) **extlist);
int X509V3_add_value_int(const char *name, const ASN1_INTEGER *aint,
                         STACK_OF(CONF_VALUE) **extlist);
char *i2s_ASN1_INTEGER(X509V3_EXT_METHOD *meth, const ASN1_INTEGER *aint);
ASN1_INTEGER *s2i_ASN1_INTEGER(X509V3_EXT_METHOD *meth, const char *value);
char *i2s_ASN1_ENUMERATED(X509V3_EXT_METHOD *meth, const ASN1_ENUMERATED *aint);
char *i2s_ASN1_ENUMERATED_TABLE(X509V3_EXT_METHOD *meth,
                                const ASN1_ENUMERATED *aint);
int X509V3_EXT_add(X509V3_EXT_METHOD *ext);
int X509V3_EXT_add_list(X509V3_EXT_METHOD *extlist);
int X509V3_EXT_add_alias(int nid_to, int nid_from);
void X509V3_EXT_cleanup(void);

const X509V3_EXT_METHOD *X509V3_EXT_get(X509_EXTENSION *ext);
const X509V3_EXT_METHOD *X509V3_EXT_get_nid(int nid);
int X509V3_add_standard_extensions(void);
STACK_OF(CONF_VALUE) *X509V3_parse_list(const char *line);
void *X509V3_EXT_d2i(X509_EXTENSION *ext);
void *X509V3_get_d2i(const STACK_OF(X509_EXTENSION) *x, int nid, int *crit,
                     int *idx);

X509_EXTENSION *X509V3_EXT_i2d(int ext_nid, int crit, void *ext_struc);
int X509V3_add1_i2d(STACK_OF(X509_EXTENSION) **x, int nid, void *value,
                    int crit, unsigned long flags);

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
/* The new declarations are in crypto.h, but the old ones were here. */
# define hex_to_string OPENSSL_buf2hexstr
# define string_to_hex OPENSSL_hexstr2buf
#endif

void X509V3_EXT_val_prn(BIO *out, STACK_OF(CONF_VALUE) *val, int indent,
                        int ml);
int X509V3_EXT_print(BIO *out, X509_EXTENSION *ext, unsigned long flag,
                     int indent);
#ifndef OPENSSL_NO_STDIO
int X509V3_EXT_print_fp(FILE *out, X509_EXTENSION *ext, int flag, int indent);
#endif
int X509V3_extensions_print(BIO *out, const char *title,
                            const STACK_OF(X509_EXTENSION) *exts,
                            unsigned long flag, int indent);

int X509_check_ca(X509 *x);
int X509_check_purpose(X509 *x, int id, int ca);
int X509_supported_extension(X509_EXTENSION *ex);
int X509_PURPOSE_set(int *p, int purpose);
int X509_check_issued(X509 *issuer, X509 *subject);
int X509_check_akid(const X509 *issuer, const AUTHORITY_KEYID *akid);
void X509_set_proxy_flag(X509 *x);
void X509_set_proxy_pathlen(X509 *x, long l);
long X509_get_proxy_pathlen(X509 *x);

uint32_t X509_get_extension_flags(X509 *x);
uint32_t X509_get_key_usage(X509 *x);
uint32_t X509_get_extended_key_usage(X509 *x);
const ASN1_OCTET_STRING *X509_get0_subject_key_id(X509 *x);
const ASN1_OCTET_STRING *X509_get0_authority_key_id(X509 *x);
const GENERAL_NAMES *X509_get0_authority_issuer(X509 *x);
const ASN1_INTEGER *X509_get0_authority_serial(X509 *x);

int X509_PURPOSE_get_count(void);
X509_PURPOSE *X509_PURPOSE_get0(int idx);
int X509_PURPOSE_get_by_sname(const char *sname);
int X509_PURPOSE_get_by_id(int id);
int X509_PURPOSE_add(int id, int trust, int flags,
                     int (*ck) (const X509_PURPOSE *, const X509 *, int),
                     const char *name, const char *sname, void *arg);
char *X509_PURPOSE_get0_name(const X509_PURPOSE *xp);
char *X509_PURPOSE_get0_sname(const X509_PURPOSE *xp);
int X509_PURPOSE_get_trust(const X509_PURPOSE *xp);
void X509_PURPOSE_cleanup(void);
int X509_PURPOSE_get_id(const X509_PURPOSE *);

STACK_OF(OPENSSL_STRING) *X509_get1_email(X509 *x);
STACK_OF(OPENSSL_STRING) *X509_REQ_get1_email(X509_REQ *x);
void X509_email_free(STACK_OF(OPENSSL_STRING) *sk);
STACK_OF(OPENSSL_STRING) *X509_get1_ocsp(X509 *x);
/* Flags for X509_check_* functions */

/*
 * Always check subject name for host match even if subject alt names present
 */
# define X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT    0x1
/* Disable wildcard matching for dnsName fields and common name. */
# define X509_CHECK_FLAG_NO_WILDCARDS    0x2
/* Wildcards must not match a partial label. */
# define X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS 0x4
/* Allow (non-partial) wildcards to match multiple labels. */
# define X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS 0x8
/* Constraint verifier subdomain patterns to match a single labels. */
# define X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS 0x10
/* Never check the subject CN */
# define X509_CHECK_FLAG_NEVER_CHECK_SUBJECT    0x20
/*
 * Match reference identifiers starting with "." to any sub-domain.
 * This is a non-public flag, turned on implicitly when the subject
 * reference identity is a DNS name.
 */
# define _X509_CHECK_FLAG_DOT_SUBDOMAINS 0x8000

int X509_check_host(X509 *x, const char *chk, size_t chklen,
                    unsigned int flags, char **peername);
int X509_check_email(X509 *x, const char *chk, size_t chklen,
                     unsigned int flags);
int X509_check_ip(X509 *x, const unsigned char *chk, size_t chklen,
                  unsigned int flags);
int X509_check_ip_asc(X509 *x, const char *ipasc, unsigned int flags);

ASN1_OCTET_STRING *a2i_IPADDRESS(const char *ipasc);
ASN1_OCTET_STRING *a2i_IPADDRESS_NC(const char *ipasc);
int X509V3_NAME_from_section(X509_NAME *nm, STACK_OF(CONF_VALUE) *dn_sk,
                             unsigned long chtype);

void X509_POLICY_NODE_print(BIO *out, X509_POLICY_NODE *node, int indent);
SKM_DEFINE_STACK_OF_INTERNAL(X509_POLICY_NODE, X509_POLICY_NODE, X509_POLICY_NODE)
#define sk_X509_POLICY_NODE_num(sk) OPENSSL_sk_num(ossl_check_const_X509_POLICY_NODE_sk_type(sk))
#define sk_X509_POLICY_NODE_value(sk, idx) ((X509_POLICY_NODE *)OPENSSL_sk_value(ossl_check_const_X509_POLICY_NODE_sk_type(sk), (idx)))
#define sk_X509_POLICY_NODE_new(cmp) ((STACK_OF(X509_POLICY_NODE) *)OPENSSL_sk_new(ossl_check_X509_POLICY_NODE_compfunc_type(cmp)))
#define sk_X509_POLICY_NODE_new_null() ((STACK_OF(X509_POLICY_NODE) *)OPENSSL_sk_new_null())
#define sk_X509_POLICY_NODE_new_reserve(cmp, n) ((STACK_OF(X509_POLICY_NODE) *)OPENSSL_sk_new_reserve(ossl_check_X509_POLICY_NODE_compfunc_type(cmp), (n)))
#define sk_X509_POLICY_NODE_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_POLICY_NODE_sk_type(sk), (n))
#define sk_X509_POLICY_NODE_free(sk) OPENSSL_sk_free(ossl_check_X509_POLICY_NODE_sk_type(sk))
#define sk_X509_POLICY_NODE_zero(sk) OPENSSL_sk_zero(ossl_check_X509_POLICY_NODE_sk_type(sk))
#define sk_X509_POLICY_NODE_delete(sk, i) ((X509_POLICY_NODE *)OPENSSL_sk_delete(ossl_check_X509_POLICY_NODE_sk_type(sk), (i)))
#define sk_X509_POLICY_NODE_delete_ptr(sk, ptr) ((X509_POLICY_NODE *)OPENSSL_sk_delete_ptr(ossl_check_X509_POLICY_NODE_sk_type(sk), ossl_check_X509_POLICY_NODE_type(ptr)))
#define sk_X509_POLICY_NODE_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_POLICY_NODE_sk_type(sk), ossl_check_X509_POLICY_NODE_type(ptr))
#define sk_X509_POLICY_NODE_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_POLICY_NODE_sk_type(sk), ossl_check_X509_POLICY_NODE_type(ptr))
#define sk_X509_POLICY_NODE_pop(sk) ((X509_POLICY_NODE *)OPENSSL_sk_pop(ossl_check_X509_POLICY_NODE_sk_type(sk)))
#define sk_X509_POLICY_NODE_shift(sk) ((X509_POLICY_NODE *)OPENSSL_sk_shift(ossl_check_X509_POLICY_NODE_sk_type(sk)))
#define sk_X509_POLICY_NODE_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_POLICY_NODE_sk_type(sk),ossl_check_X509_POLICY_NODE_freefunc_type(freefunc))
#define sk_X509_POLICY_NODE_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_POLICY_NODE_sk_type(sk), ossl_check_X509_POLICY_NODE_type(ptr), (idx))
#define sk_X509_POLICY_NODE_set(sk, idx, ptr) ((X509_POLICY_NODE *)OPENSSL_sk_set(ossl_check_X509_POLICY_NODE_sk_type(sk), (idx), ossl_check_X509_POLICY_NODE_type(ptr)))
#define sk_X509_POLICY_NODE_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_POLICY_NODE_sk_type(sk), ossl_check_X509_POLICY_NODE_type(ptr))
#define sk_X509_POLICY_NODE_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_POLICY_NODE_sk_type(sk), ossl_check_X509_POLICY_NODE_type(ptr))
#define sk_X509_POLICY_NODE_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_POLICY_NODE_sk_type(sk), ossl_check_X509_POLICY_NODE_type(ptr), pnum)
#define sk_X509_POLICY_NODE_sort(sk) OPENSSL_sk_sort(ossl_check_X509_POLICY_NODE_sk_type(sk))
#define sk_X509_POLICY_NODE_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_POLICY_NODE_sk_type(sk))
#define sk_X509_POLICY_NODE_dup(sk) ((STACK_OF(X509_POLICY_NODE) *)OPENSSL_sk_dup(ossl_check_const_X509_POLICY_NODE_sk_type(sk)))
#define sk_X509_POLICY_NODE_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_POLICY_NODE) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_POLICY_NODE_sk_type(sk), ossl_check_X509_POLICY_NODE_copyfunc_type(copyfunc), ossl_check_X509_POLICY_NODE_freefunc_type(freefunc)))
#define sk_X509_POLICY_NODE_set_cmp_func(sk, cmp) ((sk_X509_POLICY_NODE_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_POLICY_NODE_sk_type(sk), ossl_check_X509_POLICY_NODE_compfunc_type(cmp)))



#ifndef OPENSSL_NO_RFC3779
typedef struct ASRange_st {
    ASN1_INTEGER *min, *max;
} ASRange;

# define ASIdOrRange_id          0
# define ASIdOrRange_range       1

typedef struct ASIdOrRange_st {
    int type;
    union {
        ASN1_INTEGER *id;
        ASRange *range;
    } u;
} ASIdOrRange;

SKM_DEFINE_STACK_OF_INTERNAL(ASIdOrRange, ASIdOrRange, ASIdOrRange)
#define sk_ASIdOrRange_num(sk) OPENSSL_sk_num(ossl_check_const_ASIdOrRange_sk_type(sk))
#define sk_ASIdOrRange_value(sk, idx) ((ASIdOrRange *)OPENSSL_sk_value(ossl_check_const_ASIdOrRange_sk_type(sk), (idx)))
#define sk_ASIdOrRange_new(cmp) ((STACK_OF(ASIdOrRange) *)OPENSSL_sk_new(ossl_check_ASIdOrRange_compfunc_type(cmp)))
#define sk_ASIdOrRange_new_null() ((STACK_OF(ASIdOrRange) *)OPENSSL_sk_new_null())
#define sk_ASIdOrRange_new_reserve(cmp, n) ((STACK_OF(ASIdOrRange) *)OPENSSL_sk_new_reserve(ossl_check_ASIdOrRange_compfunc_type(cmp), (n)))
#define sk_ASIdOrRange_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_ASIdOrRange_sk_type(sk), (n))
#define sk_ASIdOrRange_free(sk) OPENSSL_sk_free(ossl_check_ASIdOrRange_sk_type(sk))
#define sk_ASIdOrRange_zero(sk) OPENSSL_sk_zero(ossl_check_ASIdOrRange_sk_type(sk))
#define sk_ASIdOrRange_delete(sk, i) ((ASIdOrRange *)OPENSSL_sk_delete(ossl_check_ASIdOrRange_sk_type(sk), (i)))
#define sk_ASIdOrRange_delete_ptr(sk, ptr) ((ASIdOrRange *)OPENSSL_sk_delete_ptr(ossl_check_ASIdOrRange_sk_type(sk), ossl_check_ASIdOrRange_type(ptr)))
#define sk_ASIdOrRange_push(sk, ptr) OPENSSL_sk_push(ossl_check_ASIdOrRange_sk_type(sk), ossl_check_ASIdOrRange_type(ptr))
#define sk_ASIdOrRange_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_ASIdOrRange_sk_type(sk), ossl_check_ASIdOrRange_type(ptr))
#define sk_ASIdOrRange_pop(sk) ((ASIdOrRange *)OPENSSL_sk_pop(ossl_check_ASIdOrRange_sk_type(sk)))
#define sk_ASIdOrRange_shift(sk) ((ASIdOrRange *)OPENSSL_sk_shift(ossl_check_ASIdOrRange_sk_type(sk)))
#define sk_ASIdOrRange_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_ASIdOrRange_sk_type(sk),ossl_check_ASIdOrRange_freefunc_type(freefunc))
#define sk_ASIdOrRange_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_ASIdOrRange_sk_type(sk), ossl_check_ASIdOrRange_type(ptr), (idx))
#define sk_ASIdOrRange_set(sk, idx, ptr) ((ASIdOrRange *)OPENSSL_sk_set(ossl_check_ASIdOrRange_sk_type(sk), (idx), ossl_check_ASIdOrRange_type(ptr)))
#define sk_ASIdOrRange_find(sk, ptr) OPENSSL_sk_find(ossl_check_ASIdOrRange_sk_type(sk), ossl_check_ASIdOrRange_type(ptr))
#define sk_ASIdOrRange_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_ASIdOrRange_sk_type(sk), ossl_check_ASIdOrRange_type(ptr))
#define sk_ASIdOrRange_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_ASIdOrRange_sk_type(sk), ossl_check_ASIdOrRange_type(ptr), pnum)
#define sk_ASIdOrRange_sort(sk) OPENSSL_sk_sort(ossl_check_ASIdOrRange_sk_type(sk))
#define sk_ASIdOrRange_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_ASIdOrRange_sk_type(sk))
#define sk_ASIdOrRange_dup(sk) ((STACK_OF(ASIdOrRange) *)OPENSSL_sk_dup(ossl_check_const_ASIdOrRange_sk_type(sk)))
#define sk_ASIdOrRange_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(ASIdOrRange) *)OPENSSL_sk_deep_copy(ossl_check_const_ASIdOrRange_sk_type(sk), ossl_check_ASIdOrRange_copyfunc_type(copyfunc), ossl_check_ASIdOrRange_freefunc_type(freefunc)))
#define sk_ASIdOrRange_set_cmp_func(sk, cmp) ((sk_ASIdOrRange_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_ASIdOrRange_sk_type(sk), ossl_check_ASIdOrRange_compfunc_type(cmp)))


typedef STACK_OF(ASIdOrRange) ASIdOrRanges;

# define ASIdentifierChoice_inherit              0
# define ASIdentifierChoice_asIdsOrRanges        1

typedef struct ASIdentifierChoice_st {
    int type;
    union {
        ASN1_NULL *inherit;
        ASIdOrRanges *asIdsOrRanges;
    } u;
} ASIdentifierChoice;

typedef struct ASIdentifiers_st {
    ASIdentifierChoice *asnum, *rdi;
} ASIdentifiers;

DECLARE_ASN1_FUNCTIONS(ASRange)
DECLARE_ASN1_FUNCTIONS(ASIdOrRange)
DECLARE_ASN1_FUNCTIONS(ASIdentifierChoice)
DECLARE_ASN1_FUNCTIONS(ASIdentifiers)

typedef struct IPAddressRange_st {
    ASN1_BIT_STRING *min, *max;
} IPAddressRange;

# define IPAddressOrRange_addressPrefix  0
# define IPAddressOrRange_addressRange   1

typedef struct IPAddressOrRange_st {
    int type;
    union {
        ASN1_BIT_STRING *addressPrefix;
        IPAddressRange *addressRange;
    } u;
} IPAddressOrRange;

SKM_DEFINE_STACK_OF_INTERNAL(IPAddressOrRange, IPAddressOrRange, IPAddressOrRange)
#define sk_IPAddressOrRange_num(sk) OPENSSL_sk_num(ossl_check_const_IPAddressOrRange_sk_type(sk))
#define sk_IPAddressOrRange_value(sk, idx) ((IPAddressOrRange *)OPENSSL_sk_value(ossl_check_const_IPAddressOrRange_sk_type(sk), (idx)))
#define sk_IPAddressOrRange_new(cmp) ((STACK_OF(IPAddressOrRange) *)OPENSSL_sk_new(ossl_check_IPAddressOrRange_compfunc_type(cmp)))
#define sk_IPAddressOrRange_new_null() ((STACK_OF(IPAddressOrRange) *)OPENSSL_sk_new_null())
#define sk_IPAddressOrRange_new_reserve(cmp, n) ((STACK_OF(IPAddressOrRange) *)OPENSSL_sk_new_reserve(ossl_check_IPAddressOrRange_compfunc_type(cmp), (n)))
#define sk_IPAddressOrRange_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_IPAddressOrRange_sk_type(sk), (n))
#define sk_IPAddressOrRange_free(sk) OPENSSL_sk_free(ossl_check_IPAddressOrRange_sk_type(sk))
#define sk_IPAddressOrRange_zero(sk) OPENSSL_sk_zero(ossl_check_IPAddressOrRange_sk_type(sk))
#define sk_IPAddressOrRange_delete(sk, i) ((IPAddressOrRange *)OPENSSL_sk_delete(ossl_check_IPAddressOrRange_sk_type(sk), (i)))
#define sk_IPAddressOrRange_delete_ptr(sk, ptr) ((IPAddressOrRange *)OPENSSL_sk_delete_ptr(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr)))
#define sk_IPAddressOrRange_push(sk, ptr) OPENSSL_sk_push(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr))
#define sk_IPAddressOrRange_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr))
#define sk_IPAddressOrRange_pop(sk) ((IPAddressOrRange *)OPENSSL_sk_pop(ossl_check_IPAddressOrRange_sk_type(sk)))
#define sk_IPAddressOrRange_shift(sk) ((IPAddressOrRange *)OPENSSL_sk_shift(ossl_check_IPAddressOrRange_sk_type(sk)))
#define sk_IPAddressOrRange_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_IPAddressOrRange_sk_type(sk),ossl_check_IPAddressOrRange_freefunc_type(freefunc))
#define sk_IPAddressOrRange_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr), (idx))
#define sk_IPAddressOrRange_set(sk, idx, ptr) ((IPAddressOrRange *)OPENSSL_sk_set(ossl_check_IPAddressOrRange_sk_type(sk), (idx), ossl_check_IPAddressOrRange_type(ptr)))
#define sk_IPAddressOrRange_find(sk, ptr) OPENSSL_sk_find(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr))
#define sk_IPAddressOrRange_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr))
#define sk_IPAddressOrRange_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr), pnum)
#define sk_IPAddressOrRange_sort(sk) OPENSSL_sk_sort(ossl_check_IPAddressOrRange_sk_type(sk))
#define sk_IPAddressOrRange_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_IPAddressOrRange_sk_type(sk))
#define sk_IPAddressOrRange_dup(sk) ((STACK_OF(IPAddressOrRange) *)OPENSSL_sk_dup(ossl_check_const_IPAddressOrRange_sk_type(sk)))
#define sk_IPAddressOrRange_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(IPAddressOrRange) *)OPENSSL_sk_deep_copy(ossl_check_const_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_copyfunc_type(copyfunc), ossl_check_IPAddressOrRange_freefunc_type(freefunc)))
#define sk_IPAddressOrRange_set_cmp_func(sk, cmp) ((sk_IPAddressOrRange_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_compfunc_type(cmp)))


typedef STACK_OF(IPAddressOrRange) IPAddressOrRanges;

# define IPAddressChoice_inherit                 0
# define IPAddressChoice_addressesOrRanges       1

typedef struct IPAddressChoice_st {
    int type;
    union {
        ASN1_NULL *inherit;
        IPAddressOrRanges *addressesOrRanges;
    } u;
} IPAddressChoice;

typedef struct IPAddressFamily_st {
    ASN1_OCTET_STRING *addressFamily;
    IPAddressChoice *ipAddressChoice;
} IPAddressFamily;

SKM_DEFINE_STACK_OF_INTERNAL(IPAddressFamily, IPAddressFamily, IPAddressFamily)
#define sk_IPAddressFamily_num(sk) OPENSSL_sk_num(ossl_check_const_IPAddressFamily_sk_type(sk))
#define sk_IPAddressFamily_value(sk, idx) ((IPAddressFamily *)OPENSSL_sk_value(ossl_check_const_IPAddressFamily_sk_type(sk), (idx)))
#define sk_IPAddressFamily_new(cmp) ((STACK_OF(IPAddressFamily) *)OPENSSL_sk_new(ossl_check_IPAddressFamily_compfunc_type(cmp)))
#define sk_IPAddressFamily_new_null() ((STACK_OF(IPAddressFamily) *)OPENSSL_sk_new_null())
#define sk_IPAddressFamily_new_reserve(cmp, n) ((STACK_OF(IPAddressFamily) *)OPENSSL_sk_new_reserve(ossl_check_IPAddressFamily_compfunc_type(cmp), (n)))
#define sk_IPAddressFamily_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_IPAddressFamily_sk_type(sk), (n))
#define sk_IPAddressFamily_free(sk) OPENSSL_sk_free(ossl_check_IPAddressFamily_sk_type(sk))
#define sk_IPAddressFamily_zero(sk) OPENSSL_sk_zero(ossl_check_IPAddressFamily_sk_type(sk))
#define sk_IPAddressFamily_delete(sk, i) ((IPAddressFamily *)OPENSSL_sk_delete(ossl_check_IPAddressFamily_sk_type(sk), (i)))
#define sk_IPAddressFamily_delete_ptr(sk, ptr) ((IPAddressFamily *)OPENSSL_sk_delete_ptr(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr)))
#define sk_IPAddressFamily_push(sk, ptr) OPENSSL_sk_push(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr))
#define sk_IPAddressFamily_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr))
#define sk_IPAddressFamily_pop(sk) ((IPAddressFamily *)OPENSSL_sk_pop(ossl_check_IPAddressFamily_sk_type(sk)))
#define sk_IPAddressFamily_shift(sk) ((IPAddressFamily *)OPENSSL_sk_shift(ossl_check_IPAddressFamily_sk_type(sk)))
#define sk_IPAddressFamily_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_IPAddressFamily_sk_type(sk),ossl_check_IPAddressFamily_freefunc_type(freefunc))
#define sk_IPAddressFamily_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr), (idx))
#define sk_IPAddressFamily_set(sk, idx, ptr) ((IPAddressFamily *)OPENSSL_sk_set(ossl_check_IPAddressFamily_sk_type(sk), (idx), ossl_check_IPAddressFamily_type(ptr)))
#define sk_IPAddressFamily_find(sk, ptr) OPENSSL_sk_find(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr))
#define sk_IPAddressFamily_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr))
#define sk_IPAddressFamily_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr), pnum)
#define sk_IPAddressFamily_sort(sk) OPENSSL_sk_sort(ossl_check_IPAddressFamily_sk_type(sk))
#define sk_IPAddressFamily_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_IPAddressFamily_sk_type(sk))
#define sk_IPAddressFamily_dup(sk) ((STACK_OF(IPAddressFamily) *)OPENSSL_sk_dup(ossl_check_const_IPAddressFamily_sk_type(sk)))
#define sk_IPAddressFamily_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(IPAddressFamily) *)OPENSSL_sk_deep_copy(ossl_check_const_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_copyfunc_type(copyfunc), ossl_check_IPAddressFamily_freefunc_type(freefunc)))
#define sk_IPAddressFamily_set_cmp_func(sk, cmp) ((sk_IPAddressFamily_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_compfunc_type(cmp)))



typedef STACK_OF(IPAddressFamily) IPAddrBlocks;

DECLARE_ASN1_FUNCTIONS(IPAddressRange)
DECLARE_ASN1_FUNCTIONS(IPAddressOrRange)
DECLARE_ASN1_FUNCTIONS(IPAddressChoice)
DECLARE_ASN1_FUNCTIONS(IPAddressFamily)

/*
 * API tag for elements of the ASIdentifer SEQUENCE.
 */
# define V3_ASID_ASNUM   0
# define V3_ASID_RDI     1

/*
 * AFI values, assigned by IANA.  It'd be nice to make the AFI
 * handling code totally generic, but there are too many little things
 * that would need to be defined for other address families for it to
 * be worth the trouble.
 */
# define IANA_AFI_IPV4   1
# define IANA_AFI_IPV6   2

/*
 * Utilities to construct and extract values from RFC3779 extensions,
 * since some of the encodings (particularly for IP address prefixes
 * and ranges) are a bit tedious to work with directly.
 */
int X509v3_asid_add_inherit(ASIdentifiers *asid, int which);
int X509v3_asid_add_id_or_range(ASIdentifiers *asid, int which,
                                ASN1_INTEGER *min, ASN1_INTEGER *max);
int X509v3_addr_add_inherit(IPAddrBlocks *addr,
                            const unsigned afi, const unsigned *safi);
int X509v3_addr_add_prefix(IPAddrBlocks *addr,
                           const unsigned afi, const unsigned *safi,
                           unsigned char *a, const int prefixlen);
int X509v3_addr_add_range(IPAddrBlocks *addr,
                          const unsigned afi, const unsigned *safi,
                          unsigned char *min, unsigned char *max);
unsigned X509v3_addr_get_afi(const IPAddressFamily *f);
int X509v3_addr_get_range(IPAddressOrRange *aor, const unsigned afi,
                          unsigned char *min, unsigned char *max,
                          const int length);

/*
 * Canonical forms.
 */
int X509v3_asid_is_canonical(ASIdentifiers *asid);
int X509v3_addr_is_canonical(IPAddrBlocks *addr);
int X509v3_asid_canonize(ASIdentifiers *asid);
int X509v3_addr_canonize(IPAddrBlocks *addr);

/*
 * Tests for inheritance and containment.
 */
int X509v3_asid_inherits(ASIdentifiers *asid);
int X509v3_addr_inherits(IPAddrBlocks *addr);
int X509v3_asid_subset(ASIdentifiers *a, ASIdentifiers *b);
int X509v3_addr_subset(IPAddrBlocks *a, IPAddrBlocks *b);

/*
 * Check whether RFC 3779 extensions nest properly in chains.
 */
int X509v3_asid_validate_path(X509_STORE_CTX *);
int X509v3_addr_validate_path(X509_STORE_CTX *);
int X509v3_asid_validate_resource_set(STACK_OF(X509) *chain,
                                      ASIdentifiers *ext,
                                      int allow_inheritance);
int X509v3_addr_validate_resource_set(STACK_OF(X509) *chain,
                                      IPAddrBlocks *ext, int allow_inheritance);

#endif                         /* OPENSSL_NO_RFC3779 */

SKM_DEFINE_STACK_OF_INTERNAL(ASN1_STRING, ASN1_STRING, ASN1_STRING)
#define sk_ASN1_STRING_num(sk) OPENSSL_sk_num(ossl_check_const_ASN1_STRING_sk_type(sk))
#define sk_ASN1_STRING_value(sk, idx) ((ASN1_STRING *)OPENSSL_sk_value(ossl_check_const_ASN1_STRING_sk_type(sk), (idx)))
#define sk_ASN1_STRING_new(cmp) ((STACK_OF(ASN1_STRING) *)OPENSSL_sk_new(ossl_check_ASN1_STRING_compfunc_type(cmp)))
#define sk_ASN1_STRING_new_null() ((STACK_OF(ASN1_STRING) *)OPENSSL_sk_new_null())
#define sk_ASN1_STRING_new_reserve(cmp, n) ((STACK_OF(ASN1_STRING) *)OPENSSL_sk_new_reserve(ossl_check_ASN1_STRING_compfunc_type(cmp), (n)))
#define sk_ASN1_STRING_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_ASN1_STRING_sk_type(sk), (n))
#define sk_ASN1_STRING_free(sk) OPENSSL_sk_free(ossl_check_ASN1_STRING_sk_type(sk))
#define sk_ASN1_STRING_zero(sk) OPENSSL_sk_zero(ossl_check_ASN1_STRING_sk_type(sk))
#define sk_ASN1_STRING_delete(sk, i) ((ASN1_STRING *)OPENSSL_sk_delete(ossl_check_ASN1_STRING_sk_type(sk), (i)))
#define sk_ASN1_STRING_delete_ptr(sk, ptr) ((ASN1_STRING *)OPENSSL_sk_delete_ptr(ossl_check_ASN1_STRING_sk_type(sk), ossl_check_ASN1_STRING_type(ptr)))
#define sk_ASN1_STRING_push(sk, ptr) OPENSSL_sk_push(ossl_check_ASN1_STRING_sk_type(sk), ossl_check_ASN1_STRING_type(ptr))
#define sk_ASN1_STRING_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_ASN1_STRING_sk_type(sk), ossl_check_ASN1_STRING_type(ptr))
#define sk_ASN1_STRING_pop(sk) ((ASN1_STRING *)OPENSSL_sk_pop(ossl_check_ASN1_STRING_sk_type(sk)))
#define sk_ASN1_STRING_shift(sk) ((ASN1_STRING *)OPENSSL_sk_shift(ossl_check_ASN1_STRING_sk_type(sk)))
#define sk_ASN1_STRING_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_ASN1_STRING_sk_type(sk),ossl_check_ASN1_STRING_freefunc_type(freefunc))
#define sk_ASN1_STRING_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_ASN1_STRING_sk_type(sk), ossl_check_ASN1_STRING_type(ptr), (idx))
#define sk_ASN1_STRING_set(sk, idx, ptr) ((ASN1_STRING *)OPENSSL_sk_set(ossl_check_ASN1_STRING_sk_type(sk), (idx), ossl_check_ASN1_STRING_type(ptr)))
#define sk_ASN1_STRING_find(sk, ptr) OPENSSL_sk_find(ossl_check_ASN1_STRING_sk_type(sk), ossl_check_ASN1_STRING_type(ptr))
#define sk_ASN1_STRING_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_ASN1_STRING_sk_type(sk), ossl_check_ASN1_STRING_type(ptr))
#define sk_ASN1_STRING_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_ASN1_STRING_sk_type(sk), ossl_check_ASN1_STRING_type(ptr), pnum)
#define sk_ASN1_STRING_sort(sk) OPENSSL_sk_sort(ossl_check_ASN1_STRING_sk_type(sk))
#define sk_ASN1_STRING_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_ASN1_STRING_sk_type(sk))
#define sk_ASN1_STRING_dup(sk) ((STACK_OF(ASN1_STRING) *)OPENSSL_sk_dup(ossl_check_const_ASN1_STRING_sk_type(sk)))
#define sk_ASN1_STRING_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(ASN1_STRING) *)OPENSSL_sk_deep_copy(ossl_check_const_ASN1_STRING_sk_type(sk), ossl_check_ASN1_STRING_copyfunc_type(copyfunc), ossl_check_ASN1_STRING_freefunc_type(freefunc)))
#define sk_ASN1_STRING_set_cmp_func(sk, cmp) ((sk_ASN1_STRING_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_ASN1_STRING_sk_type(sk), ossl_check_ASN1_STRING_compfunc_type(cmp)))


/*
 * Admission Syntax
 */
typedef struct NamingAuthority_st NAMING_AUTHORITY;
typedef struct ProfessionInfo_st PROFESSION_INFO;
typedef struct Admissions_st ADMISSIONS;
typedef struct AdmissionSyntax_st ADMISSION_SYNTAX;
DECLARE_ASN1_FUNCTIONS(NAMING_AUTHORITY)
DECLARE_ASN1_FUNCTIONS(PROFESSION_INFO)
DECLARE_ASN1_FUNCTIONS(ADMISSIONS)
DECLARE_ASN1_FUNCTIONS(ADMISSION_SYNTAX)
SKM_DEFINE_STACK_OF_INTERNAL(PROFESSION_INFO, PROFESSION_INFO, PROFESSION_INFO)
#define sk_PROFESSION_INFO_num(sk) OPENSSL_sk_num(ossl_check_const_PROFESSION_INFO_sk_type(sk))
#define sk_PROFESSION_INFO_value(sk, idx) ((PROFESSION_INFO *)OPENSSL_sk_value(ossl_check_const_PROFESSION_INFO_sk_type(sk), (idx)))
#define sk_PROFESSION_INFO_new(cmp) ((STACK_OF(PROFESSION_INFO) *)OPENSSL_sk_new(ossl_check_PROFESSION_INFO_compfunc_type(cmp)))
#define sk_PROFESSION_INFO_new_null() ((STACK_OF(PROFESSION_INFO) *)OPENSSL_sk_new_null())
#define sk_PROFESSION_INFO_new_reserve(cmp, n) ((STACK_OF(PROFESSION_INFO) *)OPENSSL_sk_new_reserve(ossl_check_PROFESSION_INFO_compfunc_type(cmp), (n)))
#define sk_PROFESSION_INFO_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_PROFESSION_INFO_sk_type(sk), (n))
#define sk_PROFESSION_INFO_free(sk) OPENSSL_sk_free(ossl_check_PROFESSION_INFO_sk_type(sk))
#define sk_PROFESSION_INFO_zero(sk) OPENSSL_sk_zero(ossl_check_PROFESSION_INFO_sk_type(sk))
#define sk_PROFESSION_INFO_delete(sk, i) ((PROFESSION_INFO *)OPENSSL_sk_delete(ossl_check_PROFESSION_INFO_sk_type(sk), (i)))
#define sk_PROFESSION_INFO_delete_ptr(sk, ptr) ((PROFESSION_INFO *)OPENSSL_sk_delete_ptr(ossl_check_PROFESSION_INFO_sk_type(sk), ossl_check_PROFESSION_INFO_type(ptr)))
#define sk_PROFESSION_INFO_push(sk, ptr) OPENSSL_sk_push(ossl_check_PROFESSION_INFO_sk_type(sk), ossl_check_PROFESSION_INFO_type(ptr))
#define sk_PROFESSION_INFO_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_PROFESSION_INFO_sk_type(sk), ossl_check_PROFESSION_INFO_type(ptr))
#define sk_PROFESSION_INFO_pop(sk) ((PROFESSION_INFO *)OPENSSL_sk_pop(ossl_check_PROFESSION_INFO_sk_type(sk)))
#define sk_PROFESSION_INFO_shift(sk) ((PROFESSION_INFO *)OPENSSL_sk_shift(ossl_check_PROFESSION_INFO_sk_type(sk)))
#define sk_PROFESSION_INFO_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_PROFESSION_INFO_sk_type(sk),ossl_check_PROFESSION_INFO_freefunc_type(freefunc))
#define sk_PROFESSION_INFO_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_PROFESSION_INFO_sk_type(sk), ossl_check_PROFESSION_INFO_type(ptr), (idx))
#define sk_PROFESSION_INFO_set(sk, idx, ptr) ((PROFESSION_INFO *)OPENSSL_sk_set(ossl_check_PROFESSION_INFO_sk_type(sk), (idx), ossl_check_PROFESSION_INFO_type(ptr)))
#define sk_PROFESSION_INFO_find(sk, ptr) OPENSSL_sk_find(ossl_check_PROFESSION_INFO_sk_type(sk), ossl_check_PROFESSION_INFO_type(ptr))
#define sk_PROFESSION_INFO_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_PROFESSION_INFO_sk_type(sk), ossl_check_PROFESSION_INFO_type(ptr))
#define sk_PROFESSION_INFO_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_PROFESSION_INFO_sk_type(sk), ossl_check_PROFESSION_INFO_type(ptr), pnum)
#define sk_PROFESSION_INFO_sort(sk) OPENSSL_sk_sort(ossl_check_PROFESSION_INFO_sk_type(sk))
#define sk_PROFESSION_INFO_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_PROFESSION_INFO_sk_type(sk))
#define sk_PROFESSION_INFO_dup(sk) ((STACK_OF(PROFESSION_INFO) *)OPENSSL_sk_dup(ossl_check_const_PROFESSION_INFO_sk_type(sk)))
#define sk_PROFESSION_INFO_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(PROFESSION_INFO) *)OPENSSL_sk_deep_copy(ossl_check_const_PROFESSION_INFO_sk_type(sk), ossl_check_PROFESSION_INFO_copyfunc_type(copyfunc), ossl_check_PROFESSION_INFO_freefunc_type(freefunc)))
#define sk_PROFESSION_INFO_set_cmp_func(sk, cmp) ((sk_PROFESSION_INFO_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_PROFESSION_INFO_sk_type(sk), ossl_check_PROFESSION_INFO_compfunc_type(cmp)))
SKM_DEFINE_STACK_OF_INTERNAL(ADMISSIONS, ADMISSIONS, ADMISSIONS)
#define sk_ADMISSIONS_num(sk) OPENSSL_sk_num(ossl_check_const_ADMISSIONS_sk_type(sk))
#define sk_ADMISSIONS_value(sk, idx) ((ADMISSIONS *)OPENSSL_sk_value(ossl_check_const_ADMISSIONS_sk_type(sk), (idx)))
#define sk_ADMISSIONS_new(cmp) ((STACK_OF(ADMISSIONS) *)OPENSSL_sk_new(ossl_check_ADMISSIONS_compfunc_type(cmp)))
#define sk_ADMISSIONS_new_null() ((STACK_OF(ADMISSIONS) *)OPENSSL_sk_new_null())
#define sk_ADMISSIONS_new_reserve(cmp, n) ((STACK_OF(ADMISSIONS) *)OPENSSL_sk_new_reserve(ossl_check_ADMISSIONS_compfunc_type(cmp), (n)))
#define sk_ADMISSIONS_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_ADMISSIONS_sk_type(sk), (n))
#define sk_ADMISSIONS_free(sk) OPENSSL_sk_free(ossl_check_ADMISSIONS_sk_type(sk))
#define sk_ADMISSIONS_zero(sk) OPENSSL_sk_zero(ossl_check_ADMISSIONS_sk_type(sk))
#define sk_ADMISSIONS_delete(sk, i) ((ADMISSIONS *)OPENSSL_sk_delete(ossl_check_ADMISSIONS_sk_type(sk), (i)))
#define sk_ADMISSIONS_delete_ptr(sk, ptr) ((ADMISSIONS *)OPENSSL_sk_delete_ptr(ossl_check_ADMISSIONS_sk_type(sk), ossl_check_ADMISSIONS_type(ptr)))
#define sk_ADMISSIONS_push(sk, ptr) OPENSSL_sk_push(ossl_check_ADMISSIONS_sk_type(sk), ossl_check_ADMISSIONS_type(ptr))
#define sk_ADMISSIONS_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_ADMISSIONS_sk_type(sk), ossl_check_ADMISSIONS_type(ptr))
#define sk_ADMISSIONS_pop(sk) ((ADMISSIONS *)OPENSSL_sk_pop(ossl_check_ADMISSIONS_sk_type(sk)))
#define sk_ADMISSIONS_shift(sk) ((ADMISSIONS *)OPENSSL_sk_shift(ossl_check_ADMISSIONS_sk_type(sk)))
#define sk_ADMISSIONS_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_ADMISSIONS_sk_type(sk),ossl_check_ADMISSIONS_freefunc_type(freefunc))
#define sk_ADMISSIONS_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_ADMISSIONS_sk_type(sk), ossl_check_ADMISSIONS_type(ptr), (idx))
#define sk_ADMISSIONS_set(sk, idx, ptr) ((ADMISSIONS *)OPENSSL_sk_set(ossl_check_ADMISSIONS_sk_type(sk), (idx), ossl_check_ADMISSIONS_type(ptr)))
#define sk_ADMISSIONS_find(sk, ptr) OPENSSL_sk_find(ossl_check_ADMISSIONS_sk_type(sk), ossl_check_ADMISSIONS_type(ptr))
#define sk_ADMISSIONS_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_ADMISSIONS_sk_type(sk), ossl_check_ADMISSIONS_type(ptr))
#define sk_ADMISSIONS_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_ADMISSIONS_sk_type(sk), ossl_check_ADMISSIONS_type(ptr), pnum)
#define sk_ADMISSIONS_sort(sk) OPENSSL_sk_sort(ossl_check_ADMISSIONS_sk_type(sk))
#define sk_ADMISSIONS_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_ADMISSIONS_sk_type(sk))
#define sk_ADMISSIONS_dup(sk) ((STACK_OF(ADMISSIONS) *)OPENSSL_sk_dup(ossl_check_const_ADMISSIONS_sk_type(sk)))
#define sk_ADMISSIONS_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(ADMISSIONS) *)OPENSSL_sk_deep_copy(ossl_check_const_ADMISSIONS_sk_type(sk), ossl_check_ADMISSIONS_copyfunc_type(copyfunc), ossl_check_ADMISSIONS_freefunc_type(freefunc)))
#define sk_ADMISSIONS_set_cmp_func(sk, cmp) ((sk_ADMISSIONS_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_ADMISSIONS_sk_type(sk), ossl_check_ADMISSIONS_compfunc_type(cmp)))

typedef STACK_OF(PROFESSION_INFO) PROFESSION_INFOS;

const ASN1_OBJECT *NAMING_AUTHORITY_get0_authorityId(
    const NAMING_AUTHORITY *n);
const ASN1_IA5STRING *NAMING_AUTHORITY_get0_authorityURL(
    const NAMING_AUTHORITY *n);
const ASN1_STRING *NAMING_AUTHORITY_get0_authorityText(
    const NAMING_AUTHORITY *n);
void NAMING_AUTHORITY_set0_authorityId(NAMING_AUTHORITY *n,
    ASN1_OBJECT* namingAuthorityId);
void NAMING_AUTHORITY_set0_authorityURL(NAMING_AUTHORITY *n,
    ASN1_IA5STRING* namingAuthorityUrl);
void NAMING_AUTHORITY_set0_authorityText(NAMING_AUTHORITY *n,
    ASN1_STRING* namingAuthorityText);

const GENERAL_NAME *ADMISSION_SYNTAX_get0_admissionAuthority(
    const ADMISSION_SYNTAX *as);
void ADMISSION_SYNTAX_set0_admissionAuthority(
    ADMISSION_SYNTAX *as, GENERAL_NAME *aa);
const STACK_OF(ADMISSIONS) *ADMISSION_SYNTAX_get0_contentsOfAdmissions(
    const ADMISSION_SYNTAX *as);
void ADMISSION_SYNTAX_set0_contentsOfAdmissions(
    ADMISSION_SYNTAX *as, STACK_OF(ADMISSIONS) *a);
const GENERAL_NAME *ADMISSIONS_get0_admissionAuthority(const ADMISSIONS *a);
void ADMISSIONS_set0_admissionAuthority(ADMISSIONS *a, GENERAL_NAME *aa);
const NAMING_AUTHORITY *ADMISSIONS_get0_namingAuthority(const ADMISSIONS *a);
void ADMISSIONS_set0_namingAuthority(ADMISSIONS *a, NAMING_AUTHORITY *na);
const PROFESSION_INFOS *ADMISSIONS_get0_professionInfos(const ADMISSIONS *a);
void ADMISSIONS_set0_professionInfos(ADMISSIONS *a, PROFESSION_INFOS *pi);
const ASN1_OCTET_STRING *PROFESSION_INFO_get0_addProfessionInfo(
    const PROFESSION_INFO *pi);
void PROFESSION_INFO_set0_addProfessionInfo(
    PROFESSION_INFO *pi, ASN1_OCTET_STRING *aos);
const NAMING_AUTHORITY *PROFESSION_INFO_get0_namingAuthority(
    const PROFESSION_INFO *pi);
void PROFESSION_INFO_set0_namingAuthority(
    PROFESSION_INFO *pi, NAMING_AUTHORITY *na);
const STACK_OF(ASN1_STRING) *PROFESSION_INFO_get0_professionItems(
    const PROFESSION_INFO *pi);
void PROFESSION_INFO_set0_professionItems(
    PROFESSION_INFO *pi, STACK_OF(ASN1_STRING) *as);
const STACK_OF(ASN1_OBJECT) *PROFESSION_INFO_get0_professionOIDs(
    const PROFESSION_INFO *pi);
void PROFESSION_INFO_set0_professionOIDs(
    PROFESSION_INFO *pi, STACK_OF(ASN1_OBJECT) *po);
const ASN1_PRINTABLESTRING *PROFESSION_INFO_get0_registrationNumber(
    const PROFESSION_INFO *pi);
void PROFESSION_INFO_set0_registrationNumber(
    PROFESSION_INFO *pi, ASN1_PRINTABLESTRING *rn);

# ifdef  __cplusplus
}
# endif
#endif
