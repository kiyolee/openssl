/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*
 * Generated from x509_vfy.h.in for https://github.com/kiyolee/openssl.git.
 */



#ifndef OPENSSL_X509_VFY_H
# define OPENSSL_X509_VFY_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_X509_VFY_H
# endif

/*
 * Protect against recursion, x509.h and x509_vfy.h each include the other.
 */
# ifndef OPENSSL_X509_H
#  include <openssl/x509.h>
# endif

# include <openssl/opensslconf.h>
# include <openssl/lhash.h>
# include <openssl/bio.h>
# include <openssl/crypto.h>
# include <openssl/symhacks.h>

#ifdef  __cplusplus
extern "C" {
#endif

/*-
SSL_CTX -> X509_STORE
                -> X509_LOOKUP
                        ->X509_LOOKUP_METHOD
                -> X509_LOOKUP
                        ->X509_LOOKUP_METHOD

SSL     -> X509_STORE_CTX
                ->X509_STORE

The X509_STORE holds the tables etc for verification stuff.
A X509_STORE_CTX is used while validating a single certificate.
The X509_STORE has X509_LOOKUPs for looking up certs.
The X509_STORE then calls a function to actually verify the
certificate chain.
*/

typedef enum {
    X509_LU_NONE = 0,
    X509_LU_X509, X509_LU_CRL
} X509_LOOKUP_TYPE;

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#define X509_LU_RETRY   -1
#define X509_LU_FAIL    0
#endif

SKM_DEFINE_STACK_OF_INTERNAL(X509_LOOKUP, X509_LOOKUP, X509_LOOKUP)
#define sk_X509_LOOKUP_num(sk) OPENSSL_sk_num(ossl_check_const_X509_LOOKUP_sk_type(sk))
#define sk_X509_LOOKUP_value(sk, idx) ((X509_LOOKUP *)OPENSSL_sk_value(ossl_check_const_X509_LOOKUP_sk_type(sk), (idx)))
#define sk_X509_LOOKUP_new(cmp) ((STACK_OF(X509_LOOKUP) *)OPENSSL_sk_new(ossl_check_X509_LOOKUP_compfunc_type(cmp)))
#define sk_X509_LOOKUP_new_null() ((STACK_OF(X509_LOOKUP) *)OPENSSL_sk_new_null())
#define sk_X509_LOOKUP_new_reserve(cmp, n) ((STACK_OF(X509_LOOKUP) *)OPENSSL_sk_new_reserve(ossl_check_X509_LOOKUP_compfunc_type(cmp), (n)))
#define sk_X509_LOOKUP_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_LOOKUP_sk_type(sk), (n))
#define sk_X509_LOOKUP_free(sk) OPENSSL_sk_free(ossl_check_X509_LOOKUP_sk_type(sk))
#define sk_X509_LOOKUP_zero(sk) OPENSSL_sk_zero(ossl_check_X509_LOOKUP_sk_type(sk))
#define sk_X509_LOOKUP_delete(sk, i) ((X509_LOOKUP *)OPENSSL_sk_delete(ossl_check_X509_LOOKUP_sk_type(sk), (i)))
#define sk_X509_LOOKUP_delete_ptr(sk, ptr) ((X509_LOOKUP *)OPENSSL_sk_delete_ptr(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr)))
#define sk_X509_LOOKUP_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr))
#define sk_X509_LOOKUP_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr))
#define sk_X509_LOOKUP_pop(sk) ((X509_LOOKUP *)OPENSSL_sk_pop(ossl_check_X509_LOOKUP_sk_type(sk)))
#define sk_X509_LOOKUP_shift(sk) ((X509_LOOKUP *)OPENSSL_sk_shift(ossl_check_X509_LOOKUP_sk_type(sk)))
#define sk_X509_LOOKUP_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_LOOKUP_sk_type(sk),ossl_check_X509_LOOKUP_freefunc_type(freefunc))
#define sk_X509_LOOKUP_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr), (idx))
#define sk_X509_LOOKUP_set(sk, idx, ptr) ((X509_LOOKUP *)OPENSSL_sk_set(ossl_check_X509_LOOKUP_sk_type(sk), (idx), ossl_check_X509_LOOKUP_type(ptr)))
#define sk_X509_LOOKUP_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr))
#define sk_X509_LOOKUP_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr))
#define sk_X509_LOOKUP_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_type(ptr), pnum)
#define sk_X509_LOOKUP_sort(sk) OPENSSL_sk_sort(ossl_check_X509_LOOKUP_sk_type(sk))
#define sk_X509_LOOKUP_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_LOOKUP_sk_type(sk))
#define sk_X509_LOOKUP_dup(sk) ((STACK_OF(X509_LOOKUP) *)OPENSSL_sk_dup(ossl_check_const_X509_LOOKUP_sk_type(sk)))
#define sk_X509_LOOKUP_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_LOOKUP) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_copyfunc_type(copyfunc), ossl_check_X509_LOOKUP_freefunc_type(freefunc)))
#define sk_X509_LOOKUP_set_cmp_func(sk, cmp) ((sk_X509_LOOKUP_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_LOOKUP_sk_type(sk), ossl_check_X509_LOOKUP_compfunc_type(cmp)))
SKM_DEFINE_STACK_OF_INTERNAL(X509_OBJECT, X509_OBJECT, X509_OBJECT)
#define sk_X509_OBJECT_num(sk) OPENSSL_sk_num(ossl_check_const_X509_OBJECT_sk_type(sk))
#define sk_X509_OBJECT_value(sk, idx) ((X509_OBJECT *)OPENSSL_sk_value(ossl_check_const_X509_OBJECT_sk_type(sk), (idx)))
#define sk_X509_OBJECT_new(cmp) ((STACK_OF(X509_OBJECT) *)OPENSSL_sk_new(ossl_check_X509_OBJECT_compfunc_type(cmp)))
#define sk_X509_OBJECT_new_null() ((STACK_OF(X509_OBJECT) *)OPENSSL_sk_new_null())
#define sk_X509_OBJECT_new_reserve(cmp, n) ((STACK_OF(X509_OBJECT) *)OPENSSL_sk_new_reserve(ossl_check_X509_OBJECT_compfunc_type(cmp), (n)))
#define sk_X509_OBJECT_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_OBJECT_sk_type(sk), (n))
#define sk_X509_OBJECT_free(sk) OPENSSL_sk_free(ossl_check_X509_OBJECT_sk_type(sk))
#define sk_X509_OBJECT_zero(sk) OPENSSL_sk_zero(ossl_check_X509_OBJECT_sk_type(sk))
#define sk_X509_OBJECT_delete(sk, i) ((X509_OBJECT *)OPENSSL_sk_delete(ossl_check_X509_OBJECT_sk_type(sk), (i)))
#define sk_X509_OBJECT_delete_ptr(sk, ptr) ((X509_OBJECT *)OPENSSL_sk_delete_ptr(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr)))
#define sk_X509_OBJECT_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr))
#define sk_X509_OBJECT_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr))
#define sk_X509_OBJECT_pop(sk) ((X509_OBJECT *)OPENSSL_sk_pop(ossl_check_X509_OBJECT_sk_type(sk)))
#define sk_X509_OBJECT_shift(sk) ((X509_OBJECT *)OPENSSL_sk_shift(ossl_check_X509_OBJECT_sk_type(sk)))
#define sk_X509_OBJECT_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_OBJECT_sk_type(sk),ossl_check_X509_OBJECT_freefunc_type(freefunc))
#define sk_X509_OBJECT_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr), (idx))
#define sk_X509_OBJECT_set(sk, idx, ptr) ((X509_OBJECT *)OPENSSL_sk_set(ossl_check_X509_OBJECT_sk_type(sk), (idx), ossl_check_X509_OBJECT_type(ptr)))
#define sk_X509_OBJECT_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr))
#define sk_X509_OBJECT_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr))
#define sk_X509_OBJECT_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_type(ptr), pnum)
#define sk_X509_OBJECT_sort(sk) OPENSSL_sk_sort(ossl_check_X509_OBJECT_sk_type(sk))
#define sk_X509_OBJECT_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_OBJECT_sk_type(sk))
#define sk_X509_OBJECT_dup(sk) ((STACK_OF(X509_OBJECT) *)OPENSSL_sk_dup(ossl_check_const_X509_OBJECT_sk_type(sk)))
#define sk_X509_OBJECT_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_OBJECT) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_copyfunc_type(copyfunc), ossl_check_X509_OBJECT_freefunc_type(freefunc)))
#define sk_X509_OBJECT_set_cmp_func(sk, cmp) ((sk_X509_OBJECT_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_OBJECT_sk_type(sk), ossl_check_X509_OBJECT_compfunc_type(cmp)))
SKM_DEFINE_STACK_OF_INTERNAL(X509_VERIFY_PARAM, X509_VERIFY_PARAM, X509_VERIFY_PARAM)
#define sk_X509_VERIFY_PARAM_num(sk) OPENSSL_sk_num(ossl_check_const_X509_VERIFY_PARAM_sk_type(sk))
#define sk_X509_VERIFY_PARAM_value(sk, idx) ((X509_VERIFY_PARAM *)OPENSSL_sk_value(ossl_check_const_X509_VERIFY_PARAM_sk_type(sk), (idx)))
#define sk_X509_VERIFY_PARAM_new(cmp) ((STACK_OF(X509_VERIFY_PARAM) *)OPENSSL_sk_new(ossl_check_X509_VERIFY_PARAM_compfunc_type(cmp)))
#define sk_X509_VERIFY_PARAM_new_null() ((STACK_OF(X509_VERIFY_PARAM) *)OPENSSL_sk_new_null())
#define sk_X509_VERIFY_PARAM_new_reserve(cmp, n) ((STACK_OF(X509_VERIFY_PARAM) *)OPENSSL_sk_new_reserve(ossl_check_X509_VERIFY_PARAM_compfunc_type(cmp), (n)))
#define sk_X509_VERIFY_PARAM_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_VERIFY_PARAM_sk_type(sk), (n))
#define sk_X509_VERIFY_PARAM_free(sk) OPENSSL_sk_free(ossl_check_X509_VERIFY_PARAM_sk_type(sk))
#define sk_X509_VERIFY_PARAM_zero(sk) OPENSSL_sk_zero(ossl_check_X509_VERIFY_PARAM_sk_type(sk))
#define sk_X509_VERIFY_PARAM_delete(sk, i) ((X509_VERIFY_PARAM *)OPENSSL_sk_delete(ossl_check_X509_VERIFY_PARAM_sk_type(sk), (i)))
#define sk_X509_VERIFY_PARAM_delete_ptr(sk, ptr) ((X509_VERIFY_PARAM *)OPENSSL_sk_delete_ptr(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr)))
#define sk_X509_VERIFY_PARAM_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr))
#define sk_X509_VERIFY_PARAM_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr))
#define sk_X509_VERIFY_PARAM_pop(sk) ((X509_VERIFY_PARAM *)OPENSSL_sk_pop(ossl_check_X509_VERIFY_PARAM_sk_type(sk)))
#define sk_X509_VERIFY_PARAM_shift(sk) ((X509_VERIFY_PARAM *)OPENSSL_sk_shift(ossl_check_X509_VERIFY_PARAM_sk_type(sk)))
#define sk_X509_VERIFY_PARAM_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_VERIFY_PARAM_sk_type(sk),ossl_check_X509_VERIFY_PARAM_freefunc_type(freefunc))
#define sk_X509_VERIFY_PARAM_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr), (idx))
#define sk_X509_VERIFY_PARAM_set(sk, idx, ptr) ((X509_VERIFY_PARAM *)OPENSSL_sk_set(ossl_check_X509_VERIFY_PARAM_sk_type(sk), (idx), ossl_check_X509_VERIFY_PARAM_type(ptr)))
#define sk_X509_VERIFY_PARAM_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr))
#define sk_X509_VERIFY_PARAM_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr))
#define sk_X509_VERIFY_PARAM_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_type(ptr), pnum)
#define sk_X509_VERIFY_PARAM_sort(sk) OPENSSL_sk_sort(ossl_check_X509_VERIFY_PARAM_sk_type(sk))
#define sk_X509_VERIFY_PARAM_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_VERIFY_PARAM_sk_type(sk))
#define sk_X509_VERIFY_PARAM_dup(sk) ((STACK_OF(X509_VERIFY_PARAM) *)OPENSSL_sk_dup(ossl_check_const_X509_VERIFY_PARAM_sk_type(sk)))
#define sk_X509_VERIFY_PARAM_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_VERIFY_PARAM) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_copyfunc_type(copyfunc), ossl_check_X509_VERIFY_PARAM_freefunc_type(freefunc)))
#define sk_X509_VERIFY_PARAM_set_cmp_func(sk, cmp) ((sk_X509_VERIFY_PARAM_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_VERIFY_PARAM_sk_type(sk), ossl_check_X509_VERIFY_PARAM_compfunc_type(cmp)))


/* This is used for a table of trust checking functions */
typedef struct x509_trust_st {
    int trust;
    int flags;
    int (*check_trust) (struct x509_trust_st *, X509 *, int);
    char *name;
    int arg1;
    void *arg2;
} X509_TRUST;
SKM_DEFINE_STACK_OF_INTERNAL(X509_TRUST, X509_TRUST, X509_TRUST)
#define sk_X509_TRUST_num(sk) OPENSSL_sk_num(ossl_check_const_X509_TRUST_sk_type(sk))
#define sk_X509_TRUST_value(sk, idx) ((X509_TRUST *)OPENSSL_sk_value(ossl_check_const_X509_TRUST_sk_type(sk), (idx)))
#define sk_X509_TRUST_new(cmp) ((STACK_OF(X509_TRUST) *)OPENSSL_sk_new(ossl_check_X509_TRUST_compfunc_type(cmp)))
#define sk_X509_TRUST_new_null() ((STACK_OF(X509_TRUST) *)OPENSSL_sk_new_null())
#define sk_X509_TRUST_new_reserve(cmp, n) ((STACK_OF(X509_TRUST) *)OPENSSL_sk_new_reserve(ossl_check_X509_TRUST_compfunc_type(cmp), (n)))
#define sk_X509_TRUST_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_TRUST_sk_type(sk), (n))
#define sk_X509_TRUST_free(sk) OPENSSL_sk_free(ossl_check_X509_TRUST_sk_type(sk))
#define sk_X509_TRUST_zero(sk) OPENSSL_sk_zero(ossl_check_X509_TRUST_sk_type(sk))
#define sk_X509_TRUST_delete(sk, i) ((X509_TRUST *)OPENSSL_sk_delete(ossl_check_X509_TRUST_sk_type(sk), (i)))
#define sk_X509_TRUST_delete_ptr(sk, ptr) ((X509_TRUST *)OPENSSL_sk_delete_ptr(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr)))
#define sk_X509_TRUST_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr))
#define sk_X509_TRUST_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr))
#define sk_X509_TRUST_pop(sk) ((X509_TRUST *)OPENSSL_sk_pop(ossl_check_X509_TRUST_sk_type(sk)))
#define sk_X509_TRUST_shift(sk) ((X509_TRUST *)OPENSSL_sk_shift(ossl_check_X509_TRUST_sk_type(sk)))
#define sk_X509_TRUST_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_TRUST_sk_type(sk),ossl_check_X509_TRUST_freefunc_type(freefunc))
#define sk_X509_TRUST_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr), (idx))
#define sk_X509_TRUST_set(sk, idx, ptr) ((X509_TRUST *)OPENSSL_sk_set(ossl_check_X509_TRUST_sk_type(sk), (idx), ossl_check_X509_TRUST_type(ptr)))
#define sk_X509_TRUST_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr))
#define sk_X509_TRUST_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr))
#define sk_X509_TRUST_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_type(ptr), pnum)
#define sk_X509_TRUST_sort(sk) OPENSSL_sk_sort(ossl_check_X509_TRUST_sk_type(sk))
#define sk_X509_TRUST_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_TRUST_sk_type(sk))
#define sk_X509_TRUST_dup(sk) ((STACK_OF(X509_TRUST) *)OPENSSL_sk_dup(ossl_check_const_X509_TRUST_sk_type(sk)))
#define sk_X509_TRUST_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_TRUST) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_copyfunc_type(copyfunc), ossl_check_X509_TRUST_freefunc_type(freefunc)))
#define sk_X509_TRUST_set_cmp_func(sk, cmp) ((sk_X509_TRUST_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_TRUST_sk_type(sk), ossl_check_X509_TRUST_compfunc_type(cmp)))


/* standard trust ids */
# define X509_TRUST_DEFAULT      0 /* Only valid in purpose settings */
# define X509_TRUST_COMPAT       1
# define X509_TRUST_SSL_CLIENT   2
# define X509_TRUST_SSL_SERVER   3
# define X509_TRUST_EMAIL        4
# define X509_TRUST_OBJECT_SIGN  5
# define X509_TRUST_OCSP_SIGN    6
# define X509_TRUST_OCSP_REQUEST 7
# define X509_TRUST_TSA          8
/* Keep these up to date! */
# define X509_TRUST_MIN          1
# define X509_TRUST_MAX          8

/* trust_flags values */
# define X509_TRUST_DYNAMIC      (1U << 0)
# define X509_TRUST_DYNAMIC_NAME (1U << 1)
/* No compat trust if self-signed, preempts "DO_SS" */
# define X509_TRUST_NO_SS_COMPAT (1U << 2)
/* Compat trust if no explicit accepted trust EKUs */
# define X509_TRUST_DO_SS_COMPAT (1U << 3)
/* Accept "anyEKU" as a wildcard rejection OID and as a wildcard trust OID */
# define X509_TRUST_OK_ANY_EKU   (1U << 4)

/* check_trust return codes */
# define X509_TRUST_TRUSTED      1
# define X509_TRUST_REJECTED     2
# define X509_TRUST_UNTRUSTED    3

int X509_TRUST_set(int *t, int trust);
int X509_TRUST_get_count(void);
X509_TRUST *X509_TRUST_get0(int idx);
int X509_TRUST_get_by_id(int id);
int X509_TRUST_add(int id, int flags, int (*ck) (X509_TRUST *, X509 *, int),
                   const char *name, int arg1, void *arg2);
void X509_TRUST_cleanup(void);
int X509_TRUST_get_flags(const X509_TRUST *xp);
char *X509_TRUST_get0_name(const X509_TRUST *xp);
int X509_TRUST_get_trust(const X509_TRUST *xp);

int X509_trusted(const X509 *x);
int X509_add1_trust_object(X509 *x, const ASN1_OBJECT *obj);
int X509_add1_reject_object(X509 *x, const ASN1_OBJECT *obj);
void X509_trust_clear(X509 *x);
void X509_reject_clear(X509 *x);
STACK_OF(ASN1_OBJECT) *X509_get0_trust_objects(X509 *x);
STACK_OF(ASN1_OBJECT) *X509_get0_reject_objects(X509 *x);

int (*X509_TRUST_set_default(int (*trust) (int, X509 *, int))) (int, X509 *,
                                                                int);
int X509_check_trust(X509 *x, int id, int flags);

int X509_verify_cert(X509_STORE_CTX *ctx);
int X509_STORE_CTX_verify(X509_STORE_CTX *ctx);
STACK_OF(X509) *X509_build_chain(X509 *target, STACK_OF(X509) *certs,
                                 X509_STORE *store, int with_self_signed,
                                 OSSL_LIB_CTX *libctx, const char *propq);

int X509_STORE_set_depth(X509_STORE *store, int depth);

typedef int (*X509_STORE_CTX_verify_cb)(int, X509_STORE_CTX *);
int X509_STORE_CTX_print_verify_cb(int ok, X509_STORE_CTX *ctx);
typedef int (*X509_STORE_CTX_verify_fn)(X509_STORE_CTX *);
typedef int (*X509_STORE_CTX_get_issuer_fn)(X509 **issuer,
                                            X509_STORE_CTX *ctx, X509 *x);
typedef int (*X509_STORE_CTX_check_issued_fn)(X509_STORE_CTX *ctx,
                                              X509 *x, X509 *issuer);
typedef int (*X509_STORE_CTX_check_revocation_fn)(X509_STORE_CTX *ctx);
typedef int (*X509_STORE_CTX_get_crl_fn)(X509_STORE_CTX *ctx,
                                         X509_CRL **crl, X509 *x);
typedef int (*X509_STORE_CTX_check_crl_fn)(X509_STORE_CTX *ctx, X509_CRL *crl);
typedef int (*X509_STORE_CTX_cert_crl_fn)(X509_STORE_CTX *ctx,
                                          X509_CRL *crl, X509 *x);
typedef int (*X509_STORE_CTX_check_policy_fn)(X509_STORE_CTX *ctx);
typedef STACK_OF(X509)
    *(*X509_STORE_CTX_lookup_certs_fn)(X509_STORE_CTX *ctx,
                                       const X509_NAME *nm);
typedef STACK_OF(X509_CRL)
    *(*X509_STORE_CTX_lookup_crls_fn)(const X509_STORE_CTX *ctx,
                                      const X509_NAME *nm);
typedef int (*X509_STORE_CTX_cleanup_fn)(X509_STORE_CTX *ctx);

void X509_STORE_CTX_set_depth(X509_STORE_CTX *ctx, int depth);

# define X509_STORE_CTX_set_app_data(ctx,data) \
        X509_STORE_CTX_set_ex_data(ctx,0,data)
# define X509_STORE_CTX_get_app_data(ctx) \
        X509_STORE_CTX_get_ex_data(ctx,0)

# define X509_L_FILE_LOAD        1
# define X509_L_ADD_DIR          2
# define X509_L_ADD_STORE        3
# define X509_L_LOAD_STORE       4

# define X509_LOOKUP_load_file(x,name,type) \
                X509_LOOKUP_ctrl((x),X509_L_FILE_LOAD,(name),(long)(type),NULL)

# define X509_LOOKUP_add_dir(x,name,type) \
                X509_LOOKUP_ctrl((x),X509_L_ADD_DIR,(name),(long)(type),NULL)

# define X509_LOOKUP_add_store(x,name) \
                X509_LOOKUP_ctrl((x),X509_L_ADD_STORE,(name),0,NULL)

# define X509_LOOKUP_load_store(x,name) \
                X509_LOOKUP_ctrl((x),X509_L_LOAD_STORE,(name),0,NULL)

# define X509_LOOKUP_load_file_ex(x, name, type, libctx, propq)       \
X509_LOOKUP_ctrl_ex((x), X509_L_FILE_LOAD, (name), (long)(type), NULL,\
                    (libctx), (propq))

# define X509_LOOKUP_load_store_ex(x, name, libctx, propq)            \
X509_LOOKUP_ctrl_ex((x), X509_L_LOAD_STORE, (name), 0, NULL,          \
                    (libctx), (propq))

# define X509_LOOKUP_add_store_ex(x, name, libctx, propq)             \
X509_LOOKUP_ctrl_ex((x), X509_L_ADD_STORE, (name), 0, NULL,           \
                    (libctx), (propq))

# define X509_V_OK                                       0
# define X509_V_ERR_UNSPECIFIED                          1
# define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT            2
# define X509_V_ERR_UNABLE_TO_GET_CRL                    3
# define X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE     4
# define X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE      5
# define X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY   6
# define X509_V_ERR_CERT_SIGNATURE_FAILURE               7
# define X509_V_ERR_CRL_SIGNATURE_FAILURE                8
# define X509_V_ERR_CERT_NOT_YET_VALID                   9
# define X509_V_ERR_CERT_HAS_EXPIRED                     10
# define X509_V_ERR_CRL_NOT_YET_VALID                    11
# define X509_V_ERR_CRL_HAS_EXPIRED                      12
# define X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD       13
# define X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD        14
# define X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD       15
# define X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD       16
# define X509_V_ERR_OUT_OF_MEM                           17
# define X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT          18
# define X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN            19
# define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY    20
# define X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE      21
# define X509_V_ERR_CERT_CHAIN_TOO_LONG                  22
# define X509_V_ERR_CERT_REVOKED                         23
# define X509_V_ERR_NO_ISSUER_PUBLIC_KEY                 24
# define X509_V_ERR_PATH_LENGTH_EXCEEDED                 25
# define X509_V_ERR_INVALID_PURPOSE                      26
# define X509_V_ERR_CERT_UNTRUSTED                       27
# define X509_V_ERR_CERT_REJECTED                        28

/* These are 'informational' when looking for issuer cert */
# define X509_V_ERR_SUBJECT_ISSUER_MISMATCH              29
# define X509_V_ERR_AKID_SKID_MISMATCH                   30
# define X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH          31
# define X509_V_ERR_KEYUSAGE_NO_CERTSIGN                 32
# define X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER             33
# define X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION         34
# define X509_V_ERR_KEYUSAGE_NO_CRL_SIGN                 35
# define X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION     36
# define X509_V_ERR_INVALID_NON_CA                       37
# define X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED           38
# define X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE        39
# define X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED       40
# define X509_V_ERR_INVALID_EXTENSION                    41
# define X509_V_ERR_INVALID_POLICY_EXTENSION             42
# define X509_V_ERR_NO_EXPLICIT_POLICY                   43
# define X509_V_ERR_DIFFERENT_CRL_SCOPE                  44
# define X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE        45
# define X509_V_ERR_UNNESTED_RESOURCE                    46
# define X509_V_ERR_PERMITTED_VIOLATION                  47
# define X509_V_ERR_EXCLUDED_VIOLATION                   48
# define X509_V_ERR_SUBTREE_MINMAX                       49
/* The application is not happy */
# define X509_V_ERR_APPLICATION_VERIFICATION             50
# define X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE          51
# define X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX        52
# define X509_V_ERR_UNSUPPORTED_NAME_SYNTAX              53
# define X509_V_ERR_CRL_PATH_VALIDATION_ERROR            54
/* Another issuer check debug option */
# define X509_V_ERR_PATH_LOOP                            55
/* Suite B mode algorithm violation */
# define X509_V_ERR_SUITE_B_INVALID_VERSION              56
# define X509_V_ERR_SUITE_B_INVALID_ALGORITHM            57
# define X509_V_ERR_SUITE_B_INVALID_CURVE                58
# define X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM  59
# define X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED              60
# define X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 61
/* Host, email and IP check errors */
# define X509_V_ERR_HOSTNAME_MISMATCH                    62
# define X509_V_ERR_EMAIL_MISMATCH                       63
# define X509_V_ERR_IP_ADDRESS_MISMATCH                  64
/* DANE TLSA errors */
# define X509_V_ERR_DANE_NO_MATCH                        65
/* security level errors */
# define X509_V_ERR_EE_KEY_TOO_SMALL                     66
# define X509_V_ERR_CA_KEY_TOO_SMALL                     67
# define X509_V_ERR_CA_MD_TOO_WEAK                       68
/* Caller error */
# define X509_V_ERR_INVALID_CALL                         69
/* Issuer lookup error */
# define X509_V_ERR_STORE_LOOKUP                         70
/* Certificate transparency */
# define X509_V_ERR_NO_VALID_SCTS                        71

# define X509_V_ERR_PROXY_SUBJECT_NAME_VIOLATION         72
/* OCSP status errors */
# define X509_V_ERR_OCSP_VERIFY_NEEDED                   73  /* Need OCSP verification */
# define X509_V_ERR_OCSP_VERIFY_FAILED                   74  /* Couldn't verify cert through OCSP */
# define X509_V_ERR_OCSP_CERT_UNKNOWN                    75  /* Certificate wasn't recognized by the OCSP responder */

# define X509_V_ERR_UNSUPPORTED_SIGNATURE_ALGORITHM      76
# define X509_V_ERR_SIGNATURE_ALGORITHM_MISMATCH         77

/* Errors in case a check in X509_V_FLAG_X509_STRICT mode fails */
# define X509_V_ERR_SIGNATURE_ALGORITHM_INCONSISTENCY    78
# define X509_V_ERR_INVALID_CA                           79
# define X509_V_ERR_PATHLEN_INVALID_FOR_NON_CA           80
# define X509_V_ERR_PATHLEN_WITHOUT_KU_KEY_CERT_SIGN     81
# define X509_V_ERR_KU_KEY_CERT_SIGN_INVALID_FOR_NON_CA  82
# define X509_V_ERR_ISSUER_NAME_EMPTY                    83
# define X509_V_ERR_SUBJECT_NAME_EMPTY                   84
# define X509_V_ERR_MISSING_AUTHORITY_KEY_IDENTIFIER     85
# define X509_V_ERR_MISSING_SUBJECT_KEY_IDENTIFIER       86
# define X509_V_ERR_EMPTY_SUBJECT_ALT_NAME               87
# define X509_V_ERR_EMPTY_SUBJECT_SAN_NOT_CRITICAL       88
# define X509_V_ERR_CA_BCONS_NOT_CRITICAL                89
# define X509_V_ERR_AUTHORITY_KEY_IDENTIFIER_CRITICAL    90
# define X509_V_ERR_SUBJECT_KEY_IDENTIFIER_CRITICAL      91
# define X509_V_ERR_CA_CERT_MISSING_KEY_USAGE            92
# define X509_V_ERR_EXTENSIONS_REQUIRE_VERSION_3         93
# define X509_V_ERR_EC_KEY_EXPLICIT_PARAMS               94

/* Certificate verify flags */
# ifndef OPENSSL_NO_DEPRECATED_1_1_0
#  define X509_V_FLAG_CB_ISSUER_CHECK             0x0   /* Deprecated */
# endif
/* Use check time instead of current time */
# define X509_V_FLAG_USE_CHECK_TIME              0x2
/* Lookup CRLs */
# define X509_V_FLAG_CRL_CHECK                   0x4
/* Lookup CRLs for whole chain */
# define X509_V_FLAG_CRL_CHECK_ALL               0x8
/* Ignore unhandled critical extensions */
# define X509_V_FLAG_IGNORE_CRITICAL             0x10
/* Disable workarounds for broken certificates */
# define X509_V_FLAG_X509_STRICT                 0x20
/* Enable proxy certificate validation */
# define X509_V_FLAG_ALLOW_PROXY_CERTS           0x40
/* Enable policy checking */
# define X509_V_FLAG_POLICY_CHECK                0x80
/* Policy variable require-explicit-policy */
# define X509_V_FLAG_EXPLICIT_POLICY             0x100
/* Policy variable inhibit-any-policy */
# define X509_V_FLAG_INHIBIT_ANY                 0x200
/* Policy variable inhibit-policy-mapping */
# define X509_V_FLAG_INHIBIT_MAP                 0x400
/* Notify callback that policy is OK */
# define X509_V_FLAG_NOTIFY_POLICY               0x800
/* Extended CRL features such as indirect CRLs, alternate CRL signing keys */
# define X509_V_FLAG_EXTENDED_CRL_SUPPORT        0x1000
/* Delta CRL support */
# define X509_V_FLAG_USE_DELTAS                  0x2000
/* Check self-signed CA signature */
# define X509_V_FLAG_CHECK_SS_SIGNATURE          0x4000
/* Use trusted store first */
# define X509_V_FLAG_TRUSTED_FIRST               0x8000
/* Suite B 128 bit only mode: not normally used */
# define X509_V_FLAG_SUITEB_128_LOS_ONLY         0x10000
/* Suite B 192 bit only mode */
# define X509_V_FLAG_SUITEB_192_LOS              0x20000
/* Suite B 128 bit mode allowing 192 bit algorithms */
# define X509_V_FLAG_SUITEB_128_LOS              0x30000
/* Allow partial chains if at least one certificate is in trusted store */
# define X509_V_FLAG_PARTIAL_CHAIN               0x80000
/*
 * If the initial chain is not trusted, do not attempt to build an alternative
 * chain. Alternate chain checking was introduced in 1.1.0. Setting this flag
 * will force the behaviour to match that of previous versions.
 */
# define X509_V_FLAG_NO_ALT_CHAINS               0x100000
/* Do not check certificate/CRL validity against current time */
# define X509_V_FLAG_NO_CHECK_TIME               0x200000

# define X509_VP_FLAG_DEFAULT                    0x1
# define X509_VP_FLAG_OVERWRITE                  0x2
# define X509_VP_FLAG_RESET_FLAGS                0x4
# define X509_VP_FLAG_LOCKED                     0x8
# define X509_VP_FLAG_ONCE                       0x10

/* Internal use: mask of policy related options */
# define X509_V_FLAG_POLICY_MASK (X509_V_FLAG_POLICY_CHECK \
                                | X509_V_FLAG_EXPLICIT_POLICY \
                                | X509_V_FLAG_INHIBIT_ANY \
                                | X509_V_FLAG_INHIBIT_MAP)

int X509_OBJECT_idx_by_subject(STACK_OF(X509_OBJECT) *h, X509_LOOKUP_TYPE type,
                               const X509_NAME *name);
X509_OBJECT *X509_OBJECT_retrieve_by_subject(STACK_OF(X509_OBJECT) *h,
                                             X509_LOOKUP_TYPE type,
                                             const X509_NAME *name);
X509_OBJECT *X509_OBJECT_retrieve_match(STACK_OF(X509_OBJECT) *h,
                                        X509_OBJECT *x);
int X509_OBJECT_up_ref_count(X509_OBJECT *a);
X509_OBJECT *X509_OBJECT_new(void);
void X509_OBJECT_free(X509_OBJECT *a);
X509_LOOKUP_TYPE X509_OBJECT_get_type(const X509_OBJECT *a);
X509 *X509_OBJECT_get0_X509(const X509_OBJECT *a);
int X509_OBJECT_set1_X509(X509_OBJECT *a, X509 *obj);
X509_CRL *X509_OBJECT_get0_X509_CRL(const X509_OBJECT *a);
int X509_OBJECT_set1_X509_CRL(X509_OBJECT *a, X509_CRL *obj);
X509_STORE *X509_STORE_new(void);
void X509_STORE_free(X509_STORE *xs);
int X509_STORE_lock(X509_STORE *xs);
int X509_STORE_unlock(X509_STORE *xs);
int X509_STORE_up_ref(X509_STORE *xs);
STACK_OF(X509_OBJECT) *X509_STORE_get0_objects(const X509_STORE *xs);
STACK_OF(X509) *X509_STORE_get1_all_certs(X509_STORE *xs);
STACK_OF(X509) *X509_STORE_CTX_get1_certs(X509_STORE_CTX *xs,
                                          const X509_NAME *nm);
STACK_OF(X509_CRL) *X509_STORE_CTX_get1_crls(const X509_STORE_CTX *st,
                                             const X509_NAME *nm);
int X509_STORE_set_flags(X509_STORE *xs, unsigned long flags);
int X509_STORE_set_purpose(X509_STORE *xs, int purpose);
int X509_STORE_set_trust(X509_STORE *xs, int trust);
int X509_STORE_set1_param(X509_STORE *xs, const X509_VERIFY_PARAM *pm);
X509_VERIFY_PARAM *X509_STORE_get0_param(const X509_STORE *xs);

void X509_STORE_set_verify(X509_STORE *xs, X509_STORE_CTX_verify_fn verify);
#define X509_STORE_set_verify_func(ctx, func) \
            X509_STORE_set_verify((ctx),(func))
void X509_STORE_CTX_set_verify(X509_STORE_CTX *ctx,
                               X509_STORE_CTX_verify_fn verify);
X509_STORE_CTX_verify_fn X509_STORE_get_verify(const X509_STORE *xs);
void X509_STORE_set_verify_cb(X509_STORE *xs,
                              X509_STORE_CTX_verify_cb verify_cb);
# define X509_STORE_set_verify_cb_func(ctx,func) \
            X509_STORE_set_verify_cb((ctx),(func))
X509_STORE_CTX_verify_cb X509_STORE_get_verify_cb(const X509_STORE *xs);
void X509_STORE_set_get_issuer(X509_STORE *xs,
                               X509_STORE_CTX_get_issuer_fn get_issuer);
X509_STORE_CTX_get_issuer_fn X509_STORE_get_get_issuer(const X509_STORE *xs);
void X509_STORE_set_check_issued(X509_STORE *xs,
                                 X509_STORE_CTX_check_issued_fn check_issued);
X509_STORE_CTX_check_issued_fn X509_STORE_get_check_issued(const X509_STORE *s);
void X509_STORE_set_check_revocation(X509_STORE *xs,
                                     X509_STORE_CTX_check_revocation_fn check_revocation);
X509_STORE_CTX_check_revocation_fn
    X509_STORE_get_check_revocation(const X509_STORE *xs);
void X509_STORE_set_get_crl(X509_STORE *xs,
                            X509_STORE_CTX_get_crl_fn get_crl);
X509_STORE_CTX_get_crl_fn X509_STORE_get_get_crl(const X509_STORE *xs);
void X509_STORE_set_check_crl(X509_STORE *xs,
                              X509_STORE_CTX_check_crl_fn check_crl);
X509_STORE_CTX_check_crl_fn X509_STORE_get_check_crl(const X509_STORE *xs);
void X509_STORE_set_cert_crl(X509_STORE *xs,
                             X509_STORE_CTX_cert_crl_fn cert_crl);
X509_STORE_CTX_cert_crl_fn X509_STORE_get_cert_crl(const X509_STORE *xs);
void X509_STORE_set_check_policy(X509_STORE *xs,
                                 X509_STORE_CTX_check_policy_fn check_policy);
X509_STORE_CTX_check_policy_fn X509_STORE_get_check_policy(const X509_STORE *s);
void X509_STORE_set_lookup_certs(X509_STORE *xs,
                                 X509_STORE_CTX_lookup_certs_fn lookup_certs);
X509_STORE_CTX_lookup_certs_fn X509_STORE_get_lookup_certs(const X509_STORE *s);
void X509_STORE_set_lookup_crls(X509_STORE *xs,
                                X509_STORE_CTX_lookup_crls_fn lookup_crls);
#define X509_STORE_set_lookup_crls_cb(ctx, func) \
    X509_STORE_set_lookup_crls((ctx), (func))
X509_STORE_CTX_lookup_crls_fn X509_STORE_get_lookup_crls(const X509_STORE *xs);
void X509_STORE_set_cleanup(X509_STORE *xs,
                            X509_STORE_CTX_cleanup_fn cleanup);
X509_STORE_CTX_cleanup_fn X509_STORE_get_cleanup(const X509_STORE *xs);

#define X509_STORE_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE, l, p, newf, dupf, freef)
int X509_STORE_set_ex_data(X509_STORE *xs, int idx, void *data);
void *X509_STORE_get_ex_data(const X509_STORE *xs, int idx);

X509_STORE_CTX *X509_STORE_CTX_new_ex(OSSL_LIB_CTX *libctx, const char *propq);
X509_STORE_CTX *X509_STORE_CTX_new(void);

int X509_STORE_CTX_get1_issuer(X509 **issuer, X509_STORE_CTX *ctx, X509 *x);

void X509_STORE_CTX_free(X509_STORE_CTX *ctx);
int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *trust_store,
                        X509 *target, STACK_OF(X509) *untrusted);
void X509_STORE_CTX_set0_trusted_stack(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);
void X509_STORE_CTX_cleanup(X509_STORE_CTX *ctx);

X509_STORE *X509_STORE_CTX_get0_store(const X509_STORE_CTX *ctx);
X509 *X509_STORE_CTX_get0_cert(const X509_STORE_CTX *ctx);
STACK_OF(X509)* X509_STORE_CTX_get0_untrusted(const X509_STORE_CTX *ctx);
void X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);
void X509_STORE_CTX_set_verify_cb(X509_STORE_CTX *ctx,
                                  X509_STORE_CTX_verify_cb verify);
X509_STORE_CTX_verify_cb X509_STORE_CTX_get_verify_cb(const X509_STORE_CTX *ctx);
X509_STORE_CTX_verify_fn X509_STORE_CTX_get_verify(const X509_STORE_CTX *ctx);
X509_STORE_CTX_get_issuer_fn X509_STORE_CTX_get_get_issuer(const X509_STORE_CTX *ctx);
X509_STORE_CTX_check_issued_fn X509_STORE_CTX_get_check_issued(const X509_STORE_CTX *ctx);
X509_STORE_CTX_check_revocation_fn X509_STORE_CTX_get_check_revocation(const X509_STORE_CTX *ctx);
X509_STORE_CTX_get_crl_fn X509_STORE_CTX_get_get_crl(const X509_STORE_CTX *ctx);
X509_STORE_CTX_check_crl_fn X509_STORE_CTX_get_check_crl(const X509_STORE_CTX *ctx);
X509_STORE_CTX_cert_crl_fn X509_STORE_CTX_get_cert_crl(const X509_STORE_CTX *ctx);
X509_STORE_CTX_check_policy_fn X509_STORE_CTX_get_check_policy(const X509_STORE_CTX *ctx);
X509_STORE_CTX_lookup_certs_fn X509_STORE_CTX_get_lookup_certs(const X509_STORE_CTX *ctx);
X509_STORE_CTX_lookup_crls_fn X509_STORE_CTX_get_lookup_crls(const X509_STORE_CTX *ctx);
X509_STORE_CTX_cleanup_fn X509_STORE_CTX_get_cleanup(const X509_STORE_CTX *ctx);

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
# define X509_STORE_CTX_get_chain X509_STORE_CTX_get0_chain
# define X509_STORE_CTX_set_chain X509_STORE_CTX_set0_untrusted
# define X509_STORE_CTX_trusted_stack X509_STORE_CTX_set0_trusted_stack
# define X509_STORE_get_by_subject X509_STORE_CTX_get_by_subject
# define X509_STORE_get1_certs X509_STORE_CTX_get1_certs
# define X509_STORE_get1_crls X509_STORE_CTX_get1_crls
/* the following macro is misspelled; use X509_STORE_get1_certs instead */
# define X509_STORE_get1_cert X509_STORE_CTX_get1_certs
/* the following macro is misspelled; use X509_STORE_get1_crls instead */
# define X509_STORE_get1_crl X509_STORE_CTX_get1_crls
#endif

X509_LOOKUP *X509_STORE_add_lookup(X509_STORE *xs, X509_LOOKUP_METHOD *m);
X509_LOOKUP_METHOD *X509_LOOKUP_hash_dir(void);
X509_LOOKUP_METHOD *X509_LOOKUP_file(void);
X509_LOOKUP_METHOD *X509_LOOKUP_store(void);

typedef int (*X509_LOOKUP_ctrl_fn)(X509_LOOKUP *ctx, int cmd, const char *argc,
                                   long argl, char **ret);
typedef int (*X509_LOOKUP_ctrl_ex_fn)(
    X509_LOOKUP *ctx, int cmd, const char *argc, long argl, char **ret,
    OSSL_LIB_CTX *libctx, const char *propq);

typedef int (*X509_LOOKUP_get_by_subject_fn)(X509_LOOKUP *ctx,
                                             X509_LOOKUP_TYPE type,
                                             const X509_NAME *name,
                                             X509_OBJECT *ret);
typedef int (*X509_LOOKUP_get_by_subject_ex_fn)(X509_LOOKUP *ctx,
                                                         X509_LOOKUP_TYPE type,
                                                         const X509_NAME *name,
                                                         X509_OBJECT *ret,
                                                         OSSL_LIB_CTX *libctx,
                                                         const char *propq);
typedef int (*X509_LOOKUP_get_by_issuer_serial_fn)(X509_LOOKUP *ctx,
                                                   X509_LOOKUP_TYPE type,
                                                   const X509_NAME *name,
                                                   const ASN1_INTEGER *serial,
                                                   X509_OBJECT *ret);
typedef int (*X509_LOOKUP_get_by_fingerprint_fn)(X509_LOOKUP *ctx,
                                                 X509_LOOKUP_TYPE type,
                                                 const unsigned char* bytes,
                                                 int len,
                                                 X509_OBJECT *ret);
typedef int (*X509_LOOKUP_get_by_alias_fn)(X509_LOOKUP *ctx,
                                           X509_LOOKUP_TYPE type,
                                           const char *str,
                                           int len,
                                           X509_OBJECT *ret);

X509_LOOKUP_METHOD *X509_LOOKUP_meth_new(const char *name);
void X509_LOOKUP_meth_free(X509_LOOKUP_METHOD *method);

int X509_LOOKUP_meth_set_new_item(X509_LOOKUP_METHOD *method,
                                  int (*new_item) (X509_LOOKUP *ctx));
int (*X509_LOOKUP_meth_get_new_item(const X509_LOOKUP_METHOD* method))
    (X509_LOOKUP *ctx);

int X509_LOOKUP_meth_set_free(X509_LOOKUP_METHOD *method,
                              void (*free_fn) (X509_LOOKUP *ctx));
void (*X509_LOOKUP_meth_get_free(const X509_LOOKUP_METHOD* method))
    (X509_LOOKUP *ctx);

int X509_LOOKUP_meth_set_init(X509_LOOKUP_METHOD *method,
                              int (*init) (X509_LOOKUP *ctx));
int (*X509_LOOKUP_meth_get_init(const X509_LOOKUP_METHOD* method))
    (X509_LOOKUP *ctx);

int X509_LOOKUP_meth_set_shutdown(X509_LOOKUP_METHOD *method,
                                  int (*shutdown) (X509_LOOKUP *ctx));
int (*X509_LOOKUP_meth_get_shutdown(const X509_LOOKUP_METHOD* method))
    (X509_LOOKUP *ctx);

int X509_LOOKUP_meth_set_ctrl(X509_LOOKUP_METHOD *method,
                              X509_LOOKUP_ctrl_fn ctrl_fn);
X509_LOOKUP_ctrl_fn X509_LOOKUP_meth_get_ctrl(const X509_LOOKUP_METHOD *method);

int X509_LOOKUP_meth_set_get_by_subject(X509_LOOKUP_METHOD *method,
                                        X509_LOOKUP_get_by_subject_fn fn);
X509_LOOKUP_get_by_subject_fn X509_LOOKUP_meth_get_get_by_subject(
    const X509_LOOKUP_METHOD *method);

int X509_LOOKUP_meth_set_get_by_issuer_serial(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_get_by_issuer_serial_fn fn);
X509_LOOKUP_get_by_issuer_serial_fn X509_LOOKUP_meth_get_get_by_issuer_serial(
    const X509_LOOKUP_METHOD *method);

int X509_LOOKUP_meth_set_get_by_fingerprint(X509_LOOKUP_METHOD *method,
    X509_LOOKUP_get_by_fingerprint_fn fn);
X509_LOOKUP_get_by_fingerprint_fn X509_LOOKUP_meth_get_get_by_fingerprint(
    const X509_LOOKUP_METHOD *method);

int X509_LOOKUP_meth_set_get_by_alias(X509_LOOKUP_METHOD *method,
                                      X509_LOOKUP_get_by_alias_fn fn);
X509_LOOKUP_get_by_alias_fn X509_LOOKUP_meth_get_get_by_alias(
    const X509_LOOKUP_METHOD *method);


int X509_STORE_add_cert(X509_STORE *xs, X509 *x);
int X509_STORE_add_crl(X509_STORE *xs, X509_CRL *x);

int X509_STORE_CTX_get_by_subject(const X509_STORE_CTX *vs,
                                  X509_LOOKUP_TYPE type,
                                  const X509_NAME *name, X509_OBJECT *ret);
X509_OBJECT *X509_STORE_CTX_get_obj_by_subject(X509_STORE_CTX *vs,
                                               X509_LOOKUP_TYPE type,
                                               const X509_NAME *name);

int X509_LOOKUP_ctrl(X509_LOOKUP *ctx, int cmd, const char *argc,
                     long argl, char **ret);
int X509_LOOKUP_ctrl_ex(X509_LOOKUP *ctx, int cmd, const char *argc, long argl,
                        char **ret, OSSL_LIB_CTX *libctx, const char *propq);

int X509_load_cert_file(X509_LOOKUP *ctx, const char *file, int type);
int X509_load_cert_file_ex(X509_LOOKUP *ctx, const char *file, int type,
                           OSSL_LIB_CTX *libctx, const char *propq);
int X509_load_crl_file(X509_LOOKUP *ctx, const char *file, int type);
int X509_load_cert_crl_file(X509_LOOKUP *ctx, const char *file, int type);
int X509_load_cert_crl_file_ex(X509_LOOKUP *ctx, const char *file, int type,
                               OSSL_LIB_CTX *libctx, const char *propq);

X509_LOOKUP *X509_LOOKUP_new(X509_LOOKUP_METHOD *method);
void X509_LOOKUP_free(X509_LOOKUP *ctx);
int X509_LOOKUP_init(X509_LOOKUP *ctx);
int X509_LOOKUP_by_subject(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                           const X509_NAME *name, X509_OBJECT *ret);
int X509_LOOKUP_by_subject_ex(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                              const X509_NAME *name, X509_OBJECT *ret,
                              OSSL_LIB_CTX *libctx, const char *propq);
int X509_LOOKUP_by_issuer_serial(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                                 const X509_NAME *name,
                                 const ASN1_INTEGER *serial,
                                 X509_OBJECT *ret);
int X509_LOOKUP_by_fingerprint(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                               const unsigned char *bytes, int len,
                               X509_OBJECT *ret);
int X509_LOOKUP_by_alias(X509_LOOKUP *ctx, X509_LOOKUP_TYPE type,
                         const char *str, int len, X509_OBJECT *ret);
int X509_LOOKUP_set_method_data(X509_LOOKUP *ctx, void *data);
void *X509_LOOKUP_get_method_data(const X509_LOOKUP *ctx);
X509_STORE *X509_LOOKUP_get_store(const X509_LOOKUP *ctx);
int X509_LOOKUP_shutdown(X509_LOOKUP *ctx);

int X509_STORE_load_file(X509_STORE *xs, const char *file);
int X509_STORE_load_path(X509_STORE *xs, const char *path);
int X509_STORE_load_store(X509_STORE *xs, const char *store);
int X509_STORE_load_locations(X509_STORE *s, const char *file, const char *dir);
int X509_STORE_set_default_paths(X509_STORE *xs);

int X509_STORE_load_file_ex(X509_STORE *xs, const char *file,
                            OSSL_LIB_CTX *libctx, const char *propq);
int X509_STORE_load_store_ex(X509_STORE *xs, const char *store,
                             OSSL_LIB_CTX *libctx, const char *propq);
int X509_STORE_load_locations_ex(X509_STORE *xs,
                                 const char *file, const char *dir,
                                 OSSL_LIB_CTX *libctx, const char *propq);
int X509_STORE_set_default_paths_ex(X509_STORE *xs,
                                    OSSL_LIB_CTX *libctx, const char *propq);

#define X509_STORE_CTX_get_ex_new_index(l, p, newf, dupf, freef) \
    CRYPTO_get_ex_new_index(CRYPTO_EX_INDEX_X509_STORE_CTX, l, p, newf, dupf, freef)
int X509_STORE_CTX_set_ex_data(X509_STORE_CTX *ctx, int idx, void *data);
void *X509_STORE_CTX_get_ex_data(const X509_STORE_CTX *ctx, int idx);
int X509_STORE_CTX_get_error(const X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_error(X509_STORE_CTX *ctx, int s);
int X509_STORE_CTX_get_error_depth(const X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_error_depth(X509_STORE_CTX *ctx, int depth);
X509 *X509_STORE_CTX_get_current_cert(const X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_current_cert(X509_STORE_CTX *ctx, X509 *x);
X509 *X509_STORE_CTX_get0_current_issuer(const X509_STORE_CTX *ctx);
X509_CRL *X509_STORE_CTX_get0_current_crl(const X509_STORE_CTX *ctx);
X509_STORE_CTX *X509_STORE_CTX_get0_parent_ctx(const X509_STORE_CTX *ctx);
STACK_OF(X509) *X509_STORE_CTX_get0_chain(const X509_STORE_CTX *ctx);
STACK_OF(X509) *X509_STORE_CTX_get1_chain(const X509_STORE_CTX *ctx);
void X509_STORE_CTX_set_cert(X509_STORE_CTX *ctx, X509 *target);
void X509_STORE_CTX_set0_verified_chain(X509_STORE_CTX *c, STACK_OF(X509) *sk);
void X509_STORE_CTX_set0_crls(X509_STORE_CTX *ctx, STACK_OF(X509_CRL) *sk);
int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose);
int X509_STORE_CTX_set_trust(X509_STORE_CTX *ctx, int trust);
int X509_STORE_CTX_purpose_inherit(X509_STORE_CTX *ctx, int def_purpose,
                                   int purpose, int trust);
void X509_STORE_CTX_set_flags(X509_STORE_CTX *ctx, unsigned long flags);
void X509_STORE_CTX_set_time(X509_STORE_CTX *ctx, unsigned long flags,
                             time_t t);

X509_POLICY_TREE *X509_STORE_CTX_get0_policy_tree(const X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_explicit_policy(const X509_STORE_CTX *ctx);
int X509_STORE_CTX_get_num_untrusted(const X509_STORE_CTX *ctx);

X509_VERIFY_PARAM *X509_STORE_CTX_get0_param(const X509_STORE_CTX *ctx);
void X509_STORE_CTX_set0_param(X509_STORE_CTX *ctx, X509_VERIFY_PARAM *param);
int X509_STORE_CTX_set_default(X509_STORE_CTX *ctx, const char *name);

/*
 * Bridge opacity barrier between libcrypt and libssl, also needed to support
 * offline testing in test/danetest.c
 */
void X509_STORE_CTX_set0_dane(X509_STORE_CTX *ctx, SSL_DANE *dane);
#define DANE_FLAG_NO_DANE_EE_NAMECHECKS (1L << 0)

/* X509_VERIFY_PARAM functions */

X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void);
void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_inherit(X509_VERIFY_PARAM *to,
                              const X509_VERIFY_PARAM *from);
int X509_VERIFY_PARAM_set1(X509_VERIFY_PARAM *to,
                           const X509_VERIFY_PARAM *from);
int X509_VERIFY_PARAM_set1_name(X509_VERIFY_PARAM *param, const char *name);
int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *param,
                                unsigned long flags);
int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM *param,
                                  unsigned long flags);
unsigned long X509_VERIFY_PARAM_get_flags(const X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *param, int purpose);
int X509_VERIFY_PARAM_set_trust(X509_VERIFY_PARAM *param, int trust);
void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM *param, int depth);
void X509_VERIFY_PARAM_set_auth_level(X509_VERIFY_PARAM *param, int auth_level);
time_t X509_VERIFY_PARAM_get_time(const X509_VERIFY_PARAM *param);
void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *param, time_t t);
int X509_VERIFY_PARAM_add0_policy(X509_VERIFY_PARAM *param,
                                  ASN1_OBJECT *policy);
int X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *param,
                                    STACK_OF(ASN1_OBJECT) *policies);

int X509_VERIFY_PARAM_set_inh_flags(X509_VERIFY_PARAM *param,
                                    uint32_t flags);
uint32_t X509_VERIFY_PARAM_get_inh_flags(const X509_VERIFY_PARAM *param);

char *X509_VERIFY_PARAM_get0_host(X509_VERIFY_PARAM *param, int idx);
int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *param,
                                const char *name, size_t namelen);
int X509_VERIFY_PARAM_add1_host(X509_VERIFY_PARAM *param,
                                const char *name, size_t namelen);
void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM *param,
                                     unsigned int flags);
unsigned int X509_VERIFY_PARAM_get_hostflags(const X509_VERIFY_PARAM *param);
char *X509_VERIFY_PARAM_get0_peername(const X509_VERIFY_PARAM *param);
void X509_VERIFY_PARAM_move_peername(X509_VERIFY_PARAM *, X509_VERIFY_PARAM *);
char *X509_VERIFY_PARAM_get0_email(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_set1_email(X509_VERIFY_PARAM *param,
                                 const char *email, size_t emaillen);
char *X509_VERIFY_PARAM_get1_ip_asc(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_set1_ip(X509_VERIFY_PARAM *param,
                              const unsigned char *ip, size_t iplen);
int X509_VERIFY_PARAM_set1_ip_asc(X509_VERIFY_PARAM *param,
                                  const char *ipasc);

int X509_VERIFY_PARAM_get_depth(const X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_get_auth_level(const X509_VERIFY_PARAM *param);
const char *X509_VERIFY_PARAM_get0_name(const X509_VERIFY_PARAM *param);

int X509_VERIFY_PARAM_add0_table(X509_VERIFY_PARAM *param);
int X509_VERIFY_PARAM_get_count(void);
const X509_VERIFY_PARAM *X509_VERIFY_PARAM_get0(int id);
const X509_VERIFY_PARAM *X509_VERIFY_PARAM_lookup(const char *name);
void X509_VERIFY_PARAM_table_cleanup(void);

/* Non positive return values are errors */
#define X509_PCY_TREE_FAILURE  -2 /* Failure to satisfy explicit policy */
#define X509_PCY_TREE_INVALID  -1 /* Inconsistent or invalid extensions */
#define X509_PCY_TREE_INTERNAL  0 /* Internal error, most likely malloc */

/*
 * Positive return values form a bit mask, all but the first are internal to
 * the library and don't appear in results from X509_policy_check().
 */
#define X509_PCY_TREE_VALID     1 /* The policy tree is valid */
#define X509_PCY_TREE_EMPTY     2 /* The policy tree is empty */
#define X509_PCY_TREE_EXPLICIT  4 /* Explicit policy required */

int X509_policy_check(X509_POLICY_TREE **ptree, int *pexplicit_policy,
                      STACK_OF(X509) *certs,
                      STACK_OF(ASN1_OBJECT) *policy_oids, unsigned int flags);

void X509_policy_tree_free(X509_POLICY_TREE *tree);

int X509_policy_tree_level_count(const X509_POLICY_TREE *tree);
X509_POLICY_LEVEL *X509_policy_tree_get0_level(const X509_POLICY_TREE *tree,
                                               int i);

STACK_OF(X509_POLICY_NODE)
    *X509_policy_tree_get0_policies(const X509_POLICY_TREE *tree);

STACK_OF(X509_POLICY_NODE)
    *X509_policy_tree_get0_user_policies(const X509_POLICY_TREE *tree);

int X509_policy_level_node_count(X509_POLICY_LEVEL *level);

X509_POLICY_NODE *X509_policy_level_get0_node(const X509_POLICY_LEVEL *level,
                                              int i);

const ASN1_OBJECT *X509_policy_node_get0_policy(const X509_POLICY_NODE *node);

STACK_OF(POLICYQUALINFO)
    *X509_policy_node_get0_qualifiers(const X509_POLICY_NODE *node);
const X509_POLICY_NODE
    *X509_policy_node_get0_parent(const X509_POLICY_NODE *node);

#ifdef  __cplusplus
}
#endif
#endif
