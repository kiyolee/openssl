/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
/*
 * Generated from asn1.h.in for https://github.com/kiyolee/openssl.git.
 */



#ifndef OPENSSL_ASN1_H
# define OPENSSL_ASN1_H
# pragma once

# include <openssl/macros.h>
# ifndef OPENSSL_NO_DEPRECATED_3_0
#  define HEADER_ASN1_H
# endif

# ifndef OPENSSL_NO_STDIO
#  include <stdio.h>
# endif
# include <time.h>
# include <openssl/e_os2.h>
# include <openssl/opensslconf.h>
# include <openssl/bio.h>
# include <openssl/safestack.h>
# include <openssl/asn1err.h>
# include <openssl/symhacks.h>

# include <openssl/types.h>
# include <openssl/bn.h>

# ifdef OPENSSL_BUILD_SHLIBCRYPTO
#  undef OPENSSL_EXTERN
#  define OPENSSL_EXTERN OPENSSL_EXPORT
# endif

#ifdef  __cplusplus
extern "C" {
#endif

# define V_ASN1_UNIVERSAL                0x00
# define V_ASN1_APPLICATION              0x40
# define V_ASN1_CONTEXT_SPECIFIC         0x80
# define V_ASN1_PRIVATE                  0xc0

# define V_ASN1_CONSTRUCTED              0x20
# define V_ASN1_PRIMITIVE_TAG            0x1f
# define V_ASN1_PRIMATIVE_TAG /*compat*/ V_ASN1_PRIMITIVE_TAG

# define V_ASN1_APP_CHOOSE               -2/* let the recipient choose */
# define V_ASN1_OTHER                    -3/* used in ASN1_TYPE */
# define V_ASN1_ANY                      -4/* used in ASN1 template code */

# define V_ASN1_UNDEF                    -1
/* ASN.1 tag values */
# define V_ASN1_EOC                      0
# define V_ASN1_BOOLEAN                  1 /**/
# define V_ASN1_INTEGER                  2
# define V_ASN1_BIT_STRING               3
# define V_ASN1_OCTET_STRING             4
# define V_ASN1_NULL                     5
# define V_ASN1_OBJECT                   6
# define V_ASN1_OBJECT_DESCRIPTOR        7
# define V_ASN1_EXTERNAL                 8
# define V_ASN1_REAL                     9
# define V_ASN1_ENUMERATED               10
# define V_ASN1_UTF8STRING               12
# define V_ASN1_SEQUENCE                 16
# define V_ASN1_SET                      17
# define V_ASN1_NUMERICSTRING            18 /**/
# define V_ASN1_PRINTABLESTRING          19
# define V_ASN1_T61STRING                20
# define V_ASN1_TELETEXSTRING            20/* alias */
# define V_ASN1_VIDEOTEXSTRING           21 /**/
# define V_ASN1_IA5STRING                22
# define V_ASN1_UTCTIME                  23
# define V_ASN1_GENERALIZEDTIME          24 /**/
# define V_ASN1_GRAPHICSTRING            25 /**/
# define V_ASN1_ISO64STRING              26 /**/
# define V_ASN1_VISIBLESTRING            26/* alias */
# define V_ASN1_GENERALSTRING            27 /**/
# define V_ASN1_UNIVERSALSTRING          28 /**/
# define V_ASN1_BMPSTRING                30

/*
 * NB the constants below are used internally by ASN1_INTEGER
 * and ASN1_ENUMERATED to indicate the sign. They are *not* on
 * the wire tag values.
 */

# define V_ASN1_NEG                      0x100
# define V_ASN1_NEG_INTEGER              (2 | V_ASN1_NEG)
# define V_ASN1_NEG_ENUMERATED           (10 | V_ASN1_NEG)

/* For use with d2i_ASN1_type_bytes() */
# define B_ASN1_NUMERICSTRING    0x0001
# define B_ASN1_PRINTABLESTRING  0x0002
# define B_ASN1_T61STRING        0x0004
# define B_ASN1_TELETEXSTRING    0x0004
# define B_ASN1_VIDEOTEXSTRING   0x0008
# define B_ASN1_IA5STRING        0x0010
# define B_ASN1_GRAPHICSTRING    0x0020
# define B_ASN1_ISO64STRING      0x0040
# define B_ASN1_VISIBLESTRING    0x0040
# define B_ASN1_GENERALSTRING    0x0080
# define B_ASN1_UNIVERSALSTRING  0x0100
# define B_ASN1_OCTET_STRING     0x0200
# define B_ASN1_BIT_STRING       0x0400
# define B_ASN1_BMPSTRING        0x0800
# define B_ASN1_UNKNOWN          0x1000
# define B_ASN1_UTF8STRING       0x2000
# define B_ASN1_UTCTIME          0x4000
# define B_ASN1_GENERALIZEDTIME  0x8000
# define B_ASN1_SEQUENCE         0x10000
/* For use with ASN1_mbstring_copy() */
# define MBSTRING_FLAG           0x1000
# define MBSTRING_UTF8           (MBSTRING_FLAG)
# define MBSTRING_ASC            (MBSTRING_FLAG|1)
# define MBSTRING_BMP            (MBSTRING_FLAG|2)
# define MBSTRING_UNIV           (MBSTRING_FLAG|4)
# define SMIME_OLDMIME           0x400
# define SMIME_CRLFEOL           0x800
# define SMIME_STREAM            0x1000

/* Stacks for types not otherwise defined in this header */
SKM_DEFINE_STACK_OF_INTERNAL(X509_ALGOR, X509_ALGOR, X509_ALGOR)
#define sk_X509_ALGOR_num(sk) OPENSSL_sk_num(ossl_check_const_X509_ALGOR_sk_type(sk))
#define sk_X509_ALGOR_value(sk, idx) ((X509_ALGOR *)OPENSSL_sk_value(ossl_check_const_X509_ALGOR_sk_type(sk), (idx)))
#define sk_X509_ALGOR_new(cmp) ((STACK_OF(X509_ALGOR) *)OPENSSL_sk_new(ossl_check_X509_ALGOR_compfunc_type(cmp)))
#define sk_X509_ALGOR_new_null() ((STACK_OF(X509_ALGOR) *)OPENSSL_sk_new_null())
#define sk_X509_ALGOR_new_reserve(cmp, n) ((STACK_OF(X509_ALGOR) *)OPENSSL_sk_new_reserve(ossl_check_X509_ALGOR_compfunc_type(cmp), (n)))
#define sk_X509_ALGOR_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_X509_ALGOR_sk_type(sk), (n))
#define sk_X509_ALGOR_free(sk) OPENSSL_sk_free(ossl_check_X509_ALGOR_sk_type(sk))
#define sk_X509_ALGOR_zero(sk) OPENSSL_sk_zero(ossl_check_X509_ALGOR_sk_type(sk))
#define sk_X509_ALGOR_delete(sk, i) ((X509_ALGOR *)OPENSSL_sk_delete(ossl_check_X509_ALGOR_sk_type(sk), (i)))
#define sk_X509_ALGOR_delete_ptr(sk, ptr) ((X509_ALGOR *)OPENSSL_sk_delete_ptr(ossl_check_X509_ALGOR_sk_type(sk), ossl_check_X509_ALGOR_type(ptr)))
#define sk_X509_ALGOR_push(sk, ptr) OPENSSL_sk_push(ossl_check_X509_ALGOR_sk_type(sk), ossl_check_X509_ALGOR_type(ptr))
#define sk_X509_ALGOR_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_X509_ALGOR_sk_type(sk), ossl_check_X509_ALGOR_type(ptr))
#define sk_X509_ALGOR_pop(sk) ((X509_ALGOR *)OPENSSL_sk_pop(ossl_check_X509_ALGOR_sk_type(sk)))
#define sk_X509_ALGOR_shift(sk) ((X509_ALGOR *)OPENSSL_sk_shift(ossl_check_X509_ALGOR_sk_type(sk)))
#define sk_X509_ALGOR_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_X509_ALGOR_sk_type(sk),ossl_check_X509_ALGOR_freefunc_type(freefunc))
#define sk_X509_ALGOR_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_X509_ALGOR_sk_type(sk), ossl_check_X509_ALGOR_type(ptr), (idx))
#define sk_X509_ALGOR_set(sk, idx, ptr) ((X509_ALGOR *)OPENSSL_sk_set(ossl_check_X509_ALGOR_sk_type(sk), (idx), ossl_check_X509_ALGOR_type(ptr)))
#define sk_X509_ALGOR_find(sk, ptr) OPENSSL_sk_find(ossl_check_X509_ALGOR_sk_type(sk), ossl_check_X509_ALGOR_type(ptr))
#define sk_X509_ALGOR_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_X509_ALGOR_sk_type(sk), ossl_check_X509_ALGOR_type(ptr))
#define sk_X509_ALGOR_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_X509_ALGOR_sk_type(sk), ossl_check_X509_ALGOR_type(ptr), pnum)
#define sk_X509_ALGOR_sort(sk) OPENSSL_sk_sort(ossl_check_X509_ALGOR_sk_type(sk))
#define sk_X509_ALGOR_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_X509_ALGOR_sk_type(sk))
#define sk_X509_ALGOR_dup(sk) ((STACK_OF(X509_ALGOR) *)OPENSSL_sk_dup(ossl_check_const_X509_ALGOR_sk_type(sk)))
#define sk_X509_ALGOR_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(X509_ALGOR) *)OPENSSL_sk_deep_copy(ossl_check_const_X509_ALGOR_sk_type(sk), ossl_check_X509_ALGOR_copyfunc_type(copyfunc), ossl_check_X509_ALGOR_freefunc_type(freefunc)))
#define sk_X509_ALGOR_set_cmp_func(sk, cmp) ((sk_X509_ALGOR_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_X509_ALGOR_sk_type(sk), ossl_check_X509_ALGOR_compfunc_type(cmp)))



# define ASN1_STRING_FLAG_BITS_LEFT 0x08 /* Set if 0x07 has bits left value */
/*
 * This indicates that the ASN1_STRING is not a real value but just a place
 * holder for the location where indefinite length constructed data should be
 * inserted in the memory buffer
 */
# define ASN1_STRING_FLAG_NDEF 0x010

/*
 * This flag is used by the CMS code to indicate that a string is not
 * complete and is a place holder for content when it had all been accessed.
 * The flag will be reset when content has been written to it.
 */

# define ASN1_STRING_FLAG_CONT 0x020
/*
 * This flag is used by ASN1 code to indicate an ASN1_STRING is an MSTRING
 * type.
 */
# define ASN1_STRING_FLAG_MSTRING 0x040
/* String is embedded and only content should be freed */
# define ASN1_STRING_FLAG_EMBED 0x080
/* String should be parsed in RFC 5280's time format */
# define ASN1_STRING_FLAG_X509_TIME 0x100
/* This is the base type that holds just about everything :-) */
struct asn1_string_st {
    int length;
    int type;
    unsigned char *data;
    /*
     * The value of the following field depends on the type being held.  It
     * is mostly being used for BIT_STRING so if the input data has a
     * non-zero 'unused bits' value, it will be handled correctly
     */
    long flags;
};

/*
 * ASN1_ENCODING structure: this is used to save the received encoding of an
 * ASN1 type. This is useful to get round problems with invalid encodings
 * which can break signatures.
 */

typedef struct ASN1_ENCODING_st {
    unsigned char *enc;         /* DER encoding */
    long len;                   /* Length of encoding */
    int modified;               /* set to 1 if 'enc' is invalid */
} ASN1_ENCODING;

/* Used with ASN1 LONG type: if a long is set to this it is omitted */
# define ASN1_LONG_UNDEF 0x7fffffffL

# define STABLE_FLAGS_MALLOC     0x01
/*
 * A zero passed to ASN1_STRING_TABLE_new_add for the flags is interpreted
 * as "don't change" and STABLE_FLAGS_MALLOC is always set. By setting
 * STABLE_FLAGS_MALLOC only we can clear the existing value. Use the alias
 * STABLE_FLAGS_CLEAR to reflect this.
 */
# define STABLE_FLAGS_CLEAR      STABLE_FLAGS_MALLOC
# define STABLE_NO_MASK          0x02
# define DIRSTRING_TYPE  \
 (B_ASN1_PRINTABLESTRING|B_ASN1_T61STRING|B_ASN1_BMPSTRING|B_ASN1_UTF8STRING)
# define PKCS9STRING_TYPE (DIRSTRING_TYPE|B_ASN1_IA5STRING)

struct asn1_string_table_st {
    int nid;
    long minsize;
    long maxsize;
    unsigned long mask;
    unsigned long flags;
};

SKM_DEFINE_STACK_OF_INTERNAL(ASN1_STRING_TABLE, ASN1_STRING_TABLE, ASN1_STRING_TABLE)
#define sk_ASN1_STRING_TABLE_num(sk) OPENSSL_sk_num(ossl_check_const_ASN1_STRING_TABLE_sk_type(sk))
#define sk_ASN1_STRING_TABLE_value(sk, idx) ((ASN1_STRING_TABLE *)OPENSSL_sk_value(ossl_check_const_ASN1_STRING_TABLE_sk_type(sk), (idx)))
#define sk_ASN1_STRING_TABLE_new(cmp) ((STACK_OF(ASN1_STRING_TABLE) *)OPENSSL_sk_new(ossl_check_ASN1_STRING_TABLE_compfunc_type(cmp)))
#define sk_ASN1_STRING_TABLE_new_null() ((STACK_OF(ASN1_STRING_TABLE) *)OPENSSL_sk_new_null())
#define sk_ASN1_STRING_TABLE_new_reserve(cmp, n) ((STACK_OF(ASN1_STRING_TABLE) *)OPENSSL_sk_new_reserve(ossl_check_ASN1_STRING_TABLE_compfunc_type(cmp), (n)))
#define sk_ASN1_STRING_TABLE_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_ASN1_STRING_TABLE_sk_type(sk), (n))
#define sk_ASN1_STRING_TABLE_free(sk) OPENSSL_sk_free(ossl_check_ASN1_STRING_TABLE_sk_type(sk))
#define sk_ASN1_STRING_TABLE_zero(sk) OPENSSL_sk_zero(ossl_check_ASN1_STRING_TABLE_sk_type(sk))
#define sk_ASN1_STRING_TABLE_delete(sk, i) ((ASN1_STRING_TABLE *)OPENSSL_sk_delete(ossl_check_ASN1_STRING_TABLE_sk_type(sk), (i)))
#define sk_ASN1_STRING_TABLE_delete_ptr(sk, ptr) ((ASN1_STRING_TABLE *)OPENSSL_sk_delete_ptr(ossl_check_ASN1_STRING_TABLE_sk_type(sk), ossl_check_ASN1_STRING_TABLE_type(ptr)))
#define sk_ASN1_STRING_TABLE_push(sk, ptr) OPENSSL_sk_push(ossl_check_ASN1_STRING_TABLE_sk_type(sk), ossl_check_ASN1_STRING_TABLE_type(ptr))
#define sk_ASN1_STRING_TABLE_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_ASN1_STRING_TABLE_sk_type(sk), ossl_check_ASN1_STRING_TABLE_type(ptr))
#define sk_ASN1_STRING_TABLE_pop(sk) ((ASN1_STRING_TABLE *)OPENSSL_sk_pop(ossl_check_ASN1_STRING_TABLE_sk_type(sk)))
#define sk_ASN1_STRING_TABLE_shift(sk) ((ASN1_STRING_TABLE *)OPENSSL_sk_shift(ossl_check_ASN1_STRING_TABLE_sk_type(sk)))
#define sk_ASN1_STRING_TABLE_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_ASN1_STRING_TABLE_sk_type(sk),ossl_check_ASN1_STRING_TABLE_freefunc_type(freefunc))
#define sk_ASN1_STRING_TABLE_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_ASN1_STRING_TABLE_sk_type(sk), ossl_check_ASN1_STRING_TABLE_type(ptr), (idx))
#define sk_ASN1_STRING_TABLE_set(sk, idx, ptr) ((ASN1_STRING_TABLE *)OPENSSL_sk_set(ossl_check_ASN1_STRING_TABLE_sk_type(sk), (idx), ossl_check_ASN1_STRING_TABLE_type(ptr)))
#define sk_ASN1_STRING_TABLE_find(sk, ptr) OPENSSL_sk_find(ossl_check_ASN1_STRING_TABLE_sk_type(sk), ossl_check_ASN1_STRING_TABLE_type(ptr))
#define sk_ASN1_STRING_TABLE_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_ASN1_STRING_TABLE_sk_type(sk), ossl_check_ASN1_STRING_TABLE_type(ptr))
#define sk_ASN1_STRING_TABLE_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_ASN1_STRING_TABLE_sk_type(sk), ossl_check_ASN1_STRING_TABLE_type(ptr), pnum)
#define sk_ASN1_STRING_TABLE_sort(sk) OPENSSL_sk_sort(ossl_check_ASN1_STRING_TABLE_sk_type(sk))
#define sk_ASN1_STRING_TABLE_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_ASN1_STRING_TABLE_sk_type(sk))
#define sk_ASN1_STRING_TABLE_dup(sk) ((STACK_OF(ASN1_STRING_TABLE) *)OPENSSL_sk_dup(ossl_check_const_ASN1_STRING_TABLE_sk_type(sk)))
#define sk_ASN1_STRING_TABLE_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(ASN1_STRING_TABLE) *)OPENSSL_sk_deep_copy(ossl_check_const_ASN1_STRING_TABLE_sk_type(sk), ossl_check_ASN1_STRING_TABLE_copyfunc_type(copyfunc), ossl_check_ASN1_STRING_TABLE_freefunc_type(freefunc)))
#define sk_ASN1_STRING_TABLE_set_cmp_func(sk, cmp) ((sk_ASN1_STRING_TABLE_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_ASN1_STRING_TABLE_sk_type(sk), ossl_check_ASN1_STRING_TABLE_compfunc_type(cmp)))


/* size limits: this stuff is taken straight from RFC2459 */

# define ub_name                         32768
# define ub_common_name                  64
# define ub_locality_name                128
# define ub_state_name                   128
# define ub_organization_name            64
# define ub_organization_unit_name       64
# define ub_title                        64
# define ub_email_address                128

/*
 * Declarations for template structures: for full definitions see asn1t.h
 */
typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
typedef struct ASN1_TLC_st ASN1_TLC;
/* This is just an opaque pointer */
typedef struct ASN1_VALUE_st ASN1_VALUE;

/* Declare ASN1 functions: the implement macro in in asn1t.h */

/*
 * The mysterious 'extern' that's passed to some macros is innocuous,
 * and is there to quiet pre-C99 compilers that may complain about empty
 * arguments in macro calls.
 */

# define DECLARE_ASN1_FUNCTIONS_attr(attr, type)                            \
    DECLARE_ASN1_FUNCTIONS_name_attr(attr, type, type)
# define DECLARE_ASN1_FUNCTIONS(type)                                       \
    DECLARE_ASN1_FUNCTIONS_attr(extern, type)

# define DECLARE_ASN1_ALLOC_FUNCTIONS_attr(attr, type)                      \
    DECLARE_ASN1_ALLOC_FUNCTIONS_name_attr(attr, type, type)
# define DECLARE_ASN1_ALLOC_FUNCTIONS(type)                                 \
    DECLARE_ASN1_ALLOC_FUNCTIONS_attr(extern, type)

# define DECLARE_ASN1_FUNCTIONS_name_attr(attr, type, name)                 \
    DECLARE_ASN1_ALLOC_FUNCTIONS_name_attr(attr, type, name)                \
    DECLARE_ASN1_ENCODE_FUNCTIONS_name_attr(attr, type, name)
# define DECLARE_ASN1_FUNCTIONS_name(type, name)                            \
    DECLARE_ASN1_FUNCTIONS_name_attr(extern, type, name)

# define DECLARE_ASN1_ENCODE_FUNCTIONS_attr(attr, type, itname, name)       \
    DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(attr, type, name)               \
    DECLARE_ASN1_ITEM_attr(attr, itname)
# define DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name)                  \
    DECLARE_ASN1_ENCODE_FUNCTIONS_attr(extern, type, itname, name)

# define DECLARE_ASN1_ENCODE_FUNCTIONS_name_attr(attr, type, name)          \
    DECLARE_ASN1_ENCODE_FUNCTIONS_attr(attr, type, name, name)
# define DECLARE_ASN1_ENCODE_FUNCTIONS_name(type, name) \
    DECLARE_ASN1_ENCODE_FUNCTIONS_name_attr(extern, type, name)

# define DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(attr, type, name)          \
    attr type *d2i_##name(type **a, const unsigned char **in, long len);    \
    attr int i2d_##name(const type *a, unsigned char **out);
# define DECLARE_ASN1_ENCODE_FUNCTIONS_only(type, name)                     \
    DECLARE_ASN1_ENCODE_FUNCTIONS_only_attr(extern, type, name)

# define DECLARE_ASN1_NDEF_FUNCTION_attr(attr, name)                        \
    attr int i2d_##name##_NDEF(const name *a, unsigned char **out);
# define DECLARE_ASN1_NDEF_FUNCTION(name)                                   \
    DECLARE_ASN1_NDEF_FUNCTION_attr(extern, name)

# define DECLARE_ASN1_ALLOC_FUNCTIONS_name_attr(attr, type, name)           \
    attr type *name##_new(void);                                            \
    attr void name##_free(type *a);
# define DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name)                      \
    DECLARE_ASN1_ALLOC_FUNCTIONS_name_attr(extern, type, name)

# define DECLARE_ASN1_DUP_FUNCTION_attr(attr, type)                         \
    DECLARE_ASN1_DUP_FUNCTION_name_attr(attr, type, type)
# define DECLARE_ASN1_DUP_FUNCTION(type)                                    \
    DECLARE_ASN1_DUP_FUNCTION_attr(extern, type)

# define DECLARE_ASN1_DUP_FUNCTION_name_attr(attr, type, name)              \
    attr type *name##_dup(const type *a);
# define DECLARE_ASN1_DUP_FUNCTION_name(type, name)                         \
    DECLARE_ASN1_DUP_FUNCTION_name_attr(extern, type, name)

# define DECLARE_ASN1_PRINT_FUNCTION_attr(attr, stname)                     \
    DECLARE_ASN1_PRINT_FUNCTION_fname_attr(attr, stname, stname)
# define DECLARE_ASN1_PRINT_FUNCTION(stname)                                \
    DECLARE_ASN1_PRINT_FUNCTION_attr(extern, stname)

# define DECLARE_ASN1_PRINT_FUNCTION_fname_attr(attr, stname, fname)        \
    attr int fname##_print_ctx(BIO *out, const stname *x, int indent,       \
                               const ASN1_PCTX *pctx);
# define DECLARE_ASN1_PRINT_FUNCTION_fname(stname, fname)                   \
    DECLARE_ASN1_PRINT_FUNCTION_fname_attr(extern, stname, fname)

# define D2I_OF(type) type *(*)(type **,const unsigned char **,long)
# define I2D_OF(type) int (*)(const type *,unsigned char **)

# define CHECKED_D2I_OF(type, d2i) \
    ((d2i_of_void*) (1 ? d2i : ((D2I_OF(type))0)))
# define CHECKED_I2D_OF(type, i2d) \
    ((i2d_of_void*) (1 ? i2d : ((I2D_OF(type))0)))
# define CHECKED_NEW_OF(type, xnew) \
    ((void *(*)(void)) (1 ? xnew : ((type *(*)(void))0)))
# define CHECKED_PTR_OF(type, p) \
    ((void*) (1 ? p : (type*)0))
# define CHECKED_PPTR_OF(type, p) \
    ((void**) (1 ? p : (type**)0))

# define TYPEDEF_D2I_OF(type) typedef type *d2i_of_##type(type **,const unsigned char **,long)
# define TYPEDEF_I2D_OF(type) typedef int i2d_of_##type(const type *,unsigned char **)
# define TYPEDEF_D2I2D_OF(type) TYPEDEF_D2I_OF(type); TYPEDEF_I2D_OF(type)

typedef void *d2i_of_void(void **, const unsigned char **, long);
typedef int i2d_of_void(const void *, unsigned char **);

/*-
 * The following macros and typedefs allow an ASN1_ITEM
 * to be embedded in a structure and referenced. Since
 * the ASN1_ITEM pointers need to be globally accessible
 * (possibly from shared libraries) they may exist in
 * different forms. On platforms that support it the
 * ASN1_ITEM structure itself will be globally exported.
 * Other platforms will export a function that returns
 * an ASN1_ITEM pointer.
 *
 * To handle both cases transparently the macros below
 * should be used instead of hard coding an ASN1_ITEM
 * pointer in a structure.
 *
 * The structure will look like this:
 *
 * typedef struct SOMETHING_st {
 *      ...
 *      ASN1_ITEM_EXP *iptr;
 *      ...
 * } SOMETHING;
 *
 * It would be initialised as e.g.:
 *
 * SOMETHING somevar = {...,ASN1_ITEM_ref(X509),...};
 *
 * and the actual pointer extracted with:
 *
 * const ASN1_ITEM *it = ASN1_ITEM_ptr(somevar.iptr);
 *
 * Finally an ASN1_ITEM pointer can be extracted from an
 * appropriate reference with: ASN1_ITEM_rptr(X509). This
 * would be used when a function takes an ASN1_ITEM * argument.
 *
 */


/*
 * Platforms that can't easily handle shared global variables are declared as
 * functions returning ASN1_ITEM pointers.
 */

/* ASN1_ITEM pointer exported type */
typedef const ASN1_ITEM *ASN1_ITEM_EXP (void);

/* Macro to obtain ASN1_ITEM pointer from exported type */
# define ASN1_ITEM_ptr(iptr) (iptr())

/* Macro to include ASN1_ITEM pointer from base type */
# define ASN1_ITEM_ref(iptr) (iptr##_it)

# define ASN1_ITEM_rptr(ref) (ref##_it())

# define DECLARE_ASN1_ITEM_attr(attr, name)                                 \
    attr const ASN1_ITEM * name##_it(void);
# define DECLARE_ASN1_ITEM(name)                                            \
    DECLARE_ASN1_ITEM_attr(extern, name)

/* Parameters used by ASN1_STRING_print_ex() */

/*
 * These determine which characters to escape: RFC2253 special characters,
 * control characters and MSB set characters
 */

# define ASN1_STRFLGS_ESC_2253           1
# define ASN1_STRFLGS_ESC_CTRL           2
# define ASN1_STRFLGS_ESC_MSB            4

/* Lower 8 bits are reserved as an output type specifier */
# define ASN1_DTFLGS_TYPE_MASK    0x0FUL
# define ASN1_DTFLGS_RFC822       0x00UL
# define ASN1_DTFLGS_ISO8601      0x01UL

/*
 * This flag determines how we do escaping: normally RC2253 backslash only,
 * set this to use backslash and quote.
 */

# define ASN1_STRFLGS_ESC_QUOTE          8

/* These three flags are internal use only. */

/* Character is a valid PrintableString character */
# define CHARTYPE_PRINTABLESTRING        0x10
/* Character needs escaping if it is the first character */
# define CHARTYPE_FIRST_ESC_2253         0x20
/* Character needs escaping if it is the last character */
# define CHARTYPE_LAST_ESC_2253          0x40

/*
 * NB the internal flags are safely reused below by flags handled at the top
 * level.
 */

/*
 * If this is set we convert all character strings to UTF8 first
 */

# define ASN1_STRFLGS_UTF8_CONVERT       0x10

/*
 * If this is set we don't attempt to interpret content: just assume all
 * strings are 1 byte per character. This will produce some pretty odd
 * looking output!
 */

# define ASN1_STRFLGS_IGNORE_TYPE        0x20

/* If this is set we include the string type in the output */
# define ASN1_STRFLGS_SHOW_TYPE          0x40

/*
 * This determines which strings to display and which to 'dump' (hex dump of
 * content octets or DER encoding). We can only dump non character strings or
 * everything. If we don't dump 'unknown' they are interpreted as character
 * strings with 1 octet per character and are subject to the usual escaping
 * options.
 */

# define ASN1_STRFLGS_DUMP_ALL           0x80
# define ASN1_STRFLGS_DUMP_UNKNOWN       0x100

/*
 * These determine what 'dumping' does, we can dump the content octets or the
 * DER encoding: both use the RFC2253 #XXXXX notation.
 */

# define ASN1_STRFLGS_DUMP_DER           0x200

/*
 * This flag specifies that RC2254 escaping shall be performed.
 */
#define ASN1_STRFLGS_ESC_2254           0x400

/*
 * All the string flags consistent with RFC2253, escaping control characters
 * isn't essential in RFC2253 but it is advisable anyway.
 */

# define ASN1_STRFLGS_RFC2253    (ASN1_STRFLGS_ESC_2253 | \
                                ASN1_STRFLGS_ESC_CTRL | \
                                ASN1_STRFLGS_ESC_MSB | \
                                ASN1_STRFLGS_UTF8_CONVERT | \
                                ASN1_STRFLGS_DUMP_UNKNOWN | \
                                ASN1_STRFLGS_DUMP_DER)


struct asn1_type_st {
    int type;
    union {
        char *ptr;
        ASN1_BOOLEAN boolean;
        ASN1_STRING *asn1_string;
        ASN1_OBJECT *object;
        ASN1_INTEGER *integer;
        ASN1_ENUMERATED *enumerated;
        ASN1_BIT_STRING *bit_string;
        ASN1_OCTET_STRING *octet_string;
        ASN1_PRINTABLESTRING *printablestring;
        ASN1_T61STRING *t61string;
        ASN1_IA5STRING *ia5string;
        ASN1_GENERALSTRING *generalstring;
        ASN1_BMPSTRING *bmpstring;
        ASN1_UNIVERSALSTRING *universalstring;
        ASN1_UTCTIME *utctime;
        ASN1_GENERALIZEDTIME *generalizedtime;
        ASN1_VISIBLESTRING *visiblestring;
        ASN1_UTF8STRING *utf8string;
        /*
         * set and sequence are left complete and still contain the set or
         * sequence bytes
         */
        ASN1_STRING *set;
        ASN1_STRING *sequence;
        ASN1_VALUE *asn1_value;
    } value;
};

SKM_DEFINE_STACK_OF_INTERNAL(ASN1_TYPE, ASN1_TYPE, ASN1_TYPE)
#define sk_ASN1_TYPE_num(sk) OPENSSL_sk_num(ossl_check_const_ASN1_TYPE_sk_type(sk))
#define sk_ASN1_TYPE_value(sk, idx) ((ASN1_TYPE *)OPENSSL_sk_value(ossl_check_const_ASN1_TYPE_sk_type(sk), (idx)))
#define sk_ASN1_TYPE_new(cmp) ((STACK_OF(ASN1_TYPE) *)OPENSSL_sk_new(ossl_check_ASN1_TYPE_compfunc_type(cmp)))
#define sk_ASN1_TYPE_new_null() ((STACK_OF(ASN1_TYPE) *)OPENSSL_sk_new_null())
#define sk_ASN1_TYPE_new_reserve(cmp, n) ((STACK_OF(ASN1_TYPE) *)OPENSSL_sk_new_reserve(ossl_check_ASN1_TYPE_compfunc_type(cmp), (n)))
#define sk_ASN1_TYPE_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_ASN1_TYPE_sk_type(sk), (n))
#define sk_ASN1_TYPE_free(sk) OPENSSL_sk_free(ossl_check_ASN1_TYPE_sk_type(sk))
#define sk_ASN1_TYPE_zero(sk) OPENSSL_sk_zero(ossl_check_ASN1_TYPE_sk_type(sk))
#define sk_ASN1_TYPE_delete(sk, i) ((ASN1_TYPE *)OPENSSL_sk_delete(ossl_check_ASN1_TYPE_sk_type(sk), (i)))
#define sk_ASN1_TYPE_delete_ptr(sk, ptr) ((ASN1_TYPE *)OPENSSL_sk_delete_ptr(ossl_check_ASN1_TYPE_sk_type(sk), ossl_check_ASN1_TYPE_type(ptr)))
#define sk_ASN1_TYPE_push(sk, ptr) OPENSSL_sk_push(ossl_check_ASN1_TYPE_sk_type(sk), ossl_check_ASN1_TYPE_type(ptr))
#define sk_ASN1_TYPE_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_ASN1_TYPE_sk_type(sk), ossl_check_ASN1_TYPE_type(ptr))
#define sk_ASN1_TYPE_pop(sk) ((ASN1_TYPE *)OPENSSL_sk_pop(ossl_check_ASN1_TYPE_sk_type(sk)))
#define sk_ASN1_TYPE_shift(sk) ((ASN1_TYPE *)OPENSSL_sk_shift(ossl_check_ASN1_TYPE_sk_type(sk)))
#define sk_ASN1_TYPE_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_ASN1_TYPE_sk_type(sk),ossl_check_ASN1_TYPE_freefunc_type(freefunc))
#define sk_ASN1_TYPE_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_ASN1_TYPE_sk_type(sk), ossl_check_ASN1_TYPE_type(ptr), (idx))
#define sk_ASN1_TYPE_set(sk, idx, ptr) ((ASN1_TYPE *)OPENSSL_sk_set(ossl_check_ASN1_TYPE_sk_type(sk), (idx), ossl_check_ASN1_TYPE_type(ptr)))
#define sk_ASN1_TYPE_find(sk, ptr) OPENSSL_sk_find(ossl_check_ASN1_TYPE_sk_type(sk), ossl_check_ASN1_TYPE_type(ptr))
#define sk_ASN1_TYPE_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_ASN1_TYPE_sk_type(sk), ossl_check_ASN1_TYPE_type(ptr))
#define sk_ASN1_TYPE_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_ASN1_TYPE_sk_type(sk), ossl_check_ASN1_TYPE_type(ptr), pnum)
#define sk_ASN1_TYPE_sort(sk) OPENSSL_sk_sort(ossl_check_ASN1_TYPE_sk_type(sk))
#define sk_ASN1_TYPE_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_ASN1_TYPE_sk_type(sk))
#define sk_ASN1_TYPE_dup(sk) ((STACK_OF(ASN1_TYPE) *)OPENSSL_sk_dup(ossl_check_const_ASN1_TYPE_sk_type(sk)))
#define sk_ASN1_TYPE_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(ASN1_TYPE) *)OPENSSL_sk_deep_copy(ossl_check_const_ASN1_TYPE_sk_type(sk), ossl_check_ASN1_TYPE_copyfunc_type(copyfunc), ossl_check_ASN1_TYPE_freefunc_type(freefunc)))
#define sk_ASN1_TYPE_set_cmp_func(sk, cmp) ((sk_ASN1_TYPE_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_ASN1_TYPE_sk_type(sk), ossl_check_ASN1_TYPE_compfunc_type(cmp)))


typedef STACK_OF(ASN1_TYPE) ASN1_SEQUENCE_ANY;

DECLARE_ASN1_ENCODE_FUNCTIONS_name(ASN1_SEQUENCE_ANY, ASN1_SEQUENCE_ANY)
DECLARE_ASN1_ENCODE_FUNCTIONS_name(ASN1_SEQUENCE_ANY, ASN1_SET_ANY)

/* This is used to contain a list of bit names */
typedef struct BIT_STRING_BITNAME_st {
    int bitnum;
    const char *lname;
    const char *sname;
} BIT_STRING_BITNAME;

# define B_ASN1_TIME \
                        B_ASN1_UTCTIME | \
                        B_ASN1_GENERALIZEDTIME

# define B_ASN1_PRINTABLE \
                        B_ASN1_NUMERICSTRING| \
                        B_ASN1_PRINTABLESTRING| \
                        B_ASN1_T61STRING| \
                        B_ASN1_IA5STRING| \
                        B_ASN1_BIT_STRING| \
                        B_ASN1_UNIVERSALSTRING|\
                        B_ASN1_BMPSTRING|\
                        B_ASN1_UTF8STRING|\
                        B_ASN1_SEQUENCE|\
                        B_ASN1_UNKNOWN

# define B_ASN1_DIRECTORYSTRING \
                        B_ASN1_PRINTABLESTRING| \
                        B_ASN1_TELETEXSTRING|\
                        B_ASN1_BMPSTRING|\
                        B_ASN1_UNIVERSALSTRING|\
                        B_ASN1_UTF8STRING

# define B_ASN1_DISPLAYTEXT \
                        B_ASN1_IA5STRING| \
                        B_ASN1_VISIBLESTRING| \
                        B_ASN1_BMPSTRING|\
                        B_ASN1_UTF8STRING

DECLARE_ASN1_ALLOC_FUNCTIONS_name(ASN1_TYPE, ASN1_TYPE)
DECLARE_ASN1_ENCODE_FUNCTIONS(ASN1_TYPE, ASN1_ANY, ASN1_TYPE)

int ASN1_TYPE_get(const ASN1_TYPE *a);
void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value);
int ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value);
int ASN1_TYPE_cmp(const ASN1_TYPE *a, const ASN1_TYPE *b);

ASN1_TYPE *ASN1_TYPE_pack_sequence(const ASN1_ITEM *it, void *s, ASN1_TYPE **t);
void *ASN1_TYPE_unpack_sequence(const ASN1_ITEM *it, const ASN1_TYPE *t);

SKM_DEFINE_STACK_OF_INTERNAL(ASN1_OBJECT, ASN1_OBJECT, ASN1_OBJECT)
#define sk_ASN1_OBJECT_num(sk) OPENSSL_sk_num(ossl_check_const_ASN1_OBJECT_sk_type(sk))
#define sk_ASN1_OBJECT_value(sk, idx) ((ASN1_OBJECT *)OPENSSL_sk_value(ossl_check_const_ASN1_OBJECT_sk_type(sk), (idx)))
#define sk_ASN1_OBJECT_new(cmp) ((STACK_OF(ASN1_OBJECT) *)OPENSSL_sk_new(ossl_check_ASN1_OBJECT_compfunc_type(cmp)))
#define sk_ASN1_OBJECT_new_null() ((STACK_OF(ASN1_OBJECT) *)OPENSSL_sk_new_null())
#define sk_ASN1_OBJECT_new_reserve(cmp, n) ((STACK_OF(ASN1_OBJECT) *)OPENSSL_sk_new_reserve(ossl_check_ASN1_OBJECT_compfunc_type(cmp), (n)))
#define sk_ASN1_OBJECT_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_ASN1_OBJECT_sk_type(sk), (n))
#define sk_ASN1_OBJECT_free(sk) OPENSSL_sk_free(ossl_check_ASN1_OBJECT_sk_type(sk))
#define sk_ASN1_OBJECT_zero(sk) OPENSSL_sk_zero(ossl_check_ASN1_OBJECT_sk_type(sk))
#define sk_ASN1_OBJECT_delete(sk, i) ((ASN1_OBJECT *)OPENSSL_sk_delete(ossl_check_ASN1_OBJECT_sk_type(sk), (i)))
#define sk_ASN1_OBJECT_delete_ptr(sk, ptr) ((ASN1_OBJECT *)OPENSSL_sk_delete_ptr(ossl_check_ASN1_OBJECT_sk_type(sk), ossl_check_ASN1_OBJECT_type(ptr)))
#define sk_ASN1_OBJECT_push(sk, ptr) OPENSSL_sk_push(ossl_check_ASN1_OBJECT_sk_type(sk), ossl_check_ASN1_OBJECT_type(ptr))
#define sk_ASN1_OBJECT_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_ASN1_OBJECT_sk_type(sk), ossl_check_ASN1_OBJECT_type(ptr))
#define sk_ASN1_OBJECT_pop(sk) ((ASN1_OBJECT *)OPENSSL_sk_pop(ossl_check_ASN1_OBJECT_sk_type(sk)))
#define sk_ASN1_OBJECT_shift(sk) ((ASN1_OBJECT *)OPENSSL_sk_shift(ossl_check_ASN1_OBJECT_sk_type(sk)))
#define sk_ASN1_OBJECT_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_ASN1_OBJECT_sk_type(sk),ossl_check_ASN1_OBJECT_freefunc_type(freefunc))
#define sk_ASN1_OBJECT_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_ASN1_OBJECT_sk_type(sk), ossl_check_ASN1_OBJECT_type(ptr), (idx))
#define sk_ASN1_OBJECT_set(sk, idx, ptr) ((ASN1_OBJECT *)OPENSSL_sk_set(ossl_check_ASN1_OBJECT_sk_type(sk), (idx), ossl_check_ASN1_OBJECT_type(ptr)))
#define sk_ASN1_OBJECT_find(sk, ptr) OPENSSL_sk_find(ossl_check_ASN1_OBJECT_sk_type(sk), ossl_check_ASN1_OBJECT_type(ptr))
#define sk_ASN1_OBJECT_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_ASN1_OBJECT_sk_type(sk), ossl_check_ASN1_OBJECT_type(ptr))
#define sk_ASN1_OBJECT_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_ASN1_OBJECT_sk_type(sk), ossl_check_ASN1_OBJECT_type(ptr), pnum)
#define sk_ASN1_OBJECT_sort(sk) OPENSSL_sk_sort(ossl_check_ASN1_OBJECT_sk_type(sk))
#define sk_ASN1_OBJECT_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_ASN1_OBJECT_sk_type(sk))
#define sk_ASN1_OBJECT_dup(sk) ((STACK_OF(ASN1_OBJECT) *)OPENSSL_sk_dup(ossl_check_const_ASN1_OBJECT_sk_type(sk)))
#define sk_ASN1_OBJECT_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(ASN1_OBJECT) *)OPENSSL_sk_deep_copy(ossl_check_const_ASN1_OBJECT_sk_type(sk), ossl_check_ASN1_OBJECT_copyfunc_type(copyfunc), ossl_check_ASN1_OBJECT_freefunc_type(freefunc)))
#define sk_ASN1_OBJECT_set_cmp_func(sk, cmp) ((sk_ASN1_OBJECT_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_ASN1_OBJECT_sk_type(sk), ossl_check_ASN1_OBJECT_compfunc_type(cmp)))


DECLARE_ASN1_FUNCTIONS(ASN1_OBJECT)

ASN1_STRING *ASN1_STRING_new(void);
void ASN1_STRING_free(ASN1_STRING *a);
void ASN1_STRING_clear_free(ASN1_STRING *a);
int ASN1_STRING_copy(ASN1_STRING *dst, const ASN1_STRING *str);
DECLARE_ASN1_DUP_FUNCTION(ASN1_STRING)
ASN1_STRING *ASN1_STRING_type_new(int type);
int ASN1_STRING_cmp(const ASN1_STRING *a, const ASN1_STRING *b);
  /*
   * Since this is used to store all sorts of things, via macros, for now,
   * make its data void *
   */
int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
void ASN1_STRING_set0(ASN1_STRING *str, void *data, int len);
int ASN1_STRING_length(const ASN1_STRING *x);
# ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0 void ASN1_STRING_length_set(ASN1_STRING *x, int n);
# endif
int ASN1_STRING_type(const ASN1_STRING *x);
# ifndef OPENSSL_NO_DEPRECATED_1_1_0
OSSL_DEPRECATEDIN_1_1_0 unsigned char *ASN1_STRING_data(ASN1_STRING *x);
# endif
const unsigned char *ASN1_STRING_get0_data(const ASN1_STRING *x);

DECLARE_ASN1_FUNCTIONS(ASN1_BIT_STRING)
int ASN1_BIT_STRING_set(ASN1_BIT_STRING *a, unsigned char *d, int length);
int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value);
int ASN1_BIT_STRING_get_bit(const ASN1_BIT_STRING *a, int n);
int ASN1_BIT_STRING_check(const ASN1_BIT_STRING *a,
                          const unsigned char *flags, int flags_len);

int ASN1_BIT_STRING_name_print(BIO *out, ASN1_BIT_STRING *bs,
                               BIT_STRING_BITNAME *tbl, int indent);
int ASN1_BIT_STRING_num_asc(const char *name, BIT_STRING_BITNAME *tbl);
int ASN1_BIT_STRING_set_asc(ASN1_BIT_STRING *bs, const char *name, int value,
                            BIT_STRING_BITNAME *tbl);

SKM_DEFINE_STACK_OF_INTERNAL(ASN1_INTEGER, ASN1_INTEGER, ASN1_INTEGER)
#define sk_ASN1_INTEGER_num(sk) OPENSSL_sk_num(ossl_check_const_ASN1_INTEGER_sk_type(sk))
#define sk_ASN1_INTEGER_value(sk, idx) ((ASN1_INTEGER *)OPENSSL_sk_value(ossl_check_const_ASN1_INTEGER_sk_type(sk), (idx)))
#define sk_ASN1_INTEGER_new(cmp) ((STACK_OF(ASN1_INTEGER) *)OPENSSL_sk_new(ossl_check_ASN1_INTEGER_compfunc_type(cmp)))
#define sk_ASN1_INTEGER_new_null() ((STACK_OF(ASN1_INTEGER) *)OPENSSL_sk_new_null())
#define sk_ASN1_INTEGER_new_reserve(cmp, n) ((STACK_OF(ASN1_INTEGER) *)OPENSSL_sk_new_reserve(ossl_check_ASN1_INTEGER_compfunc_type(cmp), (n)))
#define sk_ASN1_INTEGER_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_ASN1_INTEGER_sk_type(sk), (n))
#define sk_ASN1_INTEGER_free(sk) OPENSSL_sk_free(ossl_check_ASN1_INTEGER_sk_type(sk))
#define sk_ASN1_INTEGER_zero(sk) OPENSSL_sk_zero(ossl_check_ASN1_INTEGER_sk_type(sk))
#define sk_ASN1_INTEGER_delete(sk, i) ((ASN1_INTEGER *)OPENSSL_sk_delete(ossl_check_ASN1_INTEGER_sk_type(sk), (i)))
#define sk_ASN1_INTEGER_delete_ptr(sk, ptr) ((ASN1_INTEGER *)OPENSSL_sk_delete_ptr(ossl_check_ASN1_INTEGER_sk_type(sk), ossl_check_ASN1_INTEGER_type(ptr)))
#define sk_ASN1_INTEGER_push(sk, ptr) OPENSSL_sk_push(ossl_check_ASN1_INTEGER_sk_type(sk), ossl_check_ASN1_INTEGER_type(ptr))
#define sk_ASN1_INTEGER_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_ASN1_INTEGER_sk_type(sk), ossl_check_ASN1_INTEGER_type(ptr))
#define sk_ASN1_INTEGER_pop(sk) ((ASN1_INTEGER *)OPENSSL_sk_pop(ossl_check_ASN1_INTEGER_sk_type(sk)))
#define sk_ASN1_INTEGER_shift(sk) ((ASN1_INTEGER *)OPENSSL_sk_shift(ossl_check_ASN1_INTEGER_sk_type(sk)))
#define sk_ASN1_INTEGER_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_ASN1_INTEGER_sk_type(sk),ossl_check_ASN1_INTEGER_freefunc_type(freefunc))
#define sk_ASN1_INTEGER_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_ASN1_INTEGER_sk_type(sk), ossl_check_ASN1_INTEGER_type(ptr), (idx))
#define sk_ASN1_INTEGER_set(sk, idx, ptr) ((ASN1_INTEGER *)OPENSSL_sk_set(ossl_check_ASN1_INTEGER_sk_type(sk), (idx), ossl_check_ASN1_INTEGER_type(ptr)))
#define sk_ASN1_INTEGER_find(sk, ptr) OPENSSL_sk_find(ossl_check_ASN1_INTEGER_sk_type(sk), ossl_check_ASN1_INTEGER_type(ptr))
#define sk_ASN1_INTEGER_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_ASN1_INTEGER_sk_type(sk), ossl_check_ASN1_INTEGER_type(ptr))
#define sk_ASN1_INTEGER_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_ASN1_INTEGER_sk_type(sk), ossl_check_ASN1_INTEGER_type(ptr), pnum)
#define sk_ASN1_INTEGER_sort(sk) OPENSSL_sk_sort(ossl_check_ASN1_INTEGER_sk_type(sk))
#define sk_ASN1_INTEGER_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_ASN1_INTEGER_sk_type(sk))
#define sk_ASN1_INTEGER_dup(sk) ((STACK_OF(ASN1_INTEGER) *)OPENSSL_sk_dup(ossl_check_const_ASN1_INTEGER_sk_type(sk)))
#define sk_ASN1_INTEGER_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(ASN1_INTEGER) *)OPENSSL_sk_deep_copy(ossl_check_const_ASN1_INTEGER_sk_type(sk), ossl_check_ASN1_INTEGER_copyfunc_type(copyfunc), ossl_check_ASN1_INTEGER_freefunc_type(freefunc)))
#define sk_ASN1_INTEGER_set_cmp_func(sk, cmp) ((sk_ASN1_INTEGER_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_ASN1_INTEGER_sk_type(sk), ossl_check_ASN1_INTEGER_compfunc_type(cmp)))



DECLARE_ASN1_FUNCTIONS(ASN1_INTEGER)
ASN1_INTEGER *d2i_ASN1_UINTEGER(ASN1_INTEGER **a, const unsigned char **pp,
                                long length);
DECLARE_ASN1_DUP_FUNCTION(ASN1_INTEGER)
int ASN1_INTEGER_cmp(const ASN1_INTEGER *x, const ASN1_INTEGER *y);

DECLARE_ASN1_FUNCTIONS(ASN1_ENUMERATED)

int ASN1_UTCTIME_check(const ASN1_UTCTIME *a);
ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s, time_t t);
ASN1_UTCTIME *ASN1_UTCTIME_adj(ASN1_UTCTIME *s, time_t t,
                               int offset_day, long offset_sec);
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str);
int ASN1_UTCTIME_cmp_time_t(const ASN1_UTCTIME *s, time_t t);

int ASN1_GENERALIZEDTIME_check(const ASN1_GENERALIZEDTIME *a);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,
                                               time_t t);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_adj(ASN1_GENERALIZEDTIME *s,
                                               time_t t, int offset_day,
                                               long offset_sec);
int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str);

int ASN1_TIME_diff(int *pday, int *psec,
                   const ASN1_TIME *from, const ASN1_TIME *to);

DECLARE_ASN1_FUNCTIONS(ASN1_OCTET_STRING)
DECLARE_ASN1_DUP_FUNCTION(ASN1_OCTET_STRING)
int ASN1_OCTET_STRING_cmp(const ASN1_OCTET_STRING *a,
                          const ASN1_OCTET_STRING *b);
int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data,
                          int len);

SKM_DEFINE_STACK_OF_INTERNAL(ASN1_UTF8STRING, ASN1_UTF8STRING, ASN1_UTF8STRING)
#define sk_ASN1_UTF8STRING_num(sk) OPENSSL_sk_num(ossl_check_const_ASN1_UTF8STRING_sk_type(sk))
#define sk_ASN1_UTF8STRING_value(sk, idx) ((ASN1_UTF8STRING *)OPENSSL_sk_value(ossl_check_const_ASN1_UTF8STRING_sk_type(sk), (idx)))
#define sk_ASN1_UTF8STRING_new(cmp) ((STACK_OF(ASN1_UTF8STRING) *)OPENSSL_sk_new(ossl_check_ASN1_UTF8STRING_compfunc_type(cmp)))
#define sk_ASN1_UTF8STRING_new_null() ((STACK_OF(ASN1_UTF8STRING) *)OPENSSL_sk_new_null())
#define sk_ASN1_UTF8STRING_new_reserve(cmp, n) ((STACK_OF(ASN1_UTF8STRING) *)OPENSSL_sk_new_reserve(ossl_check_ASN1_UTF8STRING_compfunc_type(cmp), (n)))
#define sk_ASN1_UTF8STRING_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_ASN1_UTF8STRING_sk_type(sk), (n))
#define sk_ASN1_UTF8STRING_free(sk) OPENSSL_sk_free(ossl_check_ASN1_UTF8STRING_sk_type(sk))
#define sk_ASN1_UTF8STRING_zero(sk) OPENSSL_sk_zero(ossl_check_ASN1_UTF8STRING_sk_type(sk))
#define sk_ASN1_UTF8STRING_delete(sk, i) ((ASN1_UTF8STRING *)OPENSSL_sk_delete(ossl_check_ASN1_UTF8STRING_sk_type(sk), (i)))
#define sk_ASN1_UTF8STRING_delete_ptr(sk, ptr) ((ASN1_UTF8STRING *)OPENSSL_sk_delete_ptr(ossl_check_ASN1_UTF8STRING_sk_type(sk), ossl_check_ASN1_UTF8STRING_type(ptr)))
#define sk_ASN1_UTF8STRING_push(sk, ptr) OPENSSL_sk_push(ossl_check_ASN1_UTF8STRING_sk_type(sk), ossl_check_ASN1_UTF8STRING_type(ptr))
#define sk_ASN1_UTF8STRING_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_ASN1_UTF8STRING_sk_type(sk), ossl_check_ASN1_UTF8STRING_type(ptr))
#define sk_ASN1_UTF8STRING_pop(sk) ((ASN1_UTF8STRING *)OPENSSL_sk_pop(ossl_check_ASN1_UTF8STRING_sk_type(sk)))
#define sk_ASN1_UTF8STRING_shift(sk) ((ASN1_UTF8STRING *)OPENSSL_sk_shift(ossl_check_ASN1_UTF8STRING_sk_type(sk)))
#define sk_ASN1_UTF8STRING_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_ASN1_UTF8STRING_sk_type(sk),ossl_check_ASN1_UTF8STRING_freefunc_type(freefunc))
#define sk_ASN1_UTF8STRING_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_ASN1_UTF8STRING_sk_type(sk), ossl_check_ASN1_UTF8STRING_type(ptr), (idx))
#define sk_ASN1_UTF8STRING_set(sk, idx, ptr) ((ASN1_UTF8STRING *)OPENSSL_sk_set(ossl_check_ASN1_UTF8STRING_sk_type(sk), (idx), ossl_check_ASN1_UTF8STRING_type(ptr)))
#define sk_ASN1_UTF8STRING_find(sk, ptr) OPENSSL_sk_find(ossl_check_ASN1_UTF8STRING_sk_type(sk), ossl_check_ASN1_UTF8STRING_type(ptr))
#define sk_ASN1_UTF8STRING_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_ASN1_UTF8STRING_sk_type(sk), ossl_check_ASN1_UTF8STRING_type(ptr))
#define sk_ASN1_UTF8STRING_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_ASN1_UTF8STRING_sk_type(sk), ossl_check_ASN1_UTF8STRING_type(ptr), pnum)
#define sk_ASN1_UTF8STRING_sort(sk) OPENSSL_sk_sort(ossl_check_ASN1_UTF8STRING_sk_type(sk))
#define sk_ASN1_UTF8STRING_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_ASN1_UTF8STRING_sk_type(sk))
#define sk_ASN1_UTF8STRING_dup(sk) ((STACK_OF(ASN1_UTF8STRING) *)OPENSSL_sk_dup(ossl_check_const_ASN1_UTF8STRING_sk_type(sk)))
#define sk_ASN1_UTF8STRING_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(ASN1_UTF8STRING) *)OPENSSL_sk_deep_copy(ossl_check_const_ASN1_UTF8STRING_sk_type(sk), ossl_check_ASN1_UTF8STRING_copyfunc_type(copyfunc), ossl_check_ASN1_UTF8STRING_freefunc_type(freefunc)))
#define sk_ASN1_UTF8STRING_set_cmp_func(sk, cmp) ((sk_ASN1_UTF8STRING_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_ASN1_UTF8STRING_sk_type(sk), ossl_check_ASN1_UTF8STRING_compfunc_type(cmp)))


DECLARE_ASN1_FUNCTIONS(ASN1_VISIBLESTRING)
DECLARE_ASN1_FUNCTIONS(ASN1_UNIVERSALSTRING)
DECLARE_ASN1_FUNCTIONS(ASN1_UTF8STRING)
DECLARE_ASN1_FUNCTIONS(ASN1_NULL)
DECLARE_ASN1_FUNCTIONS(ASN1_BMPSTRING)

int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
int UTF8_putc(unsigned char *str, int len, unsigned long value);

SKM_DEFINE_STACK_OF_INTERNAL(ASN1_GENERALSTRING, ASN1_GENERALSTRING, ASN1_GENERALSTRING)
#define sk_ASN1_GENERALSTRING_num(sk) OPENSSL_sk_num(ossl_check_const_ASN1_GENERALSTRING_sk_type(sk))
#define sk_ASN1_GENERALSTRING_value(sk, idx) ((ASN1_GENERALSTRING *)OPENSSL_sk_value(ossl_check_const_ASN1_GENERALSTRING_sk_type(sk), (idx)))
#define sk_ASN1_GENERALSTRING_new(cmp) ((STACK_OF(ASN1_GENERALSTRING) *)OPENSSL_sk_new(ossl_check_ASN1_GENERALSTRING_compfunc_type(cmp)))
#define sk_ASN1_GENERALSTRING_new_null() ((STACK_OF(ASN1_GENERALSTRING) *)OPENSSL_sk_new_null())
#define sk_ASN1_GENERALSTRING_new_reserve(cmp, n) ((STACK_OF(ASN1_GENERALSTRING) *)OPENSSL_sk_new_reserve(ossl_check_ASN1_GENERALSTRING_compfunc_type(cmp), (n)))
#define sk_ASN1_GENERALSTRING_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_ASN1_GENERALSTRING_sk_type(sk), (n))
#define sk_ASN1_GENERALSTRING_free(sk) OPENSSL_sk_free(ossl_check_ASN1_GENERALSTRING_sk_type(sk))
#define sk_ASN1_GENERALSTRING_zero(sk) OPENSSL_sk_zero(ossl_check_ASN1_GENERALSTRING_sk_type(sk))
#define sk_ASN1_GENERALSTRING_delete(sk, i) ((ASN1_GENERALSTRING *)OPENSSL_sk_delete(ossl_check_ASN1_GENERALSTRING_sk_type(sk), (i)))
#define sk_ASN1_GENERALSTRING_delete_ptr(sk, ptr) ((ASN1_GENERALSTRING *)OPENSSL_sk_delete_ptr(ossl_check_ASN1_GENERALSTRING_sk_type(sk), ossl_check_ASN1_GENERALSTRING_type(ptr)))
#define sk_ASN1_GENERALSTRING_push(sk, ptr) OPENSSL_sk_push(ossl_check_ASN1_GENERALSTRING_sk_type(sk), ossl_check_ASN1_GENERALSTRING_type(ptr))
#define sk_ASN1_GENERALSTRING_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_ASN1_GENERALSTRING_sk_type(sk), ossl_check_ASN1_GENERALSTRING_type(ptr))
#define sk_ASN1_GENERALSTRING_pop(sk) ((ASN1_GENERALSTRING *)OPENSSL_sk_pop(ossl_check_ASN1_GENERALSTRING_sk_type(sk)))
#define sk_ASN1_GENERALSTRING_shift(sk) ((ASN1_GENERALSTRING *)OPENSSL_sk_shift(ossl_check_ASN1_GENERALSTRING_sk_type(sk)))
#define sk_ASN1_GENERALSTRING_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_ASN1_GENERALSTRING_sk_type(sk),ossl_check_ASN1_GENERALSTRING_freefunc_type(freefunc))
#define sk_ASN1_GENERALSTRING_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_ASN1_GENERALSTRING_sk_type(sk), ossl_check_ASN1_GENERALSTRING_type(ptr), (idx))
#define sk_ASN1_GENERALSTRING_set(sk, idx, ptr) ((ASN1_GENERALSTRING *)OPENSSL_sk_set(ossl_check_ASN1_GENERALSTRING_sk_type(sk), (idx), ossl_check_ASN1_GENERALSTRING_type(ptr)))
#define sk_ASN1_GENERALSTRING_find(sk, ptr) OPENSSL_sk_find(ossl_check_ASN1_GENERALSTRING_sk_type(sk), ossl_check_ASN1_GENERALSTRING_type(ptr))
#define sk_ASN1_GENERALSTRING_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_ASN1_GENERALSTRING_sk_type(sk), ossl_check_ASN1_GENERALSTRING_type(ptr))
#define sk_ASN1_GENERALSTRING_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_ASN1_GENERALSTRING_sk_type(sk), ossl_check_ASN1_GENERALSTRING_type(ptr), pnum)
#define sk_ASN1_GENERALSTRING_sort(sk) OPENSSL_sk_sort(ossl_check_ASN1_GENERALSTRING_sk_type(sk))
#define sk_ASN1_GENERALSTRING_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_ASN1_GENERALSTRING_sk_type(sk))
#define sk_ASN1_GENERALSTRING_dup(sk) ((STACK_OF(ASN1_GENERALSTRING) *)OPENSSL_sk_dup(ossl_check_const_ASN1_GENERALSTRING_sk_type(sk)))
#define sk_ASN1_GENERALSTRING_deep_copy(sk, copyfunc, freefunc) ((STACK_OF(ASN1_GENERALSTRING) *)OPENSSL_sk_deep_copy(ossl_check_const_ASN1_GENERALSTRING_sk_type(sk), ossl_check_ASN1_GENERALSTRING_copyfunc_type(copyfunc), ossl_check_ASN1_GENERALSTRING_freefunc_type(freefunc)))
#define sk_ASN1_GENERALSTRING_set_cmp_func(sk, cmp) ((sk_ASN1_GENERALSTRING_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_ASN1_GENERALSTRING_sk_type(sk), ossl_check_ASN1_GENERALSTRING_compfunc_type(cmp)))


DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, ASN1_PRINTABLE)

DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, DIRECTORYSTRING)
DECLARE_ASN1_FUNCTIONS_name(ASN1_STRING, DISPLAYTEXT)
DECLARE_ASN1_FUNCTIONS(ASN1_PRINTABLESTRING)
DECLARE_ASN1_FUNCTIONS(ASN1_T61STRING)
DECLARE_ASN1_FUNCTIONS(ASN1_IA5STRING)
DECLARE_ASN1_FUNCTIONS(ASN1_GENERALSTRING)
DECLARE_ASN1_FUNCTIONS(ASN1_UTCTIME)
DECLARE_ASN1_FUNCTIONS(ASN1_GENERALIZEDTIME)
DECLARE_ASN1_FUNCTIONS(ASN1_TIME)

DECLARE_ASN1_DUP_FUNCTION(ASN1_TIME)
DECLARE_ASN1_DUP_FUNCTION(ASN1_UTCTIME)
DECLARE_ASN1_DUP_FUNCTION(ASN1_GENERALIZEDTIME)

DECLARE_ASN1_ITEM(ASN1_OCTET_STRING_NDEF)

ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s, time_t t);
ASN1_TIME *ASN1_TIME_adj(ASN1_TIME *s, time_t t,
                         int offset_day, long offset_sec);
int ASN1_TIME_check(const ASN1_TIME *t);
ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(const ASN1_TIME *t,
                                                   ASN1_GENERALIZEDTIME **out);
int ASN1_TIME_set_string(ASN1_TIME *s, const char *str);
int ASN1_TIME_set_string_X509(ASN1_TIME *s, const char *str);
int ASN1_TIME_to_tm(const ASN1_TIME *s, struct tm *tm);
int ASN1_TIME_normalize(ASN1_TIME *s);
int ASN1_TIME_cmp_time_t(const ASN1_TIME *s, time_t t);
int ASN1_TIME_compare(const ASN1_TIME *a, const ASN1_TIME *b);

int i2a_ASN1_INTEGER(BIO *bp, const ASN1_INTEGER *a);
int a2i_ASN1_INTEGER(BIO *bp, ASN1_INTEGER *bs, char *buf, int size);
int i2a_ASN1_ENUMERATED(BIO *bp, const ASN1_ENUMERATED *a);
int a2i_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *bs, char *buf, int size);
int i2a_ASN1_OBJECT(BIO *bp, const ASN1_OBJECT *a);
int a2i_ASN1_STRING(BIO *bp, ASN1_STRING *bs, char *buf, int size);
int i2a_ASN1_STRING(BIO *bp, const ASN1_STRING *a, int type);
int i2t_ASN1_OBJECT(char *buf, int buf_len, const ASN1_OBJECT *a);

int a2d_ASN1_OBJECT(unsigned char *out, int olen, const char *buf, int num);
ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data, int len,
                                const char *sn, const char *ln);

int ASN1_INTEGER_get_int64(int64_t *pr, const ASN1_INTEGER *a);
int ASN1_INTEGER_set_int64(ASN1_INTEGER *a, int64_t r);
int ASN1_INTEGER_get_uint64(uint64_t *pr, const ASN1_INTEGER *a);
int ASN1_INTEGER_set_uint64(ASN1_INTEGER *a, uint64_t r);

int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
long ASN1_INTEGER_get(const ASN1_INTEGER *a);
ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn);

int ASN1_ENUMERATED_get_int64(int64_t *pr, const ASN1_ENUMERATED *a);
int ASN1_ENUMERATED_set_int64(ASN1_ENUMERATED *a, int64_t r);


int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v);
long ASN1_ENUMERATED_get(const ASN1_ENUMERATED *a);
ASN1_ENUMERATED *BN_to_ASN1_ENUMERATED(const BIGNUM *bn, ASN1_ENUMERATED *ai);
BIGNUM *ASN1_ENUMERATED_to_BN(const ASN1_ENUMERATED *ai, BIGNUM *bn);

/* General */
/* given a string, return the correct type, max is the maximum length */
int ASN1_PRINTABLE_type(const unsigned char *s, int max);

unsigned long ASN1_tag2bit(int tag);

/* SPECIALS */
int ASN1_get_object(const unsigned char **pp, long *plength, int *ptag,
                    int *pclass, long omax);
int ASN1_check_infinite_end(unsigned char **p, long len);
int ASN1_const_check_infinite_end(const unsigned char **p, long len);
void ASN1_put_object(unsigned char **pp, int constructed, int length,
                     int tag, int xclass);
int ASN1_put_eoc(unsigned char **pp);
int ASN1_object_size(int constructed, int length, int tag);

/* Used to implement other functions */
void *ASN1_dup(i2d_of_void *i2d, d2i_of_void *d2i, const void *x);

# define ASN1_dup_of(type,i2d,d2i,x) \
    ((type*)ASN1_dup(CHECKED_I2D_OF(type, i2d), \
                     CHECKED_D2I_OF(type, d2i), \
                     CHECKED_PTR_OF(const type, x)))

void *ASN1_item_dup(const ASN1_ITEM *it, const void *x);
int ASN1_item_sign_ex(const ASN1_ITEM *it, X509_ALGOR *algor1,
                      X509_ALGOR *algor2, ASN1_BIT_STRING *signature,
                      const void *data, const ASN1_OCTET_STRING *id,
                      EVP_PKEY *pkey, const EVP_MD *md, OSSL_LIB_CTX *libctx,
                      const char *propq);
int ASN1_item_verify_ex(const ASN1_ITEM *it, const X509_ALGOR *alg,
                        const ASN1_BIT_STRING *signature, const void *data,
                        const ASN1_OCTET_STRING *id, EVP_PKEY *pkey,
                        OSSL_LIB_CTX *libctx, const char *propq);

/* ASN1 alloc/free macros for when a type is only used internally */

# define M_ASN1_new_of(type) (type *)ASN1_item_new(ASN1_ITEM_rptr(type))
# define M_ASN1_free_of(x, type) \
                ASN1_item_free(CHECKED_PTR_OF(type, x), ASN1_ITEM_rptr(type))

# ifndef OPENSSL_NO_STDIO
void *ASN1_d2i_fp(void *(*xnew) (void), d2i_of_void *d2i, FILE *in, void **x);

#  define ASN1_d2i_fp_of(type,xnew,d2i,in,x) \
    ((type*)ASN1_d2i_fp(CHECKED_NEW_OF(type, xnew), \
                        CHECKED_D2I_OF(type, d2i), \
                        in, \
                        CHECKED_PPTR_OF(type, x)))

void *ASN1_item_d2i_fp_ex(const ASN1_ITEM *it, FILE *in, void *x,
                          OSSL_LIB_CTX *libctx, const char *propq);
void *ASN1_item_d2i_fp(const ASN1_ITEM *it, FILE *in, void *x);
int ASN1_i2d_fp(i2d_of_void *i2d, FILE *out, const void *x);

#  define ASN1_i2d_fp_of(type,i2d,out,x) \
    (ASN1_i2d_fp(CHECKED_I2D_OF(type, i2d), \
                 out, \
                 CHECKED_PTR_OF(const type, x)))

int ASN1_item_i2d_fp(const ASN1_ITEM *it, FILE *out, const void *x);
int ASN1_STRING_print_ex_fp(FILE *fp, const ASN1_STRING *str, unsigned long flags);
# endif

int ASN1_STRING_to_UTF8(unsigned char **out, const ASN1_STRING *in);

void *ASN1_d2i_bio(void *(*xnew) (void), d2i_of_void *d2i, BIO *in, void **x);

#  define ASN1_d2i_bio_of(type,xnew,d2i,in,x) \
    ((type*)ASN1_d2i_bio( CHECKED_NEW_OF(type, xnew), \
                          CHECKED_D2I_OF(type, d2i), \
                          in, \
                          CHECKED_PPTR_OF(type, x)))

void *ASN1_item_d2i_bio_ex(const ASN1_ITEM *it, BIO *in, void *pval,
                           OSSL_LIB_CTX *libctx, const char *propq);
void *ASN1_item_d2i_bio(const ASN1_ITEM *it, BIO *in, void *pval);
int ASN1_i2d_bio(i2d_of_void *i2d, BIO *out, const void *x);

#  define ASN1_i2d_bio_of(type,i2d,out,x) \
    (ASN1_i2d_bio(CHECKED_I2D_OF(type, i2d), \
                  out, \
                  CHECKED_PTR_OF(const type, x)))

int ASN1_item_i2d_bio(const ASN1_ITEM *it, BIO *out, const void *x);
BIO *ASN1_item_i2d_mem_bio(const ASN1_ITEM *it, const ASN1_VALUE *val);
int ASN1_UTCTIME_print(BIO *fp, const ASN1_UTCTIME *a);
int ASN1_GENERALIZEDTIME_print(BIO *fp, const ASN1_GENERALIZEDTIME *a);
int ASN1_TIME_print(BIO *bp, const ASN1_TIME *tm);
int ASN1_TIME_print_ex(BIO *bp, const ASN1_TIME *tm, unsigned long flags);
int ASN1_STRING_print(BIO *bp, const ASN1_STRING *v);
int ASN1_STRING_print_ex(BIO *out, const ASN1_STRING *str, unsigned long flags);
int ASN1_buf_print(BIO *bp, const unsigned char *buf, size_t buflen, int off);
int ASN1_bn_print(BIO *bp, const char *number, const BIGNUM *num,
                  unsigned char *buf, int off);
int ASN1_parse(BIO *bp, const unsigned char *pp, long len, int indent);
int ASN1_parse_dump(BIO *bp, const unsigned char *pp, long len, int indent,
                    int dump);
const char *ASN1_tag2str(int tag);

/* Used to load and write Netscape format cert */

int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s);

int ASN1_TYPE_set_octetstring(ASN1_TYPE *a, unsigned char *data, int len);
int ASN1_TYPE_get_octetstring(const ASN1_TYPE *a, unsigned char *data, int max_len);
int ASN1_TYPE_set_int_octetstring(ASN1_TYPE *a, long num,
                                  unsigned char *data, int len);
int ASN1_TYPE_get_int_octetstring(const ASN1_TYPE *a, long *num,
                                  unsigned char *data, int max_len);

void *ASN1_item_unpack(const ASN1_STRING *oct, const ASN1_ITEM *it);
void *ASN1_item_unpack_ex(const ASN1_STRING *oct, const ASN1_ITEM *it,
                          OSSL_LIB_CTX *libctx, const char *propq);

ASN1_STRING *ASN1_item_pack(void *obj, const ASN1_ITEM *it,
                            ASN1_OCTET_STRING **oct);

void ASN1_STRING_set_default_mask(unsigned long mask);
int ASN1_STRING_set_default_mask_asc(const char *p);
unsigned long ASN1_STRING_get_default_mask(void);
int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
                       int inform, unsigned long mask);
int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
                        int inform, unsigned long mask,
                        long minsize, long maxsize);

ASN1_STRING *ASN1_STRING_set_by_NID(ASN1_STRING **out,
                                    const unsigned char *in, int inlen,
                                    int inform, int nid);
ASN1_STRING_TABLE *ASN1_STRING_TABLE_get(int nid);
int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long);
void ASN1_STRING_TABLE_cleanup(void);

/* ASN1 template functions */

/* Old API compatible functions */
ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it);
ASN1_VALUE *ASN1_item_new_ex(const ASN1_ITEM *it, OSSL_LIB_CTX *libctx,
                             const char *propq);
void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it);
ASN1_VALUE *ASN1_item_d2i_ex(ASN1_VALUE **val, const unsigned char **in,
                             long len, const ASN1_ITEM *it,
                             OSSL_LIB_CTX *libctx, const char *propq);
ASN1_VALUE *ASN1_item_d2i(ASN1_VALUE **val, const unsigned char **in,
                          long len, const ASN1_ITEM *it);
int ASN1_item_i2d(const ASN1_VALUE *val, unsigned char **out, const ASN1_ITEM *it);
int ASN1_item_ndef_i2d(const ASN1_VALUE *val, unsigned char **out,
                       const ASN1_ITEM *it);

void ASN1_add_oid_module(void);
void ASN1_add_stable_module(void);

ASN1_TYPE *ASN1_generate_nconf(const char *str, CONF *nconf);
ASN1_TYPE *ASN1_generate_v3(const char *str, X509V3_CTX *cnf);
int ASN1_str2mask(const char *str, unsigned long *pmask);

/* ASN1 Print flags */

/* Indicate missing OPTIONAL fields */
# define ASN1_PCTX_FLAGS_SHOW_ABSENT             0x001
/* Mark start and end of SEQUENCE */
# define ASN1_PCTX_FLAGS_SHOW_SEQUENCE           0x002
/* Mark start and end of SEQUENCE/SET OF */
# define ASN1_PCTX_FLAGS_SHOW_SSOF               0x004
/* Show the ASN1 type of primitives */
# define ASN1_PCTX_FLAGS_SHOW_TYPE               0x008
/* Don't show ASN1 type of ANY */
# define ASN1_PCTX_FLAGS_NO_ANY_TYPE             0x010
/* Don't show ASN1 type of MSTRINGs */
# define ASN1_PCTX_FLAGS_NO_MSTRING_TYPE         0x020
/* Don't show field names in SEQUENCE */
# define ASN1_PCTX_FLAGS_NO_FIELD_NAME           0x040
/* Show structure names of each SEQUENCE field */
# define ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME  0x080
/* Don't show structure name even at top level */
# define ASN1_PCTX_FLAGS_NO_STRUCT_NAME          0x100

int ASN1_item_print(BIO *out, const ASN1_VALUE *ifld, int indent,
                    const ASN1_ITEM *it, const ASN1_PCTX *pctx);
ASN1_PCTX *ASN1_PCTX_new(void);
void ASN1_PCTX_free(ASN1_PCTX *p);
unsigned long ASN1_PCTX_get_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_nm_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_nm_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_cert_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_cert_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_oid_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_oid_flags(ASN1_PCTX *p, unsigned long flags);
unsigned long ASN1_PCTX_get_str_flags(const ASN1_PCTX *p);
void ASN1_PCTX_set_str_flags(ASN1_PCTX *p, unsigned long flags);

ASN1_SCTX *ASN1_SCTX_new(int (*scan_cb) (ASN1_SCTX *ctx));
void ASN1_SCTX_free(ASN1_SCTX *p);
const ASN1_ITEM *ASN1_SCTX_get_item(ASN1_SCTX *p);
const ASN1_TEMPLATE *ASN1_SCTX_get_template(ASN1_SCTX *p);
unsigned long ASN1_SCTX_get_flags(ASN1_SCTX *p);
void ASN1_SCTX_set_app_data(ASN1_SCTX *p, void *data);
void *ASN1_SCTX_get_app_data(ASN1_SCTX *p);

const BIO_METHOD *BIO_f_asn1(void);

/* cannot constify val because of CMS_stream() */
BIO *BIO_new_NDEF(BIO *out, ASN1_VALUE *val, const ASN1_ITEM *it);

int i2d_ASN1_bio_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
                        const ASN1_ITEM *it);
int PEM_write_bio_ASN1_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
                              const char *hdr, const ASN1_ITEM *it);
/* cannot constify val because of CMS_dataFinal() */
int SMIME_write_ASN1(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
                     int ctype_nid, int econt_nid,
                     STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it);
int SMIME_write_ASN1_ex(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
                        int ctype_nid, int econt_nid,
                        STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it,
                        OSSL_LIB_CTX *libctx, const char *propq);
ASN1_VALUE *SMIME_read_ASN1(BIO *bio, BIO **bcont, const ASN1_ITEM *it);
ASN1_VALUE *SMIME_read_ASN1_ex(BIO *bio, int flags, BIO **bcont,
                               const ASN1_ITEM *it, ASN1_VALUE **x,
                               OSSL_LIB_CTX *libctx, const char *propq);
int SMIME_crlf_copy(BIO *in, BIO *out, int flags);
int SMIME_text(BIO *in, BIO *out);

const ASN1_ITEM *ASN1_ITEM_lookup(const char *name);
const ASN1_ITEM *ASN1_ITEM_get(size_t i);

/* Legacy compatibility */
# define DECLARE_ASN1_FUNCTIONS_fname(type, itname, name) \
         DECLARE_ASN1_ALLOC_FUNCTIONS_name(type, name) \
         DECLARE_ASN1_ENCODE_FUNCTIONS(type, itname, name)
# define DECLARE_ASN1_FUNCTIONS_const(type) DECLARE_ASN1_FUNCTIONS(type)
# define DECLARE_ASN1_ENCODE_FUNCTIONS_const(type, name) \
         DECLARE_ASN1_ENCODE_FUNCTIONS(type, name)
# define I2D_OF_const(type) I2D_OF(type)
# define ASN1_dup_of_const(type,i2d,d2i,x) ASN1_dup_of(type,i2d,d2i,x)
# define ASN1_i2d_fp_of_const(type,i2d,out,x) ASN1_i2d_fp_of(type,i2d,out,x)
# define ASN1_i2d_bio_of_const(type,i2d,out,x) ASN1_i2d_bio_of(type,i2d,out,x)

# ifdef  __cplusplus
}
# endif
#endif
