/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_FIELD_IMPL_H
#define SECP256K1_FIELD_IMPL_H

#include "field.h"
#include "util.h"

#if defined(SECP256K1_WIDEMUL_INT128)
#include "field_5x52_impl.h"
#elif defined(SECP256K1_WIDEMUL_INT64)
#include "field_10x26_impl.h"
#else
#error "Please select wide multiplication implementation"
#endif

#ifndef VERIFY
static void secp256k1_fe_verify(const secp256k1_fe *a) { (void)a; }
#else
static void secp256k1_fe_impl_verify(const secp256k1_fe *a);
static void secp256k1_fe_verify(const secp256k1_fe *a) {
    secp256k1_fe_impl_verify(a);
}

static int secp256k1_fe_impl_equal(const secp256k1_fe *a, const secp256k1_fe *b);
SECP256K1_INLINE static int secp256k1_fe_equal(const secp256k1_fe *a, const secp256k1_fe *b) {
    return secp256k1_fe_impl_equal(a, b);
}

static int secp256k1_fe_impl_equal_var(const secp256k1_fe *a, const secp256k1_fe *b);
SECP256K1_INLINE static int secp256k1_fe_equal_var(const secp256k1_fe *a, const secp256k1_fe *b) {
    return secp256k1_fe_impl_equal_var(a, b);
}

static void secp256k1_fe_impl_normalize(secp256k1_fe *r);
SECP256K1_INLINE static void secp256k1_fe_normalize(secp256k1_fe *r) {
    secp256k1_fe_impl_normalize(r);
}

static void secp256k1_fe_impl_normalize_weak(secp256k1_fe *r);
SECP256K1_INLINE static void secp256k1_fe_normalize_weak(secp256k1_fe *r) {
    secp256k1_fe_verify(r);
    secp256k1_fe_impl_normalize_weak(r);
    r->magnitude = 1;
    secp256k1_fe_verify(r);
}

static void secp256k1_fe_impl_normalize_var(secp256k1_fe *r);
SECP256K1_INLINE static void secp256k1_fe_normalize_var(secp256k1_fe *r) {
    secp256k1_fe_impl_normalize_var(r);
}

static int secp256k1_fe_impl_normalizes_to_zero(const secp256k1_fe *r);
SECP256K1_INLINE static int secp256k1_fe_normalizes_to_zero(const secp256k1_fe *r) {
    return secp256k1_fe_impl_normalizes_to_zero(r);
}

static int secp256k1_fe_impl_normalizes_to_zero_var(const secp256k1_fe *r);
SECP256K1_INLINE static int secp256k1_fe_normalizes_to_zero_var(const secp256k1_fe *r) {
    secp256k1_fe_verify(r);
    return secp256k1_fe_impl_normalizes_to_zero_var(r);
}

static void secp256k1_fe_impl_set_int(secp256k1_fe *r, int a);
SECP256K1_INLINE static void secp256k1_fe_set_int(secp256k1_fe *r, int a) {
    VERIFY_CHECK(0 <= a && a <= 0x7FFF);
    secp256k1_fe_impl_set_int(r, a);
    r->magnitude = (a != 0);
    r->normalized = 1;
    secp256k1_fe_verify(r);
}

static void secp256k1_fe_impl_add_int(secp256k1_fe *r, int a);
SECP256K1_INLINE static void secp256k1_fe_add_int(secp256k1_fe *r, int a) {
    VERIFY_CHECK(0 <= a && a <= 0x7FFF);
    secp256k1_fe_verify(r);
    secp256k1_fe_impl_add_int(r, a);
    r->magnitude += 1;
    r->normalized = 0;
    secp256k1_fe_verify(r);
}

static void secp256k1_fe_impl_clear(secp256k1_fe *a);
SECP256K1_INLINE static void secp256k1_fe_clear(secp256k1_fe *a) {
    a->magnitude = 0;
    a->normalized = 1;
    secp256k1_fe_impl_clear(a);
    secp256k1_fe_verify(a);
}

static int secp256k1_fe_impl_is_zero(const secp256k1_fe *a);
SECP256K1_INLINE static int secp256k1_fe_is_zero(const secp256k1_fe *a) {
    return secp256k1_fe_impl_is_zero(a);
}

static int secp256k1_fe_impl_is_odd(const secp256k1_fe *a);
SECP256K1_INLINE static int secp256k1_fe_is_odd(const secp256k1_fe *a) {
    secp256k1_fe_verify(a);
    VERIFY_CHECK(a->normalized);
    return secp256k1_fe_impl_is_odd(a);
}

static int secp256k1_fe_impl_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b);
SECP256K1_INLINE static int secp256k1_fe_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b) {
    secp256k1_fe_verify(a);
    secp256k1_fe_verify(b);
    VERIFY_CHECK(a->normalized);
    VERIFY_CHECK(b->normalized);
    return secp256k1_fe_impl_cmp_var(a, b);
}

static void secp256k1_fe_impl_set_b32_mod(secp256k1_fe *r, const unsigned char *a);
SECP256K1_INLINE static void secp256k1_fe_set_b32_mod(secp256k1_fe *r, const unsigned char *a) {
    secp256k1_fe_impl_set_b32_mod(r, a);
    r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verify(r);
}

static int secp256k1_fe_impl_set_b32_limit(secp256k1_fe *r, const unsigned char *a);
SECP256K1_INLINE static int secp256k1_fe_set_b32_limit(secp256k1_fe *r, const unsigned char *a) {
    if (secp256k1_fe_impl_set_b32_limit(r, a)) {
        r->magnitude = 1;
        r->normalized = 1;
        secp256k1_fe_verify(r);
        return 1;
    } else {
        /* Mark the output field element as invalid. */
        r->magnitude = -1;
        return 0;
    }
}

static void secp256k1_fe_impl_get_b32(unsigned char *r, const secp256k1_fe *a);
SECP256K1_INLINE static void secp256k1_fe_get_b32(unsigned char *r, const secp256k1_fe *a) {
    secp256k1_fe_verify(a);
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_impl_get_b32(r, a);
}

static void secp256k1_fe_impl_negate_unchecked(secp256k1_fe *r, const secp256k1_fe *a, int m);
SECP256K1_INLINE static void secp256k1_fe_negate_unchecked(secp256k1_fe *r, const secp256k1_fe *a, int m) {
    secp256k1_fe_impl_negate_unchecked(r, a, m);
}

static void secp256k1_fe_impl_mul_int_unchecked(secp256k1_fe *r, int a);
SECP256K1_INLINE static void secp256k1_fe_mul_int_unchecked(secp256k1_fe *r, int a) {
    secp256k1_fe_verify(r);
    VERIFY_CHECK(a >= 0 && a <= 32);
    VERIFY_CHECK(a*r->magnitude <= 32);
    secp256k1_fe_impl_mul_int_unchecked(r, a);
    r->magnitude *= a;
    r->normalized = 0;
    secp256k1_fe_verify(r);
}

static void secp256k1_fe_impl_add(secp256k1_fe *r, const secp256k1_fe *a);
SECP256K1_INLINE static void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a) {
    secp256k1_fe_impl_add(r, a);
}

static void secp256k1_fe_impl_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b);
SECP256K1_INLINE static void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b) {
    secp256k1_fe_impl_mul(r, a, b);
}

static void secp256k1_fe_impl_sqr(secp256k1_fe *r, const secp256k1_fe *a);
SECP256K1_INLINE static void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a) {
    secp256k1_fe_impl_sqr(r, a);
}

static void secp256k1_fe_impl_cmov(secp256k1_fe *r, const secp256k1_fe *a, int flag);
SECP256K1_INLINE static void secp256k1_fe_cmov(secp256k1_fe *r, const secp256k1_fe *a, int flag) {
    VERIFY_CHECK(flag == 0 || flag == 1);
    secp256k1_fe_verify(a);
    secp256k1_fe_verify(r);
    secp256k1_fe_impl_cmov(r, a, flag);
    if (a->magnitude > r->magnitude) r->magnitude = a->magnitude;
    if (!a->normalized) r->normalized = 0;
    secp256k1_fe_verify(r);
}

static void secp256k1_fe_impl_to_storage(secp256k1_fe_storage *r, const secp256k1_fe *a);
SECP256K1_INLINE static void secp256k1_fe_to_storage(secp256k1_fe_storage *r, const secp256k1_fe *a) {
    secp256k1_fe_verify(a);
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_impl_to_storage(r, a);
}

static void secp256k1_fe_impl_from_storage(secp256k1_fe *r, const secp256k1_fe_storage *a);
SECP256K1_INLINE static void secp256k1_fe_from_storage(secp256k1_fe *r, const secp256k1_fe_storage *a) {
    secp256k1_fe_impl_from_storage(r, a);
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
}

static void secp256k1_fe_impl_inv(secp256k1_fe *r, const secp256k1_fe *x);
SECP256K1_INLINE static void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *x) {
    int input_is_zero = secp256k1_fe_normalizes_to_zero(x);
    secp256k1_fe_verify(x);
    secp256k1_fe_impl_inv(r, x);
    r->magnitude = x->magnitude > 0;
    r->normalized = 1;
    VERIFY_CHECK(secp256k1_fe_normalizes_to_zero(r) == input_is_zero);
    secp256k1_fe_verify(r);
}

static void secp256k1_fe_impl_inv_var(secp256k1_fe *r, const secp256k1_fe *x);
SECP256K1_INLINE static void secp256k1_fe_inv_var(secp256k1_fe *r, const secp256k1_fe *x) {
    int input_is_zero = secp256k1_fe_normalizes_to_zero(x);
    secp256k1_fe_verify(x);
    secp256k1_fe_impl_inv_var(r, x);
    r->magnitude = x->magnitude > 0;
    r->normalized = 1;
    VERIFY_CHECK(secp256k1_fe_normalizes_to_zero(r) == input_is_zero);
    secp256k1_fe_verify(r);
}

static int secp256k1_fe_impl_sqrt(secp256k1_fe *r, const secp256k1_fe *a);
SECP256K1_INLINE static int secp256k1_fe_sqrt(secp256k1_fe *r, const secp256k1_fe *a) {
    return secp256k1_fe_impl_sqrt(r, a);
}

static int secp256k1_fe_impl_is_square_var(const secp256k1_fe *x);
SECP256K1_INLINE static int secp256k1_fe_is_square_var(const secp256k1_fe *x) {
    int ret;
    secp256k1_fe tmp = *x, sqrt;
    secp256k1_fe_verify(x);
    ret = secp256k1_fe_impl_is_square_var(x);
    secp256k1_fe_normalize_weak(&tmp);
    VERIFY_CHECK(ret == secp256k1_fe_sqrt(&sqrt, &tmp));
    return ret;
}

static void secp256k1_fe_impl_get_bounds(secp256k1_fe* r, int m);
SECP256K1_INLINE static void secp256k1_fe_get_bounds(secp256k1_fe* r, int m) {
    VERIFY_CHECK(m >= 0);
    VERIFY_CHECK(m <= 32);
    secp256k1_fe_impl_get_bounds(r, m);
    r->magnitude = m;
    r->normalized = (m == 0);
    secp256k1_fe_verify(r);
}

static void secp256k1_fe_impl_half(secp256k1_fe *r);
SECP256K1_INLINE static void secp256k1_fe_half(secp256k1_fe *r) {
    secp256k1_fe_verify(r);
    VERIFY_CHECK(r->magnitude < 32);
    secp256k1_fe_impl_half(r);
    r->magnitude = (r->magnitude >> 1) + 1;
    r->normalized = 0;
    secp256k1_fe_verify(r);
}

#endif /* defined(VERIFY) */

#endif /* SECP256K1_FIELD_IMPL_H */
