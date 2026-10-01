/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
 * Copyright (c)      2015 Jochen Hoenicke
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */
#include <stdint.h>
#include <string.h>
#include "bignum.h"
#include "ecdsa.h"
#include "memzero.h"

void point_copy(const curve_point *cp1, curve_point *cp2) { *cp2 = *cp1; }

void point_set_infinity(curve_point *p) {
  bn_zero(&(p->x));
  bn_zero(&(p->y));
}

int point_is_infinity(const curve_point *p) {
  return bn_is_zero(&(p->x)) && bn_is_zero(&(p->y));
}

int point_is_equal(const curve_point *p, const curve_point *q) {
  return bn_is_equal(&(p->x), &(q->x)) && bn_is_equal(&(p->y), &(q->y));
}

int point_is_negative_of(const curve_point *p, const curve_point *q) {
  if (!bn_is_equal(&(p->x), &(q->x))) return 0;
  if (bn_is_zero(&(p->y))) return 0;
  return !bn_is_equal(&(p->y), &(q->y));
}

void point_double(const ecdsa_curve *curve, curve_point *cp) {
  bignum256 lambda = {0}, xr = {0}, yr = {0};
  if (point_is_infinity(cp)) return;
  if (bn_is_zero(&(cp->y))) { point_set_infinity(cp); return; }
  lambda = cp->y;
  bn_mult_k(&lambda, 2, &curve->prime);
  bn_fast_mod(&lambda, &curve->prime);
  bn_mod(&lambda, &curve->prime);
  bn_inverse(&lambda, &curve->prime);
  xr = cp->x;
  bn_multiply(&xr, &xr, &curve->prime);
  bn_mult_k(&xr, 3, &curve->prime);
  bn_subi(&xr, -curve->a, &curve->prime);
  bn_multiply(&xr, &lambda, &curve->prime);
  xr = lambda;
  bn_multiply(&xr, &xr, &curve->prime);
  yr = cp->x;
  bn_lshift(&yr);
  bn_subtractmod(&xr, &yr, &xr, &curve->prime);
  bn_fast_mod(&xr, &curve->prime);
  bn_mod(&xr, &curve->prime);
  bn_subtractmod(&(cp->x), &xr, &yr, &curve->prime);
  bn_multiply(&lambda, &yr, &curve->prime);
  bn_subtractmod(&yr, &(cp->y), &yr, &curve->prime);
  bn_fast_mod(&yr, &curve->prime);
  bn_mod(&yr, &curve->prime);
  cp->x = xr;
  cp->y = yr;
}

void point_add(const ecdsa_curve *curve, const curve_point *cp1, curve_point *cp2) {
  bignum256 lambda = {0}, inv = {0}, xr = {0}, yr = {0};
  if (point_is_infinity(cp1)) return;
  if (point_is_infinity(cp2)) { point_copy(cp1, cp2); return; }
  if (point_is_equal(cp1, cp2)) { point_double(curve, cp2); return; }
  if (point_is_negative_of(cp1, cp2)) { point_set_infinity(cp2); return; }
  bn_subtractmod(&(cp2->x), &(cp1->x), &inv, &curve->prime);
  bn_inverse(&inv, &curve->prime);
  bn_subtractmod(&(cp2->y), &(cp1->y), &lambda, &curve->prime);
  bn_multiply(&inv, &lambda, &curve->prime);
  xr = lambda;
  bn_multiply(&xr, &xr, &curve->prime);
  yr = cp1->x;
  bn_addmod(&yr, &(cp2->x), &curve->prime);
  bn_subtractmod(&xr, &yr, &xr, &curve->prime);
  bn_fast_mod(&xr, &curve->prime);
  bn_mod(&xr, &curve->prime);
  bn_subtractmod(&(cp1->x), &xr, &yr, &curve->prime);
  bn_multiply(&lambda, &yr, &curve->prime);
  bn_subtractmod(&yr, &(cp1->y), &yr, &curve->prime);
  bn_fast_mod(&yr, &curve->prime);
  bn_mod(&yr, &curve->prime);
  cp2->x = xr;
  cp2->y = yr;
}

typedef struct jacobian_curve_point { bignum256 x, y, z; } jacobian_curve_point;

void curve_to_jacobian(const curve_point *p, jacobian_curve_point *jp, const bignum256 *prime) {
  jp->x = p->x;
  jp->y = p->y;
  bn_zero(&jp->z);
  jp->z.val[0] = 1; // Simplificación: Z=1 constante, sin generadores aleatorios pesados
}

void jacobian_to_curve(const jacobian_curve_point *jp, curve_point *p, const bignum256 *prime) {
  p->y = jp->z;
  bn_inverse(&p->y, prime);
  p->x = p->y;
  bn_multiply(&p->x, &p->x, prime);
  bn_multiply(&p->x, &p->y, prime);
  bn_multiply(&jp->x, &p->x, prime);
  bn_multiply(&jp->y, &p->y, prime);
  bn_mod(&p->x, prime);
  bn_mod(&p->y, prime);
}

void point_jacobian_add(const curve_point *p1, jacobian_curve_point *p2, const ecdsa_curve *curve) {
  bignum256 r = {0}, h = {0}, r2 = {0}, hcby = {0}, hsqx = {0}, xz = {0}, yz = {0}, az = {0};
  int is_doubling = 0;
  const bignum256 *prime = &curve->prime;
  int a = curve->a;
  xz = p2->z;
  bn_multiply(&xz, &xz, prime);
  yz = p2->z;
  bn_multiply(&xz, &yz, prime);
  if (a != 0) {
    az = xz;
    bn_multiply(&az, &az, prime);
    bn_mult_k(&az, -a, prime);
  }
  bn_multiply(&p1->x, &xz, prime);
  h = xz;
  bn_subtractmod(&h, &p2->x, &h, prime);
  bn_fast_mod(&h, prime);
  bn_add(&xz, &p2->x);
  is_doubling = bn_is_equal(&h, prime);
  bn_multiply(&p1->y, &yz, prime);
  bn_subtractmod(&yz, &p2->y, &r, prime);
  bn_add(&yz, &p2->y);
  r2 = p2->x;
  bn_multiply(&r2, &r2, prime);
  bn_mult_k(&r2, 3, prime);
  if (a != 0) bn_subtractmod(&r2, &az, &r2, prime);
  bn_cmov(&r, is_doubling, &r2, &r);
  bn_cmov(&h, is_doubling, &yz, &h);
  hsqx = h;
  bn_multiply(&hsqx, &hsqx, prime);
  hcby = h;
  bn_multiply(&hsqx, &hcby, prime);
  bn_multiply(&xz, &hsqx, prime);
  bn_multiply(&yz, &hcby, prime);
  bn_multiply(&h, &p2->z, prime);
  p2->x = r;
  bn_multiply(&p2->x, &p2->x, prime);
  bn_subtractmod(&p2->x, &hsqx, &p2->x, prime);
  bn_fast_mod(&p2->x, prime);
  bn_subtractmod(&hsqx, &p2->x, &p2->y, prime);
  bn_subtractmod(&p2->y, &p2->x, &p2->y, prime);
  bn_multiply(&r, &p2->y, prime);
  bn_subtractmod(&p2->y, &hcby, &p2->y, prime);
  bn_mult_half(&p2->y, prime);
  bn_fast_mod(&p2->y, prime);
}

void point_jacobian_double(jacobian_curve_point *p, const ecdsa_curve *curve) {
  bignum256 az4 = {0}, m = {0}, msq = {0}, ysq = {0}, xysq = {0};
  const bignum256 *prime = &curve->prime;
  m = p->x;
  bn_multiply(&m, &m, prime);
  bn_mult_k(&m, 3, prime);
  az4 = p->z;
  bn_multiply(&az4, &az4, prime);
  bn_multiply(&az4, &az4, prime);
  bn_mult_k(&az4, -curve->a, prime);
  bn_subtractmod(&m, &az4, &m, prime);
  bn_mult_half(&m, prime);
  msq = m;
  bn_multiply(&msq, &msq, prime);
  ysq = p->y;
  bn_multiply(&ysq, &ysq, prime);
  xysq = p->x;
  bn_multiply(&ysq, &xysq, prime);
  bn_multiply(&p->y, &p->z, prime);
  p->x = xysq;
  bn_lshift(&p->x);
  bn_fast_mod(&p->x, prime);
  bn_subtractmod(&msq, &p->x, &p->x, prime);
  bn_fast_mod(&p->x, prime);
  bn_subtractmod(&xysq, &p->x, &p->y, prime);
  bn_multiply(&m, &p->y, prime);
  bn_multiply(&ysq, &ysq, prime);
  bn_subtractmod(&p->y, &ysq, &p->y, prime);
  bn_fast_mod(&p->y, prime);
}

int point_multiply(const ecdsa_curve *curve, const bignum256 *k, const curve_point *p, curve_point *res) {
  if (!bn_is_less(k, &curve->order)) return 1;
  int i = 0, j = 0;
  bignum256 a;
  uint32_t *aptr = NULL;
  uint32_t abits = 0;
  int ashift = 0;
  uint32_t is_even = (k->val[0] & 1) - 1;
  uint32_t bits = 0, sign = 0, nsign = 0;
  jacobian_curve_point jres;
  curve_point pmult[8] = {0};
  const bignum256 *prime = &curve->prime;

  uint32_t tmp = 1;
  uint32_t is_non_zero = 0;
  for (j = 0; j < 8; j++) {
    is_non_zero |= k->val[j];
    tmp += (BN_BASE - 1) + k->val[j] - (curve->order.val[j] & is_even);
    a.val[j] = tmp & (BN_BASE - 1);
    tmp >>= BN_BITS_PER_LIMB;
  }
  is_non_zero |= k->val[j];
  a.val[j] = tmp + 0xffffff + k->val[j] - (curve->order.val[j] & is_even);

  if (!is_non_zero) { point_set_infinity(res); return 1; }

  pmult[7] = *p;
  point_double(curve, &pmult[7]);
  pmult[0] = *p;
  for (i = 1; i < 8; i++) {
    pmult[i] = pmult[7];
    point_add(curve, &pmult[i - 1], &pmult[i]);
  }

  aptr = &a.val[8];
  abits = *aptr;
  ashift = 256 - (BN_BITS_PER_LIMB * 8) - 4;
  bits = abits >> ashift;
  sign = (bits >> 4) - 1;
  bits ^= sign;
  bits &= 15;
  curve_to_jacobian(&pmult[bits >> 1], &jres, prime);
  for (i = 62; i >= 0; i--) {
    point_jacobian_double(&jres, curve);
    point_jacobian_double(&jres, curve);
    point_jacobian_double(&jres, curve);
    point_jacobian_double(&jres, curve);
    ashift -= 4;
    if (ashift < 0) {
      bits = abits << (-ashift);
      abits = *(--aptr);
      ashift += BN_BITS_PER_LIMB;
      bits |= abits >> ashift;
    } else {
      bits = abits >> ashift;
    }
    bits &= 31;
    nsign = (bits >> 4) - 1;
    bits ^= nsign;
    bits &= 15;
    bn_cnegate((sign ^ nsign) & 1, &jres.z, prime);
    point_jacobian_add(&pmult[bits >> 1], &jres, curve);
    sign = nsign;
  }
  bn_cnegate(sign & 1, &jres.z, prime);
  jacobian_to_curve(&jres, res, prime);
  memzero(&a, sizeof(a));
  memzero(&jres, sizeof(jres));
  return 0;
}

int scalar_multiply(const ecdsa_curve *curve, const bignum256 *k, curve_point *res) {
  return point_multiply(curve, k, &curve->G, res);
}

int uncompress_coords(const ecdsa_curve *curve, uint8_t odd, const bignum256 *x, bignum256 *y) {
  bignum256 y_2 = {0}, y_2_check = {0};
  if (!bn_is_less(x, &curve->prime)) { bn_zero(y); return 0; }
  memcpy(&y_2, x, sizeof(bignum256));
  bn_multiply(x, &y_2, &curve->prime);
  bn_subi(&y_2, -curve->a, &curve->prime);
  bn_multiply(x, &y_2, &curve->prime);
  bn_addmod(&y_2, &curve->b, &curve->prime);
  bn_mod(&y_2, &curve->prime);
  bn_copy(&y_2, y);
  bn_sqrt(y, &curve->prime);
  bn_copy(y, &y_2_check);
  bn_multiply(y, &y_2_check, &curve->prime);
  bn_mod(&y_2_check, &curve->prime);
  if (!bn_is_equal(&y_2_check, &y_2)) { bn_zero(y); return 0; }
  if ((odd & 0x01) != (y->val[0] & 1)) { bn_subtract(&curve->prime, y, y); }
  return 1;
}

int ecdsa_validate_pubkey(const ecdsa_curve *curve, const curve_point *pub) {
  bignum256 y_2 = {0}, x3_ax_b = {0};
  if (point_is_infinity(pub)) return 0;
  if (!bn_is_less(&(pub->x), &curve->prime) || !bn_is_less(&(pub->y), &curve->prime)) return 0;
  memcpy(&y_2, &(pub->y), sizeof(bignum256));
  memcpy(&x3_ax_b, &(pub->x), sizeof(bignum256));
  bn_multiply(&(pub->y), &y_2, &curve->prime);
  bn_mod(&y_2, &curve->prime);
  bn_multiply(&(pub->x), &x3_ax_b, &curve->prime);
  bn_subi(&x3_ax_b, -curve->a, &curve->prime);
  bn_multiply(&(pub->x), &x3_ax_b, &curve->prime);
  bn_addmod(&x3_ax_b, &curve->b, &curve->prime);
  bn_mod(&x3_ax_b, &curve->prime);
  if (!bn_is_equal(&x3_ax_b, &y_2)) return 0;
  return 1;
}

int ecdsa_read_pubkey(const ecdsa_curve *curve, const uint8_t *pub_key, curve_point *pub) {
  if (!curve) return 0;
  if (pub_key[0] == 0x04) {
    bn_read_be(pub_key + 1, &(pub->x));
    bn_read_be(pub_key + 33, &(pub->y));
    return ecdsa_validate_pubkey(curve, pub);
  }
  if (pub_key[0] == 0x02 || pub_key[0] == 0x03) {
    bn_read_be(pub_key + 1, &(pub->x));
    return uncompress_coords(curve, pub_key[0], &(pub->x), &(pub->y));
  }
  return 0;
}

int ecdsa_get_public_key33(const ecdsa_curve *curve, const uint8_t *priv_key, uint8_t *pub_key) {
  curve_point R = {0};
  bignum256 k = {0};
  bn_read_be(priv_key, &k);
  if (bn_is_zero(&k) || !bn_is_less(&k, &curve->order)) {
    memzero(&k, sizeof(k));
    memzero(pub_key, 33);
    return -1;
  }
  if (scalar_multiply(curve, &k, &R) != 0) {
    memzero(&k, sizeof(k));
    return 1;
  }
  pub_key[0] = 0x02 | (R.y.val[0] & 0x01);
  bn_write_be(&R.x, pub_key + 1);
  memzero(&R, sizeof(R));
  memzero(&k, sizeof(k));
  return 0;
}