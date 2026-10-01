/**
 * Copyright (c) 2013-2014 Tomas Dzetkulic
 * Copyright (c) 2013-2014 Pavol Rusnak
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
#ifndef __ECDSA_H__
#define __ECDSA_H__

#include <stdint.h>
#include "bignum.h"

// curve point x and y
typedef struct {
  bignum256 x, y;
} curve_point;

typedef struct {
  bignum256 prime;       // prime order of the finite field
  curve_point G;         // initial curve point
  bignum256 order;       // order of G
  bignum256 order_half;  // order of G divided by 2
  int a;                 // coefficient 'a' of the elliptic curve
  bignum256 b;           // coefficient 'b' of the elliptic curve
} ecdsa_curve;

// Prototipos estrictamente necesarios para derivar claves públicas (sin hashes)
int ecdsa_read_pubkey(const ecdsa_curve *curve, const uint8_t *pub_key, curve_point *pub);
int ecdsa_get_public_key33(const ecdsa_curve *curve, const uint8_t *priv_key, uint8_t *pub_key);

#endif