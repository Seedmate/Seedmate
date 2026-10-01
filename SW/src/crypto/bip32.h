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
 * 
 * Modified for BTC only
 */
#ifndef __BIP32_H__
#define __BIP32_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "ecdsa.h"
#include "options.h"

#define XPUB_MAXLEN 112
#define ADDRESS_MAXLEN 39

typedef struct {
  const char *bip32_name;     // string for generating BIP32 xprv from seed
  const ecdsa_curve *params;  // ecdsa curve parameters

} curve_info;

typedef struct {
  uint32_t depth;
  uint32_t child_num;
  uint8_t chain_code[32];
  uint8_t private_key[32];
  uint8_t public_key[33];
  bool is_public_key_set;
  const curve_info *curve;
} HDNode;

bool hdnode_validate_private_key(const curve_info *curve, const uint8_t private_key[32]);
bool hdnode_validate_public_key(const curve_info *curve, const uint8_t public_key[33]);

int hdnode_from_seed(const uint8_t *seed, size_t seed_len, const char *curve, HDNode *out);

#define hdnode_private_ckd_prime(X, I) \
  hdnode_private_ckd((X), ((I) | 0x80000000))

int hdnode_private_ckd(HDNode *inout, uint32_t i);
int hdnode_fill_public_key(HDNode *node);
int hdnode_get_address_raw(HDNode *node, uint32_t version, uint8_t *addr_raw);
int hdnode_get_address(HDNode *node, uint32_t version, char *addr, size_t addrsize);

const curve_info *get_curve_by_name(const char *curve_name);

#endif