/**
 * Copyright (c) 2013-2016 Tomas Dzetkulic
 * Copyright (c) 2013-2016 Pavol Rusnak
 * Copyright (c) 2015-2016 Jochen Hoenicke
 * Adapted for Seedmate / PIC32MM
 */

#include <stdbool.h>
#include <string.h>

#include "bip32.h"
#include "secp256k1.h"
#include "bignum.h"
#include "memzero.h"
#include "sha256.h"
#include "ripemd160.h"

// Define curve name constant if not present
#ifndef SECP256K1_NAME
#define SECP256K1_NAME "secp256k1"
#endif

// External declaration for your native HmacSha512 function (defined in main.c)
extern void HmacSha512(const uint8_t *key, size_t keyLen,
                       const uint8_t *data, size_t dataLen,
                       uint8_t *out);

bool hdnode_validate_private_key(const curve_info *curve, const uint8_t private_key[32]) {
  if (curve->params == NULL) return false;
  bool valid = true;
  bignum256 a = {0};
  bn_read_be(private_key, &a);
  if (bn_is_zero(&a)) {
    valid = false;
  } else if (!bn_is_less(&a, &curve->params->order)) {
    valid = false;
  }
  memzero(&a, sizeof(a));
  return valid;
}

bool hdnode_validate_public_key(const curve_info *curve, const uint8_t public_key[33]) {
  if (curve->params == NULL) return false;
  curve_point point = {0};
  bool valid = (public_key[0] == 0x02 || public_key[0] == 0x03) &&
               ecdsa_read_pubkey(curve->params, public_key, &point);
  memzero(&point, sizeof(point));
  return valid;
}

int hdnode_from_seed(const uint8_t *seed, size_t seed_len, const char *curve, HDNode *out) {
  uint8_t I[64];
  memzero(out, sizeof(HDNode));
  out->depth = 0;
  out->child_num = 0;
  out->curve = get_curve_by_name(curve);
  if (out->curve == 0 || out->curve->params == NULL) {
    return 0;
  }
  
  // Use native HmacSha512
  HmacSha512((const uint8_t *)out->curve->bip32_name, strlen(out->curve->bip32_name), seed, seed_len, I);

  while (!hdnode_validate_private_key(out->curve, I)) {
    HmacSha512((const uint8_t *)out->curve->bip32_name, strlen(out->curve->bip32_name), I, sizeof(I), I);
  }
  
  memcpy(out->private_key, I, 32);
  memcpy(out->chain_code, I + 32, 32);
  memzero(out->public_key, sizeof(out->public_key));
  out->is_public_key_set = false;
  memzero(I, sizeof(I));
  return 1;
}

int hdnode_private_ckd(HDNode *inout, uint32_t i) {
  uint8_t data[37];
  uint8_t I[64];
  bignum256 a, b;

  if (inout->depth == UINT32_MAX || inout->curve->params == NULL) {
    return 0;
  }

  if (i & 0x80000000) {  // private derivation
    data[0] = 0;
    memcpy(data + 1, inout->private_key, 32);
  } else {  // public derivation
    if (hdnode_fill_public_key(inout) != 0) {
      return 0;
    }
    memcpy(data, inout->public_key, 33);
  }
  
  // Big-endian index encoding
  data[33] = (i >> 24) & 0xFF;
  data[34] = (i >> 16) & 0xFF;
  data[35] = (i >> 8) & 0xFF;
  data[36] = i & 0xFF;

  bn_read_be(inout->private_key, &a);

  HmacSha512(inout->chain_code, 32, data, sizeof(data), I);

  while (true) {
    bool failed = false;
    bn_read_be(I, &b);
    if (!bn_is_less(&b, &inout->curve->params->order)) {
      failed = true;
    } else {
      bn_add(&b, &a);
      bn_mod(&b, &inout->curve->params->order);
      if (bn_is_zero(&b)) {
        failed = true;
      }
    }

    if (!failed) {
      bn_write_be(&b, inout->private_key);
      break;
    }

    data[0] = 1;
    memcpy(data + 1, I + 32, 32);
    HmacSha512(inout->chain_code, 32, data, sizeof(data), I);
  }

  memcpy(inout->chain_code, I + 32, 32);
  inout->depth++;
  inout->child_num = i;
  memzero(inout->public_key, sizeof(inout->public_key));
  inout->is_public_key_set = false;

  memzero(&a, sizeof(a));
  memzero(&b, sizeof(b));
  memzero(I, sizeof(I));
  memzero(data, sizeof(data));
  return 1;
}

int hdnode_fill_public_key(HDNode *node) {
  if (node->is_public_key_set) {
    return 0;
  }
  if (node->curve->params == NULL) {
    return 1;
  }
  if (ecdsa_get_public_key33(node->curve->params, node->private_key,
                             node->public_key) != 0) {
    return 1;
  }
  node->is_public_key_set = true;
  return 0;
}

int hdnode_get_address_raw(HDNode *node, uint32_t version, uint8_t *addr_raw) {
  if (hdnode_fill_public_key(node) != 0) {
    return 1;
  }
  
  uint8_t sha256_pub[32];
  uint8_t hash160[20];
  SHA256_CTX ctx;
  
  // Use native sha256 context matching main.c
  sha256_init(&ctx);
  sha256_update(&ctx, node->public_key, 33);
  sha256_final(&ctx, sha256_pub);
  
  // Use optimized local ripemd160
  ripemd160(sha256_pub, 32, hash160);
  
  size_t prefix_len = (version > 0xff) ? 2 : 1;
  if (prefix_len == 2) {
    addr_raw[0] = (version >> 8) & 0xFF;
    addr_raw[1] = version & 0xFF;
  } else {
    addr_raw[0] = version & 0xFF;
  }
  memcpy(addr_raw + prefix_len, hash160, 20);
  
  memzero(sha256_pub, sizeof(sha256_pub));
  memzero(hash160, sizeof(hash160));
  return 0;
}

const curve_info *get_curve_by_name(const char *curve_name) {
  if (curve_name == 0) {
    return 0;
  }
  if (strcmp(curve_name, SECP256K1_NAME) == 0) {
    return &secp256k1_info;
  }
  return 0;
}