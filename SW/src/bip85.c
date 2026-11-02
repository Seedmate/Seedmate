/*******************************************************************************
 * Project:     SeedMate
 * File:        bip85.c
 *
 * Summary:
 *   BIP85 entropy from a BIP32 master key (see bip85.h). Hardened private
 *   derivation only, so no elliptic curve point is needed: each step is an
 *   HMAC-SHA512 and an addition mod n. Host tests in ../test/vault/.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include <string.h>
#include <stdbool.h>
#include "bip85.h"
#include "kdf.h"
#include "memzero.h"

// out = (a + b) mod n, n the secp256k1 group order (big endian, 32 bytes)
static void add_256_mod_n(uint8_t *out, const uint8_t *a, const uint8_t *b) {
    static const uint8_t n[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
    };
    uint16_t carry = 0;
    uint8_t res[32];
    bool over = false;

    for (int i = 31; i >= 0; i--) {
        carry += a[i] + b[i];
        res[i] = carry & 0xFF;
        carry >>= 8;
    }
    if (carry > 0) {
        over = true;
    } else {
        for (int i = 0; i < 32; i++) {
            if (res[i] > n[i]) { over = true; break; }
            if (res[i] < n[i]) break;
        }
    }
    if (over) {
        int borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int diff = (int)res[i] - (int)n[i] - borrow;
            borrow = (diff < 0);
            out[i] = (uint8_t)(diff + (borrow ? 256 : 0));
        }
    } else {
        memcpy(out, res, 32);
    }
    memzero(res, sizeof(res));
}

void bip85_entropy(const uint8_t master_k[32], const uint8_t master_c[32],
                   const uint32_t *path, int depth, uint8_t out[64], void (*step)(void)) {
    uint8_t I[64];
    uint8_t k[32];
    uint8_t c[32];
    uint8_t data[37];

    memcpy(k, master_k, 32);
    memcpy(c, master_c, 32);
    for (int i = 0; i < depth; i++) {
        data[0] = 0x00;                         // Hardened: 0x00 || k || index
        memcpy(data + 1, k, 32);
        data[33] = (uint8_t)(path[i] >> 24);
        data[34] = (uint8_t)(path[i] >> 16);
        data[35] = (uint8_t)(path[i] >> 8);
        data[36] = (uint8_t)path[i];
        HmacSha512(c, 32, data, 37, I);
        add_256_mod_n(k, I, k);                 // k_i = (I_L + k_parent) mod n
        memcpy(c, I + 32, 32);                  // c_i = I_R
        if (step != NULL) step();
    }
    HmacSha512((const uint8_t *)"bip-entropy-from-k", 18, k, 32, out);

    memzero(I, sizeof(I));
    memzero(k, sizeof(k));
    memzero(c, sizeof(c));
    memzero(data, sizeof(data));
}
