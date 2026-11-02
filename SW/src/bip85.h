/*******************************************************************************
 * Project:     SeedMate
 * File:        bip85.h
 *
 * Summary:
 *   BIP85 entropy from a BIP32 master key: the child seeds (application 39)
 *   and the vault key (HEX application 128169) both come from here.
 ******************************************************************************/

#ifndef BIP85_H
#define BIP85_H

#include <stdint.h>

#define BIP85_HARDENED 0x80000000u

// Entropy of a hardened BIP85 path from the master private key k and chain
// code c: HMAC-SHA512("bip-entropy-from-k", k of the child), 64 bytes in out.
// Every path element must be hardened. step, if not NULL, is called after
// each derivation step (progress bar).
void bip85_entropy(const uint8_t master_k[32], const uint8_t master_c[32],
                   const uint32_t *path, int depth, uint8_t out[64], void (*step)(void));

#endif // BIP85_H
