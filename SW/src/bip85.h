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
#include <stdbool.h>

#define BIP85_HARDENED 0x80000000u

// Entropy of a hardened BIP85 path from the master private key k and chain
// code c: HMAC-SHA512("bip-entropy-from-k", k of the child), 64 bytes in out.
// Every path element must be hardened. step, if not NULL, is called after
// each derivation step (progress bar).
void bip85_entropy(const uint8_t master_k[32], const uint8_t master_c[32],
                   const uint32_t *path, int depth, uint8_t out[64], void (*step)(void));

// BIP85 passwords: PWD BASE64 (application 707764', 20..86 characters) and
// PWD BASE85 (application 707785', 10..80 characters, the RFC 1924 alphabet
// of Python's base64.b85encode), m/83696968'/app'/length'/index': the first
// 'len' characters of the encoded 64 bytes of entropy. out holds len + 1.
// False if the length is out of range for the format. Four derivation steps.
#define BIP85_PWD_BASE64        0
#define BIP85_PWD_BASE85        1
#define BIP85_PWD64_MIN         20
#define BIP85_PWD64_MAX         86
#define BIP85_PWD85_MIN         10
#define BIP85_PWD85_MAX         80
bool bip85_password(const uint8_t master_k[32], const uint8_t master_c[32], uint8_t format,
                    uint8_t len, uint32_t index, char *out, void (*step)(void));

#endif // BIP85_H
