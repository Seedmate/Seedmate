/*******************************************************************************
 * Project:     SeedMate
 * File:        kdf.h
 *
 * Summary:
 *   HMAC-SHA512 and PBKDF2-HMAC-SHA512 (BIP39 seed, BIP32, BIP85).
 *
 * Description:
 *   No fixed-size copies of the inputs: the passphrase (salt) can have any
 *   length. Intermediate values that depend on the secret are wiped.
 *   The display is not touched here; long runs report progress through a
 *   callback so the caller can draw a bar and keep the MCU tasks running.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#ifndef KDF_H
#define KDF_H

#include <stddef.h>
#include <stdint.h>

#define KDF_SHA512_SIZE 64

// HMAC-SHA512 (RFC 2104). out may be the same buffer as data.
void HmacSha512(const uint8_t *key, size_t keyLen,
                const uint8_t *data, size_t dataLen,
                uint8_t *out);

// Called by PBKDF2 every few iterations with (iteration, iterations); may be NULL.
typedef void (*kdf_progress_t)(uint32_t done, uint32_t total);

// PBKDF2-HMAC-SHA512 (RFC 8018). For BIP39: password = mnemonic,
// salt = "mnemonic" + passphrase, 2048 iterations, 64-byte output.
void PBKDF2_HMAC_SHA512(const char *password, const char *salt,
                        uint32_t iterations, uint8_t *output, size_t dkLen,
                        kdf_progress_t progress);

#endif // KDF_H
