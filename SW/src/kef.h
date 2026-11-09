/*******************************************************************************
 * Project:     SeedMate
 * File:        kef.h
 *
 * Summary:
 *   KEF, the encrypted format Krux v26.09.0 uses for a mnemonic in a QR code.
 *
 * Description:
 *   No UI and no SD access; design in ../docs/kef.md. Envelope:
 *     len_id (1) | id | version (1) | iterations (3, big endian) | payload
 *   The key is PBKDF2-HMAC-SHA256 of the user's text with id as the salt.
 *   Seedmate writes version 20 (AES-GCM, tag cut to 4 bytes) and reads 20 and
 *   15 (AES-CTR). The QR text is base43. Host test in ../test/kef/.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#ifndef KEF_H
#define KEF_H

#include <stdint.h>
#include <stdbool.h>

#define KEF_KEY_SIZE    32
#define KEF_IV_LEN      12
#define KEF_TAG_LEN     4               // Version 20: first bytes of the GCM tag
#define KEF_AUTH_LEN    4               // Version 15: SHA-256 of the text, encrypted
#define KEF_ID_MAX      252
#define KEF_ITER_MIN    10000u
#define KEF_ITER_MAX    100000000u      // Stored 10,000 means 10,000 x 10,000
#define KEF_PLAIN_MAX   32              // BIP39 entropy, 16 or 32 bytes
#define KEF_ENVELOPE_MAX (1 + KEF_ID_MAX + 4 + KEF_IV_LEN + KEF_PLAIN_MAX + KEF_AUTH_LEN)

#define KEF_V_CTR       15
#define KEF_V_GCM       20

typedef enum {
    KEF_OK,
    KEF_ERR_FORMAT,                     // Not a KEF envelope
    KEF_ERR_VERSION,                    // A version Seedmate does not read
    KEF_ERR_ITERATIONS,                 // Under KEF_ITER_MIN, or cannot be stored
    KEF_ERR_SIZE,                       // A text or buffer of the wrong size
    KEF_ERR_AUTH                        // Wrong key or damaged data, on purpose not told apart
} kef_status_t;

typedef struct {
    const uint8_t *id;                  // In the caller's envelope, not terminated
    uint8_t id_len;
    uint8_t version;
    uint32_t iterations;                // Effective count
    const uint8_t *payload;
    uint32_t payload_len;
} kef_envelope_t;

// Called every few iterations; returns false to cancel. May be NULL.
typedef bool (*kef_progress_t)(uint32_t done, uint32_t total);

// Base43 (Electrum alphabet). Return the length written, 0 on a bad character
// or if it does not fit. text gets no terminator.
uint32_t kef_base43_encode(const uint8_t *data, uint32_t len, char *text, uint32_t cap);
uint32_t kef_base43_decode(const char *text, uint32_t len, uint8_t *data, uint32_t cap);

// Checks an envelope; env points into data.
kef_status_t kef_unwrap(const uint8_t *data, uint32_t len, kef_envelope_t *env);

// PBKDF2-HMAC-SHA256, one 32 byte block. False if the progress callback cancelled.
bool kef_derive_key(const uint8_t *secret, uint32_t secret_len, const uint8_t *id, uint32_t id_len,
                    uint32_t iterations, uint8_t key[KEF_KEY_SIZE], kef_progress_t progress);

// Version 20 envelope of plain (16 or 32 bytes) in out, *out_len its length.
// iv must never repeat with the same derived key.
kef_status_t kef_seal_v20(const uint8_t key[KEF_KEY_SIZE], const uint8_t *id, uint32_t id_len,
                          uint32_t iterations, const uint8_t iv[KEF_IV_LEN],
                          const uint8_t *plain, uint32_t plain_len,
                          uint8_t *out, uint32_t cap, uint32_t *out_len);

// Decrypts env into plain (KEF_PLAIN_MAX bytes); *plain_len its length.
// On any failure plain is wiped and the result is KEF_ERR_AUTH or KEF_ERR_SIZE.
kef_status_t kef_open(const uint8_t key[KEF_KEY_SIZE], const kef_envelope_t *env,
                      uint8_t *plain, uint32_t *plain_len);

#endif // KEF_H
