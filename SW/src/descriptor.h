/*******************************************************************************
 * Project:     SeedMate
 * File:        descriptor.h
 *
 * Summary:
 *   Multisig wallet descriptor parser (cosigner xpubs, threshold, order).
 *
 * Description:
 *   Reads the two text formats that wallets export for a P2WSH multisig
 *   signer, as found in a file or a QR code (examples below):
 *
 *   - Output descriptor (BIP380/381/383/389), the first non-comment line.
 *     multi() is accepted too (keys kept in their order). Each key must end
 *     with the receive/change branches 0 and 1 and the wildcard. The
 *     checksum is verified when present.
 *   - Coldcard multisig setup file (also written by Sparrow). Always
 *     sortedmulti; no checksum.
 *   - UR "crypto-output" CBOR (BCR-2020-010), the animated "Output
 *     Descriptor" QR of Sparrow read by Krux, SeedSigner and Jade:
 *     wsh(sortedmulti/multi(hdkey...)), also with the v2 tags (40303...).
 *     Children paths are not stored: branches 0 and 1 are assumed, and a
 *     wallet that used others would simply never match a PSBT.
 *
 *   Only mainnet P2WSH is accepted: the signer only signs P2WSH inputs.
 *   No elliptic curve code here: keys are stored as given and derived by
 *   the caller (psbt_public_ckd() in psbt_sign.c). Host tests in
 *   ../test/psbt/test_descriptor.c.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

// Accepted texts:
//   wsh(sortedmulti(2,[b0b0b0b0/48h/0h/0h/2h]xpub.../<0;1>/*,...))#checksum
//   keys ending in /<0;1>/*, /0/* or /1/*
//
//   Policy: 2 of 3
//   Format: P2WSH
//   Derivation: m/48'/0'/0'/2'
//   B0B0B0B0: xpub... (or Zpub...)

#ifndef DESCRIPTOR_H
#define DESCRIPTOR_H

#include <stdint.h>
#include <stdbool.h>

#define DESC_MAX_KEYS   7       // Cosigners kept in RAM (86 bytes each)
#define DESC_ORIGIN_MAX 4       // Origin path elements kept (BIP48: 4)

typedef struct {
    uint8_t fingerprint[4];     // Master fingerprint of the key origin (0 if none)
    uint8_t origin_len;         // Origin path elements given (may exceed DESC_ORIGIN_MAX)
    uint32_t origin[DESC_ORIGIN_MAX];
    uint8_t chain_code[32];
    uint8_t public_key[33];
} desc_key_t;

typedef struct {
    uint8_t threshold;          // m of m-of-n
    uint8_t key_count;          // n
    bool sorted;                // sortedmulti (BIP67 key order) instead of multi
    bool has_checksum;          // A descriptor checksum was present (and matched)
    desc_key_t keys[DESC_MAX_KEYS];
} desc_wallet_t;

typedef enum {
    DESC_OK = 0,
    DESC_ERR_FORMAT,            // Not a descriptor / setup file we understand
    DESC_ERR_SCRIPT,            // Not wsh() multisig (sh, wpkh, tr, nested...)
    DESC_ERR_CHECKSUM,          // Descriptor checksum does not match
    DESC_ERR_KEY,               // Bad xpub (base58 checksum, length, prefix)
    DESC_ERR_NETWORK,           // Testnet key
    DESC_ERR_TOO_MANY,          // More than DESC_MAX_KEYS cosigners
    DESC_ERR_THRESHOLD,         // m is 0, larger than n, or Policy disagrees
    DESC_ERR_PATH,              // Key derivation is not /<0;1>/*, /0/* or /1/*
    DESC_ERR_DUPLICATE,         // The same key twice
} desc_result_t;

// Parses 'len' bytes of text (a whole file or QR payload) into *out.
// *out is cleared first, and again on error.
desc_result_t desc_parse(const char *text, uint32_t len, desc_wallet_t *out);

// The same for the CBOR of a UR "crypto-output" (already checked by its CRC32,
// so has_checksum is set)
desc_result_t desc_parse_cbor(const uint8_t *data, uint32_t len, desc_wallet_t *out);

// Short reason for the screen (at most 20 characters)
const char *desc_error_text(desc_result_t r);

// Witness script "OP_m <keys> OP_n OP_CHECKMULTISIG" of n compressed keys,
// sorted (BIP67) if 'sorted'. out must hold 3 + 34 * n bytes. Returns its length.
uint32_t desc_witness_script(const uint8_t keys[][33], uint8_t n, uint8_t m, bool sorted, uint8_t *out);

#endif // DESCRIPTOR_H
