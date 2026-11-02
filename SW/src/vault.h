/*******************************************************************************
 * Project:     SeedMate
 * File:        vault.h
 *
 * Summary:
 *   Vault on the seed SD card: the key, the header sector and the encrypted
 *   records (AES-256-GCM). The format is specified in ../docs/vault.md; this
 *   module has no SD access and no UI, so it can be tested on a host.
 ******************************************************************************/

#ifndef VAULT_H
#define VAULT_H

#include <stdint.h>
#include <stdbool.h>

#define VAULT_HEADER_SECTOR     501u
#define VAULT_FIRST_SECTOR      502u
#define VAULT_LAST_SECTOR       2046u           // The card marker is at 2047
#define VAULT_SECTORS           (VAULT_LAST_SECTOR - VAULT_FIRST_SECTOR + 1u)   // 1545

#define VAULT_KEY_INDEX         8377u           // BIP85 HEX index ("SM")
#define VAULT_ID_LEN            8u
#define VAULT_HDR_ID            24u             // vault_id offset in the header

// Record sector: plain header, nonce, ciphertext, GCM tag
#define VAULT_REC_NONCE         8u
#define VAULT_REC_DATA          20u
#define VAULT_REC_DATA_LEN      476u
#define VAULT_REC_TAG           496u

// Plaintext of a record
#define VAULT_PT_TYPE           0u
#define VAULT_PT_TITLE_LEN      1u
#define VAULT_PT_TITLE          2u
#define VAULT_TITLE_MAX         20u
#define VAULT_PT_BODY_LEN       22u
#define VAULT_PT_BODY           24u
#define VAULT_BODY_MAX          452u
#define VAULT_TEXT_MAX          400u            // Notes: the text editor buffer

// Entry types (the template the entry started from)
#define VAULT_TYPE_NOTE         1u
#define VAULT_TYPE_LOGIN        2u
#define VAULT_TYPE_PASSPHRASE   3u
#define VAULT_TYPE_CARD         4u
#define VAULT_TYPE_DESCRIPTOR   16u

// Vault key: BIP85 HEX (32 bytes, index VAULT_KEY_INDEX) of the BIP32 master
// key k / chain code c of the seed with its passphrase
void vault_derive_key(const uint8_t master_k[32], const uint8_t master_c[32], uint8_t key[32]);

// Header sector written by INITIALIZE CARD: magic, version, vault_id,
// counter 0, empty bitmap, CRC
void vault_header_init(uint8_t sector[512], const uint8_t vault_id[VAULT_ID_LEN]);

// True if the sector is a valid header (magic, version and CRC)
bool vault_header_valid(const uint8_t sector[512]);

// Encrypts the plaintext in sector[VAULT_REC_DATA..] in place and fills the
// plain header, nonce and tag: record number 'sector_no' (VAULT_FIRST_SECTOR
// ..VAULT_LAST_SECTOR), write counter 'counter' (never reused), part byte
// (index << 4 | parts). Returns false on a cipher error.
bool vault_record_seal(uint8_t sector[512], const uint8_t key[32], uint32_t sector_no,
                       uint64_t counter, uint8_t part);

// Checks and decrypts a record read from sector 'sector_no' in place. True if
// it authenticates with this key (ours): the plaintext is then at
// sector[VAULT_REC_DATA..]. False: another key, damaged, or not a record (the
// buffer content is then undefined and must not be used).
bool vault_record_open(uint8_t sector[512], const uint8_t key[32], uint32_t sector_no);

#endif // VAULT_H
