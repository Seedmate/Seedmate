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

// Header fields
#define VAULT_HDR_COUNTER       16u             // write_counter, big endian
#define VAULT_HDR_BITMAP        32u             // bit n = sector VAULT_FIRST_SECTOR + n in use
#define VAULT_BITMAP_LEN        194u

// Part byte of a record: high nibble = part index (1..), low nibble = parts
#define VAULT_PART(index, parts) ((uint8_t)(((index) << 4) | (parts)))
#define VAULT_PART_SINGLE       VAULT_PART(1, 1)

#define VAULT_MAX_ENTRIES       255u
#define VAULT_MAX_PARTS         2u

typedef enum {
    VAULT_OK = 0,
    VAULT_ERR_READ,         // "SD READ ERROR"
    VAULT_ERR_WRITE,        // "SD WRITE ERROR" (also a write that does not read back)
    VAULT_ERR_NO_MARKER,    // "CARD NOT INITIALIZED"
    VAULT_ERR_DAMAGED,      // "VAULT MAP DAMAGED": no valid header, nothing is written
    VAULT_ERR_CHANGED,      // "CARD CHANGED": marker, vault_id or counter differ from the open vault
    VAULT_ERR_FULL,         // "VAULT FULL": no free sector (or no more list entries)
    VAULT_ERR_NOT_OURS,     // Record of another key (or not a record)
    VAULT_ERR_ENTRY,        // "ENTRY DAMAGED": authenticates but its fields are out of range
    VAULT_ERR_CLOSED        // No vault open (programming error)
} vault_status_t;

// One entry of the list (in the fountain buffer while the vault is open)
typedef struct {
    uint16_t sector;                            // First record of the entry
    uint8_t type;
    char title[VAULT_TITLE_MAX + 1];            // NUL terminated
} vault_entry_t;

// SD access, provided by main.c (and by the mock card of the host test).
// Each moves one 512 byte sector; false on a card error.
bool vault_io_read(uint32_t sector, uint8_t buf[512]);
bool vault_io_write(uint32_t sector, const uint8_t buf[512]);
bool vault_io_marker_valid(const uint8_t buf[512]);    // Sector 2047 as read

// Vault key: BIP85 HEX (32 bytes, index VAULT_KEY_INDEX) of the BIP32 master
// key k / chain code c of the seed with its passphrase
void vault_derive_key(const uint8_t master_k[32], const uint8_t master_c[32], uint8_t key[32]);

// Header sector written by INITIALIZE CARD: magic, version, vault_id, first
// write_counter, empty bitmap, CRC. The first counter is random (top bit
// clear): two cards with a vault of the same seed, or the same card
// initialized again, never use the same nonces with the same key.
void vault_header_init(uint8_t sector[512], const uint8_t vault_id[VAULT_ID_LEN], uint64_t counter);

// True if the sector is a valid header (magic, version and CRC)
bool vault_header_valid(const uint8_t sector[512]);

// Encrypts the plaintext in sector[VAULT_REC_DATA..] in place and fills the
// plain header, nonce and tag: record number 'sector_no' (VAULT_FIRST_SECTOR
// ..VAULT_LAST_SECTOR), write counter 'counter' (never reused), part byte
// (VAULT_PART()). Returns false on a cipher error.
bool vault_record_seal(uint8_t sector[512], const uint8_t key[32], uint32_t sector_no,
                       uint64_t counter, uint8_t part);

// Checks and decrypts a record read from sector 'sector_no' in place. True if
// it authenticates with this key (ours): the plaintext is then at
// sector[VAULT_REC_DATA..]. False: another key, damaged, or not a record (the
// buffer content is then undefined and must not be used).
bool vault_record_open(uint8_t sector[512], const uint8_t key[32], uint32_t sector_no);

// ---- Format: an open vault on the card --------------------------------------
// Every function takes the 512 byte sector buffer 's' as work space; its
// content is undefined afterwards unless said otherwise. The open vault keeps
// only vault_id and write_counter (to notice a swapped card).

// Reads the header. VAULT_OK: the vault is open and, if 'bitmap' is not NULL,
// the occupancy bitmap is copied there (VAULT_BITMAP_LEN bytes). Needs no
// marker: reading works on any card with a valid header.
vault_status_t vault_open(uint8_t s[512], uint8_t *bitmap);
void vault_close(void);

// Number of sectors marked in a bitmap, and whether 'sector_no' is marked
uint16_t vault_bitmap_count(const uint8_t *bitmap);
bool vault_bitmap_test(const uint8_t *bitmap, uint16_t sector_no);

// Reads record 'sector_no' and decrypts it with 'key'. VAULT_OK: the
// plaintext is at s[VAULT_REC_DATA..] (wipe it after use) and its fields are
// in range. VAULT_ERR_NOT_OURS: another key or not a record.
vault_status_t vault_read_record(uint8_t s[512], const uint8_t key[32], uint16_t sector_no);

// Builds the list: every marked sector is read and decrypted; the first part
// of each of our entries goes to 'list' (at most 'max'), sorted by title.
// 'others' counts the marked sectors that are not ours. 'progress' (or NULL)
// is called before each sector with (done, total).
vault_status_t vault_scan(uint8_t s[512], const uint8_t key[32], const uint8_t *bitmap,
                          vault_entry_t *list, uint16_t max, uint16_t *count, uint16_t *others,
                          void (*progress)(uint16_t done, uint16_t total));

// Writing an entry of 'parts' records (1 or 2), optionally replacing an old
// one (edit), in three calls:
//  1. vault_reserve(): checks the card (marker, header, vault_id, counter),
//     picks 'parts' free sectors and records in the header that their nonces
//     are used (counter += parts) BEFORE any record is written, so a nonce is
//     never reused even if a write fails half way.
//  2. vault_write_record() for each part, with the plaintext placed by the
//     caller at s[VAULT_REC_DATA..]: seal, write, read back and decrypt again.
//  3. vault_commit(): marks the new sectors, clears the old ones in the
//     header, then overwrites the old records with zeros.
vault_status_t vault_reserve(uint8_t s[512], uint8_t parts, uint16_t sectors[], uint64_t *first_counter);
vault_status_t vault_write_record(uint8_t s[512], const uint8_t key[32], uint16_t sector_no,
                                  uint64_t counter, uint8_t part);
vault_status_t vault_commit(uint8_t s[512], const uint16_t *set, uint8_t n_set,
                            const uint16_t *clear, uint8_t n_clear);

// Deletes an entry: header first, then the records are zeroed
#define vault_delete(s, sectors, n) vault_commit((s), NULL, 0, (sectors), (n))

#endif // VAULT_H
