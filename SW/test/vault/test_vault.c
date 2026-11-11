// Host test of the vault module, crypto and format on a mock SD card, (../../src/vault.c, ../../src/bip85.c)
// against the independent Python reference gen_vault.py (vault_vectors.h).
//
/* Build and run (from this folder):
     gcc -O1 -Wall -I../../src -I../../src/crypto -I../../src/SSS -o test_vault test_vault.c
         ../../src/vault.c ../../src/bip85.c ../../src/kdf.c ../../src/sha512.c
         ../../src/sha256.c ../../src/SSS/memzero.c ../../src/ur_encode.c ../../src/bytewords.c
         ../../src/crypto/consteq.c ../../src/crypto/fault_handler_noop.c
         ../../src/crypto/aes/aescrypt.c ../../src/crypto/aes/aeskey.c
         ../../src/crypto/aes/aestab.c ../../src/crypto/aes/aesgcm.c ../../src/crypto/aes/gf128mul.c
     ./test_vault
   (one line for the gcc command; gen_vault.py rebuilds vault_vectors.h) */

#include <stdio.h>
#include <string.h>
#include "vault.h"
#include "bip85.h"
#include "ur_encode.h"
#include "vault_vectors.h"

static int failures;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

// ---- Mock SD card ------------------------------------------------------------

static uint8_t card[2048][512];
static int fail_write_sector = -1;              // Next write to this sector fails
static int corrupt_read_sector = -1;            // Reads of this sector come back changed
static uint8_t nonces[64][12];                  // Every record nonce written to the card
static int nonce_count;
static int nonce_reused;

bool vault_io_read(uint32_t sector, uint8_t buf[512]) {
    if (sector >= 2048) return false;
    memcpy(buf, card[sector], 512);
    if ((int)sector == corrupt_read_sector) buf[300] ^= 0x01;
    return true;
}

bool vault_io_write(uint32_t sector, const uint8_t buf[512]) {
    if (sector >= 2048) return false;
    if ((int)sector == fail_write_sector) {
        fail_write_sector = -1;
        return false;
    }
    if (sector >= VAULT_FIRST_SECTOR && sector <= VAULT_LAST_SECTOR && buf[0] == 'V' && buf[1] == 'R') {
        for (int i = 0; i < nonce_count; i++) {
            if (memcmp(nonces[i], &buf[VAULT_REC_NONCE], 12) == 0) nonce_reused = 1;
        }
        if (nonce_count < 64) memcpy(nonces[nonce_count++], &buf[VAULT_REC_NONCE], 12);
    }
    memcpy(card[sector], buf, 512);
    return true;
}

bool vault_io_marker_valid(const uint8_t buf[512]) {
    return memcmp(buf, "SEEDMATE", 8) == 0;
}

// Each initialization starts at another counter, as vault_new_id() makes it
static uint64_t next_first_counter = 0x1234;

static void fresh_card(const uint8_t id[VAULT_ID_LEN]) {
    memset(card, 0, sizeof(card));
    memcpy(card[2047], "SEEDMATE", 8);
    vault_header_init(card[VAULT_HEADER_SECTOR], id, next_first_counter);
    next_first_counter += 0x10000;
}

static void make_plain(uint8_t s[512], uint8_t type, const char *title, const char *body) {
    memset(s, 0, 512);
    uint8_t *pt = &s[VAULT_REC_DATA];
    pt[VAULT_PT_TYPE] = type;
    pt[VAULT_PT_TITLE_LEN] = (uint8_t)strlen(title);
    memcpy(&pt[VAULT_PT_TITLE], title, strlen(title));
    pt[VAULT_PT_BODY_LEN] = (uint8_t)(strlen(body) >> 8);
    pt[VAULT_PT_BODY_LEN + 1] = (uint8_t)strlen(body);
    memcpy(&pt[VAULT_PT_BODY], body, strlen(body));
}

// New one-sector entry; returns its sector (0 on error)
static uint16_t add_note(uint8_t s[512], const uint8_t *key, const char *title, const char *body) {
    uint16_t sec[1];
    uint64_t counter;
    if (vault_reserve(s, 1, sec, &counter) != VAULT_OK) return 0;
    make_plain(s, VAULT_TYPE_NOTE, title, body);
    if (vault_write_record(s, key, sec[0], counter, VAULT_PART_SINGLE) != VAULT_OK) return 0;
    if (vault_commit(s, sec, 1, NULL, 0) != VAULT_OK) return 0;
    return sec[0];
}

static uint64_t card_counter_raw(void) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | card[VAULT_HEADER_SECTOR][VAULT_HDR_COUNTER + i];
    return v;
}

// Counter relative to the first one of the current card
static uint64_t card_base;
#define card_counter() (card_counter_raw() - card_base)
#define FRESH_CARD() do { fresh_card(vec_vault_id); card_base = card_counter_raw(); } while (0)

static void fix_crc(uint8_t h[512]) {
    uint32_t crc = ~ur_crc32_update(0xFFFFFFFFu, h, 508);
    for (int i = 0; i < 4; i++) h[508 + i] = (uint8_t)(crc >> (24 - 8 * i));
}

static int is_zero(const uint8_t *p, int n) {
    for (int i = 0; i < n; i++) if (p[i]) return 0;
    return 1;
}

static void format_tests(void) {
    static uint8_t bitmap[VAULT_BITMAP_LEN];
    static vault_entry_t list[8];
    uint8_t s[512];
    uint8_t other_key[32];
    uint16_t count, others, sec[2];
    uint64_t counter;
    const uint8_t *key = vec_vault_key;

    memcpy(other_key, vec_vault_key, 32);
    other_key[31] ^= 0x5A;
    printf("\nformat (mock card)\n");

    FRESH_CARD();
    check(vault_open(s, bitmap) == VAULT_OK && vault_bitmap_count(bitmap) == 0, "open empty vault");
    check(vault_scan(s, key, bitmap, list, 8, &count, &others, NULL) == VAULT_OK && count == 0 && others == 0,
          "empty list");

    // Three entries, written out of order
    uint16_t z = add_note(s, key, "zeta", "last");
    uint16_t a = add_note(s, key, "Alpha", "first");
    uint16_t b = add_note(s, key, "beta", "second");
    check(z == 502 && a == 503 && b == 504, "lowest free sectors");
    check(card_counter() == 3, "counter 3 after three writes");
    vault_open(s, bitmap);
    check(vault_bitmap_count(bitmap) == 3 && vault_bitmap_test(bitmap, 503), "three bits marked");

    // A record of another passphrase on the same card
    check(vault_open(s, NULL) == VAULT_OK && add_note(s, other_key, "other", "x") == 505, "entry of another key");
    vault_open(s, bitmap);
    check(vault_scan(s, key, bitmap, list, 8, &count, &others, NULL) == VAULT_OK && count == 3 && others == 1,
          "list: 3 ours, 1 of another key");
    check(strcmp(list[0].title, "Alpha") == 0 && strcmp(list[1].title, "beta") == 0 &&
          strcmp(list[2].title, "zeta") == 0 && list[0].sector == 503, "sorted by title, case ignored");
    check(vault_scan(s, key, bitmap, list, 2, &count, &others, NULL) == VAULT_ERR_FULL && count == 2,
          "list full is reported");

    // Read one entry
    check(vault_read_record(s, key, 504) == VAULT_OK &&
          memcmp(&s[VAULT_REC_DATA + VAULT_PT_BODY], "second", 6) == 0, "read entry");
    check(vault_read_record(s, key, 505) == VAULT_ERR_NOT_OURS, "other key's entry not readable");

    // Edit: new version first, then the old one is freed and zeroed
    check(vault_reserve(s, 1, sec, &counter) == VAULT_OK && sec[0] == 506 && counter == card_base + 5, "edit: reserve");
    make_plain(s, VAULT_TYPE_NOTE, "beta", "second, edited");
    check(vault_write_record(s, key, sec[0], counter, VAULT_PART_SINGLE) == VAULT_OK, "edit: write new version");
    uint16_t old = 504;
    check(vault_commit(s, sec, 1, &old, 1) == VAULT_OK, "edit: commit");
    vault_open(s, bitmap);
    check(!vault_bitmap_test(bitmap, 504) && vault_bitmap_test(bitmap, 506) && is_zero(card[504], 512),
          "edit: old record freed and zeroed");
    check(vault_read_record(s, key, 506) == VAULT_OK &&
          memcmp(&s[VAULT_REC_DATA + VAULT_PT_BODY], "second, edited", 14) == 0, "edit: new text");

    // Delete
    uint16_t del = 502;
    check(vault_delete(s, &del, 1) == VAULT_OK, "delete");
    vault_open(s, bitmap);
    check(!vault_bitmap_test(bitmap, 502) && is_zero(card[502], 512), "delete: bit cleared, record zeroed");
    check(card_counter() == 5, "delete does not use a nonce");

    // A failed write: the nonce stays used, the sector free
    fail_write_sector = 502;
    check(vault_reserve(s, 1, sec, &counter) == VAULT_OK && sec[0] == 502 && counter == card_base + 6, "reserve before failure");
    make_plain(s, VAULT_TYPE_NOTE, "lost", "x");
    check(vault_write_record(s, key, sec[0], counter, VAULT_PART_SINGLE) == VAULT_ERR_WRITE, "write error reported");
    check(is_zero(s, 512), "plaintext wiped after the error");
    vault_open(s, NULL);                        // Even after closing and opening again
    check(add_note(s, key, "retry", "y") == 502 && card_counter() == 7, "retry uses the next nonce");

    // A write that does not read back
    corrupt_read_sector = 504;                  // First free sector now
    vault_open(s, NULL);
    check(vault_reserve(s, 1, sec, &counter) == VAULT_OK && sec[0] == 504, "reserve 504");
    make_plain(s, VAULT_TYPE_NOTE, "bad card", "z");
    check(vault_write_record(s, key, sec[0], counter, VAULT_PART_SINGLE) == VAULT_ERR_WRITE, "read-back failure reported");
    corrupt_read_sector = -1;

    // Only reserved nonces are sealed
    make_plain(s, VAULT_TYPE_NOTE, "x", "x");
    check(vault_write_record(s, key, 508, counter + 1, VAULT_PART_SINGLE) == VAULT_ERR_CLOSED, "unreserved nonce refused");
    check(vault_write_record(s, key, 501, counter, VAULT_PART_SINGLE) == VAULT_ERR_CLOSED, "header sector refused");
    check(vault_commit(s, (const uint16_t[]){199}, 1, NULL, 0) == VAULT_ERR_CLOSED, "seed slot refused");

    // Card swapped or changed behind the vault's back
    vault_open(s, NULL);
    card[VAULT_HEADER_SECTOR][VAULT_HDR_ID] ^= 1;
    vault_header_init(s, &card[VAULT_HEADER_SECTOR][VAULT_HDR_ID], card_counter_raw());   // Other card: other id
    memcpy(card[VAULT_HEADER_SECTOR], s, 512);
    check(vault_reserve(s, 1, sec, &counter) == VAULT_ERR_CHANGED, "other vault_id: refused");
    check(vault_delete(s, &old, 1) == VAULT_ERR_CHANGED, "other vault_id: delete refused");

    FRESH_CARD();
    vault_open(s, NULL);
    add_note(s, key, "a", "b");
    uint8_t saved[512];
    memcpy(saved, card[VAULT_HEADER_SECTOR], 512);
    card[VAULT_HEADER_SECTOR][VAULT_HDR_COUNTER + 7] = 9;   // Written elsewhere: other counter
    fix_crc(card[VAULT_HEADER_SECTOR]);
    check(vault_reserve(s, 1, sec, &counter) == VAULT_ERR_CHANGED, "other counter: refused");
    memcpy(card[VAULT_HEADER_SECTOR], saved, 512);
    card[VAULT_HEADER_SECTOR][VAULT_HDR_BITMAP + 5] ^= 0x10;  // Bitmap changed, CRC not
    check(vault_reserve(s, 1, sec, &counter) == VAULT_ERR_DAMAGED, "header with bad CRC: refused");
    memcpy(card[VAULT_HEADER_SECTOR], saved, 512);
    check(vault_reserve(s, 1, sec, &counter) == VAULT_OK, "same card again: accepted");

    memset(card[2047], 0, 512);
    check(vault_reserve(s, 1, sec, &counter) == VAULT_ERR_CHANGED, "marker gone: refused");
    memcpy(card[2047], "SEEDMATE", 8);

    memset(card[VAULT_HEADER_SECTOR], 0, 512);
    check(vault_open(s, NULL) == VAULT_ERR_DAMAGED, "no header: open refused");
    check(vault_reserve(s, 1, sec, &counter) == VAULT_ERR_CLOSED, "no header: nothing written");

    // Full vault: every sector but the last one used
    FRESH_CARD();
    memset(&card[VAULT_HEADER_SECTOR][VAULT_HDR_BITMAP], 0xFF, VAULT_BITMAP_LEN);
    card[VAULT_HEADER_SECTOR][VAULT_HDR_BITMAP + VAULT_BITMAP_LEN - 1] = 0x00;  // Bit 1544 (sector 2046) free
    fix_crc(card[VAULT_HEADER_SECTOR]);
    check(vault_open(s, bitmap) == VAULT_OK && vault_bitmap_count(bitmap) == 1544, "1544 of 1545 sectors used");
    check(vault_reserve(s, 2, sec, &counter) == VAULT_ERR_FULL, "two parts, one free sector: full");
    check(vault_reserve(s, 1, sec, &counter) == VAULT_OK && sec[0] == 2046, "last free sector is 2046");

    // Two-part entry
    FRESH_CARD();
    vault_open(s, NULL);
    check(vault_reserve(s, 2, sec, &counter) == VAULT_OK && sec[0] == 502 && sec[1] == 503 && counter == card_base + 1 &&
          card_counter() == 2, "two parts: two sectors, two nonces");
    make_plain(s, VAULT_TYPE_DESCRIPTOR, "MULTISIG", "part one");
    check(vault_write_record(s, key, sec[0], counter, VAULT_PART(1, 2)) == VAULT_OK, "part 1 of 2");
    make_plain(s, VAULT_TYPE_DESCRIPTOR, "MULTISIG", "part two");
    check(vault_write_record(s, key, sec[1], counter + 1, VAULT_PART(2, 2)) == VAULT_OK, "part 2 of 2");
    check(vault_commit(s, sec, 2, NULL, 0) == VAULT_OK, "commit both");
    vault_open(s, bitmap);
    check(vault_scan(s, key, bitmap, list, 8, &count, &others, NULL) == VAULT_OK && count == 1 && others == 0 &&
          list[0].sector == 502 && list[0].type == VAULT_TYPE_DESCRIPTOR, "listed once, by its first part");

    // Authenticates but out of range: damaged entry, never used
    vault_reserve(s, 1, sec, &counter);
    make_plain(s, VAULT_TYPE_NOTE, "x", "y");
    s[VAULT_REC_DATA + VAULT_PT_TITLE_LEN] = 30;
    vault_write_record(s, key, sec[0], counter, VAULT_PART_SINGLE);
    check(vault_read_record(s, key, sec[0]) == VAULT_ERR_ENTRY, "title length 30: entry damaged");

    check(!nonce_reused, "no nonce was ever written twice (several cards, same key)");
    vault_close();
}

int main(void) {
    uint8_t out[64];
    uint8_t key[32];
    uint8_t s[512];

    // BIP85 specification vectors
    const uint32_t hex64[4] = {BIP85_HARDENED | 83696968u, BIP85_HARDENED | 128169u,
                               BIP85_HARDENED | 64u, BIP85_HARDENED | 0u};
    bip85_entropy(vec_master_k, vec_master_c, hex64, 4, out, NULL);
    check(memcmp(out, vec_bip85_hex64, 64) == 0, "BIP85 HEX 64 bytes index 0");
    const uint32_t w12[5] = {BIP85_HARDENED | 83696968u, BIP85_HARDENED | 39u, BIP85_HARDENED | 0u,
                             BIP85_HARDENED | 12u, BIP85_HARDENED | 0u};
    bip85_entropy(vec_master_k, vec_master_c, w12, 5, out, NULL);
    check(memcmp(out, vec_bip85_bip39_12, 16) == 0, "BIP85 BIP39 12 words index 0");

    vault_derive_key(vec_master_k, vec_master_c, key);
    check(memcmp(key, vec_vault_key, 32) == 0, "vault key (HEX 32 bytes index 8377)");

    // Header
    vault_header_init(s, vec_vault_id, 0);
    check(memcmp(s, vec_header, 512) == 0, "header byte-exact");
    check(vault_header_valid(s), "header valid");
    s[100] ^= 1;
    check(!vault_header_valid(s), "damaged bitmap refused (CRC)");
    memcpy(s, vec_header, 512);
    s[8] = 2;
    check(!vault_header_valid(s), "other version refused");

    // Record seal: byte-exact with Python AES-GCM
    memset(s, 0xAA, sizeof(s));
    memcpy(&s[VAULT_REC_DATA], vec_record_plain, VAULT_REC_DATA_LEN);
    check(vault_record_seal(s, key, 502, 1, VAULT_PART_SINGLE), "seal");
    check(memcmp(s, vec_record, 512) == 0, "sealed record byte-exact");

    // Record open
    memcpy(s, vec_record, 512);
    check(vault_record_open(s, key, 502), "open");
    check(memcmp(&s[VAULT_REC_DATA], vec_record_plain, VAULT_REC_DATA_LEN) == 0, "plaintext");

    // A record sealed before the HMAC nonce (nonce = counter || sector) still opens
    memcpy(s, vec_record_legacy, 512);
    check(vault_record_open(s, key, 502), "record with the old nonce opens");
    check(memcmp(&s[VAULT_REC_DATA], vec_record_plain, VAULT_REC_DATA_LEN) == 0, "old record plaintext");

    // Audit M3: the same counter and sector again (an old header put back)
    // give another nonce to another text, and the very same record to the same text
    {
        static uint8_t a[512], b[512], c[512];
        memset(a, 0, 512);
        memcpy(&a[VAULT_REC_DATA], vec_record_plain, VAULT_REC_DATA_LEN);
        memcpy(c, a, 512);
        memcpy(b, a, 512);
        b[VAULT_REC_DATA + 30] ^= 1;                // Another text
        check(vault_record_seal(a, key, 502, 1, VAULT_PART_SINGLE) &&
              vault_record_seal(b, key, 502, 1, VAULT_PART_SINGLE) &&
              vault_record_seal(c, key, 502, 1, VAULT_PART_SINGLE), "seal three times with one counter");
        check(memcmp(&a[VAULT_REC_NONCE], &b[VAULT_REC_NONCE], 12) != 0, "another text, another nonce");
        check(memcmp(a, c, 512) == 0, "same text, same record");
    }

    memcpy(s, vec_record2, 512);
    check(vault_record_open(s, key, 2046), "open record 2 (sector 2046, long counter)");
    check(s[VAULT_REC_DATA + VAULT_PT_TYPE] == VAULT_TYPE_DESCRIPTOR && s[3] == 0x12,
          "record 2 type and part");

    // Refusals
    memcpy(s, vec_record, 512);
    check(!vault_record_open(s, key, 503), "record moved to another sector refused");
    memcpy(s, vec_record, 512);
    s[4 + 3] = 503 & 0xFF;                      // Header rewritten to match
    check(!vault_record_open(s, key, 503), "rewritten sector number refused (AAD)");
    memcpy(s, vec_record, 512);
    s[3] = 0x12;
    check(!vault_record_open(s, key, 502), "changed part byte refused (AAD)");
    memcpy(s, vec_record, 512);
    s[VAULT_REC_DATA + 10] ^= 0x80;
    check(!vault_record_open(s, key, 502), "changed ciphertext refused");
    memcpy(s, vec_record, 512);
    s[VAULT_REC_TAG] ^= 1;
    check(!vault_record_open(s, key, 502), "changed tag refused");
    memcpy(s, vec_record, 512);
    key[0] ^= 1;
    check(!vault_record_open(s, key, 502), "other key refused");
    memset(s, 0, sizeof(s));
    check(!vault_record_open(s, vec_vault_key, 502), "empty sector is not a record");

    format_tests();

    printf(failures ? "\n%d FAILED\n" : "\nall tests passed\n", failures);
    return failures != 0;
}
