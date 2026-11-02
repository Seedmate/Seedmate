/*******************************************************************************
 * Project:     SeedMate
 * File:        vault.c
 *
 * Summary:
 *   Vault key, header sector and AES-256-GCM records (see vault.h and
 *   ../docs/vault.md). AES and GCM come from the vendored trezor-crypto
 *   (Brian Gladman's code), built without tables to save flash and RAM.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include <string.h>
#include "vault.h"
#include "bip85.h"
#include "memzero.h"
#include "ur_encode.h"                          // ur_crc32_update()
#include "crypto/aes/aesgcm.h"

static const uint8_t header_magic[8] = {'S', 'M', 'V', 'A', 'U', 'L', 'T', 0};
#define HDR_VERSION     8u
#define HDR_CRC         508u
#define FORMAT_VERSION  1u

void vault_derive_key(const uint8_t master_k[32], const uint8_t master_c[32], uint8_t key[32]) {
    // m/83696968'/128169'/32'/8377': BIP85 HEX application, 32 bytes
    const uint32_t path[4] = {
        BIP85_HARDENED | 83696968u, BIP85_HARDENED | 128169u,
        BIP85_HARDENED | 32u, BIP85_HARDENED | VAULT_KEY_INDEX
    };
    uint8_t entropy[64];
    bip85_entropy(master_k, master_c, path, 4, entropy, NULL);
    memcpy(key, entropy, 32);
    memzero(entropy, sizeof(entropy));
}

static uint32_t header_crc(const uint8_t sector[512]) {
    return ~ur_crc32_update(0xFFFFFFFFu, sector, HDR_CRC);
}

static void put_be64(uint8_t *p, uint64_t v);

void vault_header_init(uint8_t sector[512], const uint8_t vault_id[VAULT_ID_LEN], uint64_t counter) {
    memset(sector, 0, 512);                     // Empty bitmap
    put_be64(&sector[VAULT_HDR_COUNTER], counter);
    memcpy(sector, header_magic, sizeof(header_magic));
    sector[HDR_VERSION] = FORMAT_VERSION;
    memcpy(&sector[VAULT_HDR_ID], vault_id, VAULT_ID_LEN);
    uint32_t crc = header_crc(sector);
    for (int i = 0; i < 4; i++) sector[HDR_CRC + i] = (uint8_t)(crc >> (24 - 8 * i));
}

bool vault_header_valid(const uint8_t sector[512]) {
    uint32_t crc = header_crc(sector);
    for (int i = 0; i < 4; i++) {
        if (sector[HDR_CRC + i] != (uint8_t)(crc >> (24 - 8 * i))) return false;
    }
    return memcmp(sector, header_magic, sizeof(header_magic)) == 0 && sector[HDR_VERSION] == FORMAT_VERSION;
}

// Plain header of a record (8 bytes, also the additional authenticated data)
static void record_header(uint8_t sector[512], uint32_t sector_no, uint8_t part) {
    sector[0] = 'V';
    sector[1] = 'R';
    sector[2] = FORMAT_VERSION;
    sector[3] = part;
    for (int i = 0; i < 4; i++) sector[4 + i] = (uint8_t)(sector_no >> (24 - 8 * i));
}

bool vault_record_seal(uint8_t sector[512], const uint8_t key[32], uint32_t sector_no,
                       uint64_t counter, uint8_t part) {
    gcm_ctx ctx;
    bool ok;

    record_header(sector, sector_no, part);
    for (int i = 0; i < 8; i++) sector[VAULT_REC_NONCE + i] = (uint8_t)(counter >> (56 - 8 * i));
    for (int i = 0; i < 4; i++) sector[VAULT_REC_NONCE + 8 + i] = (uint8_t)(sector_no >> (24 - 8 * i));

    ok = gcm_init_and_key(key, 32, &ctx) == RETURN_GOOD &&
         gcm_encrypt_message(&sector[VAULT_REC_NONCE], 12, sector, 8,
                             &sector[VAULT_REC_DATA], VAULT_REC_DATA_LEN,
                             &sector[VAULT_REC_TAG], 16, &ctx) == RETURN_GOOD;
    gcm_end(&ctx);
    memzero(&ctx, sizeof(ctx));
    return ok;
}

bool vault_record_open(uint8_t sector[512], const uint8_t key[32], uint32_t sector_no) {
    gcm_ctx ctx;
    bool ok;

    // The plain header must match where the record was read from
    if (sector[0] != 'V' || sector[1] != 'R' || sector[2] != FORMAT_VERSION) return false;
    for (int i = 0; i < 4; i++) {
        if (sector[4 + i] != (uint8_t)(sector_no >> (24 - 8 * i))) return false;
    }
    ok = gcm_init_and_key(key, 32, &ctx) == RETURN_GOOD &&
         gcm_decrypt_message(&sector[VAULT_REC_NONCE], 12, sector, 8,
                             &sector[VAULT_REC_DATA], VAULT_REC_DATA_LEN,
                             &sector[VAULT_REC_TAG], 16, &ctx) == RETURN_GOOD;
    gcm_end(&ctx);
    memzero(&ctx, sizeof(ctx));
    return ok;
}

// ---- Format ------------------------------------------------------------------

#define MARKER_SECTOR   2047u

// The open vault: what the header said when it was opened or last written
static struct {
    bool open;
    uint8_t id[VAULT_ID_LEN];
    uint64_t counter;
} session;

static uint64_t get_be64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static void put_be64(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)v; v >>= 8; }
}

static bool record_sector_ok(uint16_t sector_no) {
    return sector_no >= VAULT_FIRST_SECTOR && sector_no <= VAULT_LAST_SECTOR;
}

// Bit n of the bitmap (byte n / 8, bit n % 8, LSB first) = sector VAULT_FIRST_SECTOR + n
static void bitmap_set(uint8_t *bitmap, uint16_t sector_no, bool used) {
    uint16_t n = sector_no - VAULT_FIRST_SECTOR;
    if (used) bitmap[n >> 3] |= (uint8_t)(1u << (n & 7));
    else bitmap[n >> 3] &= (uint8_t)~(1u << (n & 7));
}

bool vault_bitmap_test(const uint8_t *bitmap, uint16_t sector_no) {
    uint16_t n = sector_no - VAULT_FIRST_SECTOR;
    return record_sector_ok(sector_no) && (bitmap[n >> 3] & (1u << (n & 7))) != 0;
}

uint16_t vault_bitmap_count(const uint8_t *bitmap) {
    uint16_t count = 0;
    for (uint16_t sector_no = VAULT_FIRST_SECTOR; sector_no <= VAULT_LAST_SECTOR; sector_no++) {
        if (vault_bitmap_test(bitmap, sector_no)) count++;
    }
    return count;
}

void vault_close(void) {
    memzero(&session, sizeof(session));
}

vault_status_t vault_open(uint8_t s[512], uint8_t *bitmap) {
    vault_close();
    if (!vault_io_read(VAULT_HEADER_SECTOR, s)) return VAULT_ERR_READ;
    if (!vault_header_valid(s)) return VAULT_ERR_DAMAGED;
    memcpy(session.id, &s[VAULT_HDR_ID], VAULT_ID_LEN);
    session.counter = get_be64(&s[VAULT_HDR_COUNTER]);
    session.open = true;
    if (bitmap != NULL) memcpy(bitmap, &s[VAULT_HDR_BITMAP], VAULT_BITMAP_LEN);
    return VAULT_OK;
}

// Before every write: the card must still be the one the vault was opened
// from (marker, vault_id and counter). VAULT_OK leaves the header in s.
static vault_status_t check_card(uint8_t s[512]) {
    if (!session.open) return VAULT_ERR_CLOSED;
    if (!vault_io_read(MARKER_SECTOR, s)) return VAULT_ERR_READ;
    if (!vault_io_marker_valid(s)) return VAULT_ERR_CHANGED;
    if (!vault_io_read(VAULT_HEADER_SECTOR, s)) return VAULT_ERR_READ;
    if (!vault_header_valid(s)) return VAULT_ERR_DAMAGED;
    if (memcmp(&s[VAULT_HDR_ID], session.id, VAULT_ID_LEN) != 0 ||
        get_be64(&s[VAULT_HDR_COUNTER]) != session.counter) return VAULT_ERR_CHANGED;
    return VAULT_OK;
}

// Writes the header in s with a new CRC and checks that it reads back
static vault_status_t store_header(uint8_t s[512]) {
    uint64_t counter = get_be64(&s[VAULT_HDR_COUNTER]);
    uint32_t crc = header_crc(s);
    for (int i = 0; i < 4; i++) s[HDR_CRC + i] = (uint8_t)(crc >> (24 - 8 * i));
    if (!vault_io_write(VAULT_HEADER_SECTOR, s)) return VAULT_ERR_WRITE;
    memset(s, 0, 512);
    if (!vault_io_read(VAULT_HEADER_SECTOR, s) || !vault_header_valid(s) ||
        header_crc(s) != crc || get_be64(&s[VAULT_HDR_COUNTER]) != counter) return VAULT_ERR_WRITE;
    session.counter = counter;
    return VAULT_OK;
}

vault_status_t vault_read_record(uint8_t s[512], const uint8_t key[32], uint16_t sector_no) {
    if (!record_sector_ok(sector_no)) return VAULT_ERR_NOT_OURS;
    if (!vault_io_read(sector_no, s)) return VAULT_ERR_READ;
    if (!vault_record_open(s, key, sector_no)) return VAULT_ERR_NOT_OURS;

    // Ours: the fields must be in range before anything uses them
    const uint8_t *pt = &s[VAULT_REC_DATA];
    uint8_t title_len = pt[VAULT_PT_TITLE_LEN];
    uint16_t body_len = (uint16_t)((pt[VAULT_PT_BODY_LEN] << 8) | pt[VAULT_PT_BODY_LEN + 1]);
    if (pt[VAULT_PT_TYPE] == 0 || title_len > VAULT_TITLE_MAX || body_len > VAULT_BODY_MAX) return VAULT_ERR_ENTRY;
    for (uint8_t i = 0; i < title_len; i++) {
        if (pt[VAULT_PT_TITLE + i] < 0x20 || pt[VAULT_PT_TITLE + i] > 0x7E) return VAULT_ERR_ENTRY;
    }
    return VAULT_OK;
}

// Title order, ignoring case; equal titles by sector
static int entry_cmp(const vault_entry_t *a, const vault_entry_t *b) {
    for (int i = 0; i <= (int)VAULT_TITLE_MAX; i++) {
        char ca = a->title[i], cb = b->title[i];
        if (ca >= 'a' && ca <= 'z') ca -= 32;
        if (cb >= 'a' && cb <= 'z') cb -= 32;
        if (ca != cb) return (ca < cb) ? -1 : 1;
        if (ca == 0) break;
    }
    return (a->sector < b->sector) ? -1 : (a->sector > b->sector);
}

vault_status_t vault_scan(uint8_t s[512], const uint8_t key[32], const uint8_t *bitmap,
                          vault_entry_t *list, uint16_t max, uint16_t *count, uint16_t *others,
                          void (*progress)(uint16_t done, uint16_t total)) {
    uint16_t total = vault_bitmap_count(bitmap);
    uint16_t done = 0;
    bool full = false;

    *count = 0;
    *others = 0;
    for (uint16_t sector_no = VAULT_FIRST_SECTOR; sector_no <= VAULT_LAST_SECTOR; sector_no++) {
        if (!vault_bitmap_test(bitmap, sector_no)) continue;
        if (progress != NULL) progress(done, total);
        done++;

        vault_status_t r = vault_read_record(s, key, sector_no);
        if (r == VAULT_ERR_READ) {
            memzero(s, 512);
            return r;
        }
        if (r != VAULT_OK) {
            (*others)++;                        // Another key, or damaged
        } else if ((s[3] >> 4) == 1) {          // First part of one of our entries
            if (*count < max) {
                vault_entry_t *e = &list[*count];
                uint8_t title_len = s[VAULT_REC_DATA + VAULT_PT_TITLE_LEN];
                e->sector = sector_no;
                e->type = s[VAULT_REC_DATA + VAULT_PT_TYPE];
                memcpy(e->title, &s[VAULT_REC_DATA + VAULT_PT_TITLE], title_len);
                e->title[title_len] = 0;
                (*count)++;
            } else {
                full = true;
            }
        }
        memzero(s, 512);
    }

    // Insertion sort, in place
    for (uint16_t i = 1; i < *count; i++) {
        vault_entry_t e = list[i];
        uint16_t j = i;
        while (j > 0 && entry_cmp(&list[j - 1], &e) > 0) {
            list[j] = list[j - 1];
            j--;
        }
        list[j] = e;
    }
    return full ? VAULT_ERR_FULL : VAULT_OK;
}

vault_status_t vault_reserve(uint8_t s[512], uint8_t parts, uint16_t sectors[], uint64_t *first_counter) {
    if (parts == 0 || parts > VAULT_MAX_PARTS) return VAULT_ERR_FULL;
    vault_status_t r = check_card(s);
    if (r != VAULT_OK) return r;

    // Lowest free sectors
    uint8_t found = 0;
    for (uint16_t sector_no = VAULT_FIRST_SECTOR; sector_no <= VAULT_LAST_SECTOR && found < parts; sector_no++) {
        if (!vault_bitmap_test(&s[VAULT_HDR_BITMAP], sector_no)) sectors[found++] = sector_no;
    }
    if (found < parts) return VAULT_ERR_FULL;

    // The nonces are recorded as used before any record is written
    *first_counter = session.counter + 1;
    put_be64(&s[VAULT_HDR_COUNTER], session.counter + parts);
    return store_header(s);
}

vault_status_t vault_write_record(uint8_t s[512], const uint8_t key[32], uint16_t sector_no,
                                  uint64_t counter, uint8_t part) {
    vault_status_t r = VAULT_OK;

    if (!session.open || !record_sector_ok(sector_no) || counter == 0 || counter > session.counter) {
        r = VAULT_ERR_CLOSED;                   // Not a reserved nonce: never seal
    } else if (!vault_record_seal(s, key, sector_no, counter, part) || !vault_io_write(sector_no, s)) {
        r = VAULT_ERR_WRITE;
    } else {
        memset(s, 0, 512);
        if (!vault_io_read(sector_no, s) || !vault_record_open(s, key, sector_no)) r = VAULT_ERR_WRITE;
    }
    memzero(s, 512);                            // Plaintext of the read-back check
    return r;
}

vault_status_t vault_commit(uint8_t s[512], const uint16_t *set, uint8_t n_set,
                            const uint16_t *clear, uint8_t n_clear) {
    for (uint8_t i = 0; i < n_set; i++) if (!record_sector_ok(set[i])) return VAULT_ERR_CLOSED;
    for (uint8_t i = 0; i < n_clear; i++) if (!record_sector_ok(clear[i])) return VAULT_ERR_CLOSED;

    vault_status_t r = check_card(s);
    if (r != VAULT_OK) return r;
    for (uint8_t i = 0; i < n_set; i++) bitmap_set(&s[VAULT_HDR_BITMAP], set[i], true);
    for (uint8_t i = 0; i < n_clear; i++) bitmap_set(&s[VAULT_HDR_BITMAP], clear[i], false);
    r = store_header(s);
    if (r != VAULT_OK) return r;

    // The old records are no longer listed; overwrite them
    memset(s, 0, 512);
    for (uint8_t i = 0; i < n_clear; i++) {
        if (!vault_io_write(clear[i], s)) r = VAULT_ERR_WRITE;
    }
    return r;
}
