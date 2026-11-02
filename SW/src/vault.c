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

void vault_header_init(uint8_t sector[512], const uint8_t vault_id[VAULT_ID_LEN]) {
    memset(sector, 0, 512);                     // Counter 0, empty bitmap
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
