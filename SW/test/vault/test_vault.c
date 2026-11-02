// Host test of the vault module (../../src/vault.c, ../../src/bip85.c)
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
#include "vault_vectors.h"

static int failures;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
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
    vault_header_init(s, vec_vault_id);
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
    check(vault_record_seal(s, key, 502, 1, 0x01), "seal");
    check(memcmp(s, vec_record, 512) == 0, "sealed record byte-exact");

    // Record open
    memcpy(s, vec_record, 512);
    check(vault_record_open(s, key, 502), "open");
    check(memcmp(&s[VAULT_REC_DATA], vec_record_plain, VAULT_REC_DATA_LEN) == 0, "plaintext");

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
    s[3] = 0x02;
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

    printf(failures ? "\n%d FAILED\n" : "\nall tests passed\n", failures);
    return failures != 0;
}
