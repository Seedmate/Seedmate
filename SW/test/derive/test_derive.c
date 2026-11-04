// Host test of WALLET > DERIVE: BIP85 passwords (../../src/bip85.c) and the
// Nostr keys of NIP-06 (BIP32 of the vendored crypto, ../../src/nostr.c),
// against the vectors of gen_derive.py (checked there against BIP85 and NIP-06).
/* Build and run (from this folder), one line for gcc:
     gcc -std=c99 -O1 -Wall -Wextra -Wno-unused-parameter -I../../src -I../../src/crypto -I../../src/SSS -o test_derive
         test_derive.c ../../src/bip85.c ../../src/nostr.c ../../src/kdf.c ../../src/sha512.c
         ../../src/sha256.c ../../src/SSS/memzero.c ../../src/crypto/bip32.c ../../src/crypto/bignum.c
         ../../src/crypto/ecdsa.c ../../src/crypto/secp256k1.c ../../src/crypto/ripemd160.c
         ../../src/crypto/segwit_addr.c
     ./test_derive
   (gen_derive.py rebuilds derive_vectors.h) */

#include <stdio.h>
#include <string.h>
#include "bip85.h"
#include "nostr.h"
#include "bip32.h"
#include "derive_vectors.h"

static int failures;

static void check(int ok, const char *what) {
    printf("%s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) failures++;
}

// m/44'/1237'/0'/0/0 from a master key, as main.c derives it
static void nip06_key(const uint8_t *k, const uint8_t *c, HDNode *node) {
    memset(node, 0, sizeof(*node));
    memcpy(node->private_key, k, 32);
    memcpy(node->chain_code, c, 32);
    node->curve = get_curve_by_name("secp256k1");    // As main.c names it
    hdnode_private_ckd(node, 0x80000000u | NOSTR_ACCOUNT_PURPOSE);
    hdnode_private_ckd(node, 0x80000000u | NOSTR_COIN_TYPE);
    hdnode_private_ckd(node, 0x80000000u | 0);
    hdnode_private_ckd(node, 0);
    hdnode_private_ckd(node, 0);
    hdnode_fill_public_key(node);
}

int main(void) {
    char pwd[BIP85_PWD64_MAX + 1];
    char text[NOSTR_BECH32_LEN + 1];
    HDNode node;

    // BIP85 passwords: the specification vectors, then the longest of each
    check(bip85_password(vec_master_k, vec_master_c, BIP85_PWD_BASE64, 21, 0, pwd, NULL) &&
          strcmp(pwd, vec_pwd64_21_0) == 0, "BIP85 PWD BASE64 21 chars index 0");
    check(bip85_password(vec_master_k, vec_master_c, BIP85_PWD_BASE85, 12, 0, pwd, NULL) &&
          strcmp(pwd, vec_pwd85_12_0) == 0, "BIP85 PWD BASE85 12 chars index 0");
    check(bip85_password(vec_master_k, vec_master_c, BIP85_PWD_BASE64, 86, 7, pwd, NULL) &&
          strcmp(pwd, vec_pwd64_86_7) == 0, "BASE64 86 chars index 7");
    check(bip85_password(vec_master_k, vec_master_c, BIP85_PWD_BASE85, 80, 7, pwd, NULL) &&
          strcmp(pwd, vec_pwd85_80_7) == 0, "BASE85 80 chars index 7");
    check(!bip85_password(vec_master_k, vec_master_c, BIP85_PWD_BASE64, 19, 0, pwd, NULL) &&
          !bip85_password(vec_master_k, vec_master_c, BIP85_PWD_BASE64, 87, 0, pwd, NULL) &&
          !bip85_password(vec_master_k, vec_master_c, BIP85_PWD_BASE85, 9, 0, pwd, NULL) &&
          !bip85_password(vec_master_k, vec_master_c, BIP85_PWD_BASE85, 81, 0, pwd, NULL),
          "lengths out of range refused");

    // NIP-06 vectors: derivation, x-only key, npub and nsec
    nip06_key(vec_nip06_0_master_k, vec_nip06_0_master_c, &node);
    check(memcmp(node.private_key, vec_nip06_0_priv, 32) == 0, "NIP-06 vector 1 private key");
    check(memcmp(node.public_key + 1, vec_nip06_0_xonly, 32) == 0, "NIP-06 vector 1 public key");
    check(nostr_bech32("npub", node.public_key + 1, text) && strcmp(text, vec_nip06_0_npub) == 0, "vector 1 npub");
    check(nostr_bech32("nsec", node.private_key, text) && strcmp(text, vec_nip06_0_nsec) == 0, "vector 1 nsec");
    nip06_key(vec_nip06_1_master_k, vec_nip06_1_master_c, &node);
    check(memcmp(node.private_key, vec_nip06_1_priv, 32) == 0, "NIP-06 vector 2 private key");
    check(nostr_bech32("npub", node.public_key + 1, text) && strcmp(text, vec_nip06_1_npub) == 0, "vector 2 npub");
    check(nostr_bech32("nsec", node.private_key, text) && strcmp(text, vec_nip06_1_nsec) == 0, "vector 2 nsec");
    check(strlen(text) == NOSTR_BECH32_LEN, "bech32 length 63");

    printf(failures ? "\n%d FAILED\n" : "\nall tests passed\n", failures);
    return failures != 0;
}
