// Host tests for descriptor.c and psbt_public_ckd() (psbt_sign.c).
// Data from gen_descriptor.py: a 2-of-3 P2WSH wallet whose keys come from
// private BIP32 derivation in Python.
#include <stdio.h>
#include <string.h>
#include "descriptor.h"
#include "psbt_sign.h"
#include "descriptor_vectors.h"

static int failures = 0;

#define CHECK(cond, what) do { \
    if (!(cond)) { printf("FAIL: %s (line %d)\n", what, __LINE__); failures++; } \
} while (0)

static void check_keys(const desc_wallet_t *w, const int *order, const char *name) {
    char what[64];
    CHECK(w->threshold == 2 && w->key_count == 3, name);
    for (int i = 0; i < 3 && i < w->key_count; i++) {
        int v = order[i];
        snprintf(what, sizeof(what), "%s key %d", name, i);
        CHECK(memcmp(w->keys[i].fingerprint, vec_fp[v], 4) == 0, what);
        CHECK(memcmp(w->keys[i].chain_code, vec_chain[v], 32) == 0, what);
        CHECK(memcmp(w->keys[i].public_key, vec_pub[v], 33) == 0, what);
        CHECK(w->keys[i].origin_len == 4 && w->keys[i].origin[0] == (48 | 0x80000000u) &&
              w->keys[i].origin[3] == (2 | 0x80000000u), what);
    }
}

// Derives every cosigner key at change/index from its xpub and builds the script
static uint32_t wallet_script(const desc_wallet_t *w, uint32_t change, uint32_t index, uint8_t *out) {
    uint8_t keys[DESC_MAX_KEYS][33];
    uint8_t chain[32];
    for (int i = 0; i < w->key_count; i++) {
        if (!psbt_public_ckd(w->keys[i].chain_code, w->keys[i].public_key, change, chain, keys[i]) ||
            !psbt_public_ckd(chain, keys[i], index, chain, keys[i])) {
            return 0;
        }
    }
    return desc_witness_script((const uint8_t (*)[33])keys, w->key_count, w->threshold, w->sorted, out);
}

// Finds 'pat' in buf (first occurrence) or returns -1
static long find_bytes(const uint8_t *buf, uint32_t len, const uint8_t *pat, uint32_t pat_len) {
    for (uint32_t i = 0; i + pat_len <= len; i++) {
        if (memcmp(&buf[i], pat, pat_len) == 0) return (long)i;
    }
    return -1;
}

// UR crypto-output CBOR of the same wallet: keys, script, and refusals of altered copies
static void test_crypto_output(void) {
    static const int abc[3] = {0, 1, 2};
    static uint8_t copy[sizeof(vec_output_cbor)];
    uint8_t script[3 + 34 * DESC_MAX_KEYS];
    desc_wallet_t w;
    uint32_t len = sizeof(copy);

    CHECK(desc_parse_cbor(vec_output_cbor, len, &w) == DESC_OK, "crypto-output parses");
    CHECK(w.sorted && w.has_checksum, "crypto-output is sortedmulti");
    check_keys(&w, abc, "crypto-output");
    uint32_t n = wallet_script(&w, VEC_CHANGE, VEC_INDEX, script);
    CHECK(n == sizeof(vec_script_sorted) && memcmp(script, vec_script_sorted, n) == 0, "crypto-output change script");
    CHECK(desc_parse_cbor(vec_output_cbor_v2, sizeof(vec_output_cbor_v2), &w) == DESC_OK, "crypto-output v2 tags parse");
    check_keys(&w, abc, "crypto-output v2");

    memcpy(copy, vec_output_cbor, len);
    CHECK(desc_parse_cbor(copy, len - 1, &w) == DESC_ERR_FORMAT && w.key_count == 0, "truncated CBOR refused");
    static const uint8_t wsh_tag[3] = {0xd9, 0x01, 0x91}, mainnet[5] = {0xa2, 0x01, 0x00, 0x02, 0x00};
    static const uint8_t not_private[2] = {0x02, 0xf4};
    long at = find_bytes(copy, len, wsh_tag, 3);
    CHECK(at == 0, "starts with wsh tag");
    copy[2] = 0x94;                                         // wpkh (404)
    CHECK(desc_parse_cbor(copy, len, &w) == DESC_ERR_SCRIPT, "wpkh refused");
    copy[2] = 0x91;
    at = find_bytes(copy, len, mainnet, 5);
    CHECK(at > 0, "use-info found");
    if (at > 0) {
        copy[at + 4] = 0x01;                                // testnet
        CHECK(desc_parse_cbor(copy, len, &w) == DESC_ERR_NETWORK, "testnet key refused");
        copy[at + 4] = 0x00;
    }
    at = find_bytes(copy, len, not_private, 2);
    CHECK(at > 0, "is-private found");
    if (at > 0) {
        copy[at + 1] = 0xf5;                                // private key
        CHECK(desc_parse_cbor(copy, len, &w) == DESC_ERR_KEY, "private key refused");
        copy[at + 1] = 0xf4;
    }
    CHECK(desc_parse_cbor(copy, len, &w) == DESC_OK, "restored copy parses");
}

int main(void) {
    desc_wallet_t w;
    uint8_t script[3 + 34 * DESC_MAX_KEYS];
    static const int abc[3] = {0, 1, 2}, cab[3] = {2, 0, 1};

    // Sparrow style file: comments, BIP389 descriptor first
    CHECK(desc_parse(desc_text, (uint32_t)strlen(desc_text), &w) == DESC_OK, "descriptor file parses");
    CHECK(w.sorted && w.has_checksum, "sortedmulti with checksum");
    check_keys(&w, abc, "descriptor");
    uint32_t len = wallet_script(&w, VEC_CHANGE, VEC_INDEX, script);
    CHECK(len == sizeof(vec_script_sorted) && memcmp(script, vec_script_sorted, len) == 0, "sortedmulti change script");

    // multi(): keys in the given order
    CHECK(desc_parse(desc_multi, (uint32_t)strlen(desc_multi), &w) == DESC_OK, "multi parses");
    CHECK(!w.sorted, "multi is not sorted");
    check_keys(&w, cab, "multi");
    len = wallet_script(&w, VEC_CHANGE, VEC_INDEX, script);
    CHECK(len == sizeof(vec_script_multi) && memcmp(script, vec_script_multi, len) == 0, "multi change script");

    // Coldcard file with Zpub keys
    CHECK(desc_parse(cold_text, (uint32_t)strlen(cold_text), &w) == DESC_OK, "coldcard file parses");
    CHECK(w.sorted && !w.has_checksum, "coldcard is sortedmulti, no checksum");
    check_keys(&w, abc, "coldcard");
    len = wallet_script(&w, VEC_CHANGE, VEC_INDEX, script);
    CHECK(len == sizeof(vec_script_sorted) && memcmp(script, vec_script_sorted, len) == 0, "coldcard change script");

    // Refusals, each with its reason; the wallet is left empty
    for (size_t i = 0; i < sizeof(desc_neg) / sizeof(desc_neg[0]); i++) {
        char what[64];
        desc_result_t r = desc_parse(desc_neg[i].text, (uint32_t)strlen(desc_neg[i].text), &w);
        snprintf(what, sizeof(what), "negative case %u: got %d (%s)", (unsigned)i, r, desc_error_text(r));
        CHECK(r == desc_neg[i].expected, what);
        CHECK(w.key_count == 0, "wallet cleared on error");
    }

    test_crypto_output();

    // Hardened public derivation is impossible
    uint8_t chain[32], key[33];
    CHECK(!psbt_public_ckd(vec_chain[0], vec_pub[0], 0x80000000u, chain, key), "hardened index refused");

    if (failures == 0) printf("test_descriptor: all tests passed\n");
    return failures != 0;
}
