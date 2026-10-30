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

    // Hardened public derivation is impossible
    uint8_t chain[32], key[33];
    CHECK(!psbt_public_ckd(vec_chain[0], vec_pub[0], 0x80000000u, chain, key), "hardened index refused");

    if (failures == 0) printf("test_descriptor: all tests passed\n");
    return failures != 0;
}
