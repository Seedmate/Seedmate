// Host tests for descriptor.c and psbt_public_ckd() (psbt_sign.c).
// Data from gen_descriptor.py: a 2-of-3 P2WSH wallet whose keys come from
// private BIP32 derivation in Python.
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "descriptor.h"
#include "psbt_sign.h"
#include "descriptor_vectors.h"
#include "ms_nested_vectors.h"
#include "ur_encode.h"
#include "sha256.h"
#include "crypto/ripemd160.h"

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

    // As a single part UR (the static QR of Sparrow's PDF): encode, decode
    // in place in the text as the scanner path does, parse
    {
        static char text[2 * sizeof(vec_output_cbor) + 64];
        ur_encoder_t e;
        CHECK(ur_encoder_init_type(&e, "crypto-output", vec_output_cbor, sizeof(vec_output_cbor), false,
                                   sizeof(vec_output_cbor)) && e.seq_len == 1, "single part crypto-output");
        CHECK(ur_encoder_part(&e, 1, text, sizeof(text)) > 0, "single part text");
        uint32_t got = ur_decode_single(text + strlen("UR:CRYPTO-OUTPUT/"), (uint8_t *)text, sizeof(text));
        CHECK(got == sizeof(vec_output_cbor) && memcmp(text, vec_output_cbor, got) == 0, "single part decodes");
        CHECK(desc_parse_cbor((const uint8_t *)text, got, &w) == DESC_OK, "single part parses");
        check_keys(&w, abc, "single part crypto-output");
    }
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
        copy[at + 4] = 0x01;                                // One key on testnet, the others not
        CHECK(desc_parse_cbor(copy, len, &w) == DESC_ERR_NETWORK && w.key_count == 0, "mixed networks refused");
        copy[at + 4] = 0x02;                                // No such network
        CHECK(desc_parse_cbor(copy, len, &w) == DESC_ERR_KEY, "network 2 refused");
        copy[at + 4] = 0x00;
        // Every key on testnet: a testnet wallet with the same keys
        int keys_on_testnet = 0;
        for (uint32_t k = 0; k + 5 <= len; k++) {
            if (memcmp(&copy[k], mainnet, 5) == 0) {
                copy[k + 4] = 0x01;
                keys_on_testnet++;
            }
        }
        CHECK(keys_on_testnet == 3 && desc_parse_cbor(copy, len, &w) == DESC_OK && w.testnet, "testnet wallet parses");
        check_keys(&w, abc, "testnet crypto-output");
        for (uint32_t k = 0; k + 5 <= len; k++) {
            if (copy[k] == 0xa2 && copy[k + 1] == 0x01 && copy[k + 2] == 0x00 && copy[k + 3] == 0x02 && copy[k + 4] == 0x01) {
                copy[k + 4] = 0x00;
            }
        }
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

// A crypto-output map that repeats the key array (two arrays of 7 keys) wrote
// past desc_wallet_t (security audit C1): it must be refused, the wallet left
// empty and nothing written after it
static uint8_t rep_cbor[2048];
static uint32_t rep_n;
static void rep_put(uint8_t b) { rep_cbor[rep_n++] = b; }
static void rep_head(uint8_t major, uint32_t v) {
    if (v < 24) rep_put((uint8_t)(major << 5 | v));
    else if (v < 256) { rep_put((uint8_t)(major << 5 | 24)); rep_put((uint8_t)v); }
    else { rep_put((uint8_t)(major << 5 | 25)); rep_put((uint8_t)(v >> 8)); rep_put((uint8_t)v); }
}

static void check_repeated_key_array(void) {
    struct { desc_wallet_t w; uint8_t canary[1024]; } s;
    rep_n = 0;
    rep_head(6, 401);                       // wsh
    rep_head(6, 407);                       // sortedmulti
    rep_head(5, 3);                         // threshold, keys, keys again
    rep_head(0, 1);
    rep_head(0, 2);
    for (int rep = 0; rep < 2; rep++) {
        rep_head(0, 2);
        rep_head(4, 7);
        for (int k = 0; k < 7; k++) {
            rep_head(6, 303);
            rep_head(5, 2);
            rep_head(0, 3);
            rep_head(2, 33);
            rep_put(0x02);
            for (int i = 0; i < 32; i++) rep_put((uint8_t)(0x41 + rep * 7 + k));
            rep_head(0, 4);
            rep_head(2, 32);
            for (int i = 0; i < 32; i++) rep_put((uint8_t)(0x41 + rep * 7 + k));
        }
    }
    memset(&s, 0, sizeof(s));
    memset(s.canary, 0xEE, sizeof(s.canary));
    CHECK(desc_parse_cbor(rep_cbor, rep_n, &s.w) == DESC_ERR_FORMAT && s.w.key_count == 0,
          "repeated key array refused");
    bool intact = true;
    for (uint32_t i = 0; i < sizeof(s.canary); i++) intact = intact && s.canary[i] == 0xEE;
    CHECK(intact, "nothing written past the wallet");
}

// Nested multisig (sh(wsh()), m/48h/0h/0h/1h) from gen_ms_nested.py: the
// descriptor, the Coldcard file with Ypub keys and the UR CBOR give the same
// wallet, flagged nested, whose change script and P2SH output match Python's
static void check_nested_wallet(const desc_wallet_t *w, const char *name) {
    char what[64];
    uint8_t script[3 + 34 * DESC_MAX_KEYS], sha[32], redeem[34], hash[20];
    SHA256_CTX ctx;

    snprintf(what, sizeof(what), "%s: nested 2 of 3 sortedmulti", name);
    CHECK(w->nested && w->sorted && w->threshold == 2 && w->key_count == 3, what);
    for (int i = 0; i < 3 && i < w->key_count; i++) {
        snprintf(what, sizeof(what), "%s key %d", name, i);
        CHECK(memcmp(w->keys[i].fingerprint, msn_fp[i], 4) == 0 && memcmp(w->keys[i].chain_code, msn_chain[i], 32) == 0 &&
              memcmp(w->keys[i].public_key, msn_pub[i], 33) == 0 && w->keys[i].origin_len == 4 &&
              w->keys[i].origin[3] == (1 | 0x80000000u), what);
    }
    uint32_t len = wallet_script(w, MSN_CHANGE, MSN_INDEX, script);
    snprintf(what, sizeof(what), "%s change script", name);
    CHECK(len == sizeof(msn_change_ws) && memcmp(script, msn_change_ws, len) == 0, what);
    // P2SH of OP_0 <sha256(ws)>, as ms_script_matches() in main.c builds it
    sha256_init(&ctx);
    sha256_update(&ctx, script, len);
    sha256_final(&ctx, &redeem[2]);
    redeem[0] = 0x00;
    redeem[1] = 0x20;
    sha256_init(&ctx);
    sha256_update(&ctx, redeem, sizeof(redeem));
    sha256_final(&ctx, sha);
    ripemd160(sha, 32, hash);
    snprintf(what, sizeof(what), "%s change P2SH output", name);
    CHECK(memcmp(hash, &msn_change_spk[2], 20) == 0, what);
}

static void test_nested_multisig(void) {
    desc_wallet_t w, w2;
    uint8_t blob[DESC_PACK_MAX];

    CHECK(desc_parse(msn_desc_text, (uint32_t)strlen(msn_desc_text), &w) == DESC_OK, "nested descriptor parses");
    CHECK(w.has_checksum, "nested descriptor checksum");
    check_nested_wallet(&w, "nested descriptor");
    uint32_t n = desc_pack(&w, blob);
    CHECK(desc_unpack(blob, n, &w2) && w2.nested, "nested flag kept in the vault copy");
    check_nested_wallet(&w2, "nested unpacked");

    CHECK(desc_parse(msn_cold_text, (uint32_t)strlen(msn_cold_text), &w) == DESC_OK, "nested coldcard file parses");
    check_nested_wallet(&w, "nested coldcard (Ypub)");

    CHECK(desc_parse_cbor(msn_output_cbor, sizeof(msn_output_cbor), &w) == DESC_OK, "nested crypto-output parses");
    check_nested_wallet(&w, "nested crypto-output");

    // The native descriptor of gen_descriptor.py is not nested
    CHECK(desc_parse(desc_text, (uint32_t)strlen(desc_text), &w) == DESC_OK && !w.nested, "native is not nested");
    printf("nested multisig: descriptor, Coldcard and CBOR agree\n");
}

// The single sig wallet descriptors the XPUB page saves to the SD card, with
// the checksums of the BIP380 reference code (gen_descriptor.py)
static void test_single_sig_checksums(void) {
    static const char *const descs[3] = {
        "wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V/<0;1>/*)#qf45pmyh",
        "sh(wpkh([73c5da0a/49h/0h/0h]xpub6C6nQwHaWbSrzs5tZ1q7m5R9cPK9eYpNMFesiXsYrgc1P8bvLLAet9JfHjYXKjToD8cBRswJXXbbFpXgwsswVPAZzKMa1jUp2kVkGVUaJa7/<0;1>/*))#zmygnj3e",
        "tr([73c5da0a/86h/0h/0h]xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ/<0;1>/*)#xf07c0qd",
    };
    for (int i = 0; i < 3; i++) {
        char sum[8];
        uint32_t n = (uint32_t)(strchr(descs[i], '#') - descs[i]);
        CHECK(desc_checksum(descs[i], n, sum) && memcmp(sum, descs[i] + n + 1, 8) == 0, "single sig descriptor checksum");
    }
}

// Base58Check for desc_format(), written here from the spec (the firmware
// passes its own base58_encode_check() of main.c): length and NUL, or 0
static size_t b58check(const uint8_t *data, size_t len, char *out, size_t cap) {
    static const char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    uint8_t buf[96], h1[32], h2[32], digits[140];
    SHA256_CTX c;
    size_t n = len + 4, nd = 0, zeros = 0, k = 0;
    if (n > sizeof(buf)) return 0;
    memcpy(buf, data, len);
    sha256_init(&c); sha256_update(&c, data, len); sha256_final(&c, h1);
    sha256_init(&c); sha256_update(&c, h1, 32); sha256_final(&c, h2);
    memcpy(buf + len, h2, 4);
    while (zeros < n && buf[zeros] == 0) zeros++;
    for (size_t i = zeros; i < n; i++) {
        unsigned carry = buf[i];
        for (size_t j = 0; j < nd; j++) {
            carry += (unsigned)digits[j] << 8;
            digits[j] = (uint8_t)(carry % 58);
            carry /= 58;
        }
        while (carry) { digits[nd++] = (uint8_t)(carry % 58); carry /= 58; }
    }
    if (zeros + nd + 1 > cap) return 0;
    for (size_t i = 0; i < zeros; i++) out[k++] = '1';
    while (nd) out[k++] = alphabet[digits[--nd]];
    out[k] = 0;
    return k + 1;
}

// The descriptor line of a test file: from its first "wsh(" or "sh(wsh(" to the end of the line
static void first_descriptor(const char *text, char *out, size_t cap) {
    const char *a = strstr(text, "sh(wsh(");
    const char *b = strstr(text, "wsh(");
    const char *p = (a != NULL && a < b) ? a : b;
    size_t n = strcspn(p, "\r\n");
    if (n >= cap) n = cap - 1;
    memcpy(out, p, n);
    out[n] = '\0';
}

// Two wallets with the same policy, keys, origins and xpub data
static bool same_wallet(const desc_wallet_t *a, const desc_wallet_t *b) {
    if (a->threshold != b->threshold || a->key_count != b->key_count || a->sorted != b->sorted ||
        a->nested != b->nested || a->testnet != b->testnet) return false;
    for (int i = 0; i < a->key_count; i++) {
        const desc_key_t *x = &a->keys[i], *y = &b->keys[i];
        if (memcmp(x->fingerprint, y->fingerprint, 4) || x->origin_len != y->origin_len ||
            memcmp(x->origin, y->origin, sizeof(x->origin)) || memcmp(x->chain_code, y->chain_code, 32) ||
            memcmp(x->public_key, y->public_key, 33) || x->depth != y->depth || x->child != y->child ||
            memcmp(x->parent_fp, y->parent_fp, 4) || !x->has_xpub_data || !y->has_xpub_data) return false;
    }
    return true;
}

// EXPORT DESCRIPTOR: every test wallet written back by desc_format() is the
// same text as the BIP389 descriptor of its file, checksum included; the
// Coldcard files and the CBOR give the same text as their descriptor
static void test_export(void) {
    static char out[DESC_FORMAT_CAP], want[DESC_FORMAT_CAP];
    desc_wallet_t w, w2;
    struct { const char *text; const uint8_t *cbor; uint32_t cbor_len; const char *ref; const char *name; } cases[] = {
        {desc_text, NULL, 0, desc_text, "native descriptor"},
        {cold_text, NULL, 0, desc_text, "native Coldcard (Zpub)"},
        {NULL, vec_output_cbor, sizeof(vec_output_cbor), desc_text, "native CBOR"},
        {NULL, vec_output_cbor_v2, sizeof(vec_output_cbor_v2), desc_text, "native CBOR v2 tags"},
        {msn_desc_text, NULL, 0, msn_desc_text, "nested descriptor"},
        {msn_cold_text, NULL, 0, msn_desc_text, "nested Coldcard (Ypub)"},
        {NULL, msn_output_cbor, sizeof(msn_output_cbor), msn_desc_text, "nested CBOR"},
        {desc_testnet, NULL, 0, desc_testnet, "testnet descriptor"},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char what[80];
        desc_result_t r = cases[i].text ? desc_parse(cases[i].text, (uint32_t)strlen(cases[i].text), &w)
                                        : desc_parse_cbor(cases[i].cbor, cases[i].cbor_len, &w);
        uint32_t n = (r == DESC_OK) ? desc_format(&w, out, sizeof(out), b58check) : 0;
        first_descriptor(cases[i].ref, want, sizeof(want));
        snprintf(what, sizeof(what), "export %s: the same text", cases[i].name);
        CHECK(n == strlen(want) && strcmp(out, want) == 0, what);
        if (n != strlen(want) || strcmp(out, want) != 0) printf("  got  %s\n  want %s\n", out, want);
        snprintf(what, sizeof(what), "export %s: parses back to the same wallet", cases[i].name);
        CHECK(desc_parse(out, n, &w2) == DESC_OK && same_wallet(&w, &w2) && w2.has_checksum, what);
        // The same wallet as a ur:crypto-output QR reads back to the same text
        static uint8_t cbor[1024];
        uint32_t clen = (r == DESC_OK) ? ur_output_cbor(&w, cbor, sizeof(cbor)) : 0;
        snprintf(what, sizeof(what), "export %s: crypto-output reads back the same", cases[i].name);
        CHECK(clen > 0 && desc_parse_cbor(cbor, clen, &w2) == DESC_OK && same_wallet(&w, &w2) &&
              desc_format(&w2, out, sizeof(out), b58check) == strlen(want) && strcmp(out, want) == 0, what);
        snprintf(what, sizeof(what), "export %s: crypto-output tags", cases[i].name);
        static const uint8_t wsh_sorted[6] = {0xD9, 0x01, 0x91, 0xD9, 0x01, 0x97}, sh[3] = {0xD9, 0x01, 0x90};
        CHECK(clen > 9 && (!w.nested || memcmp(cbor, sh, 3) == 0) && memcmp(cbor + (w.nested ? 3 : 0), wsh_sorted, 6) == 0, what);
        CHECK(ur_output_cbor(&w, cbor, clen - 1) == 0, "crypto-output: a buffer one byte short is refused");
    }

    // multi() keeps its key order; /0/* keys are written as /<0;1>/*
    CHECK(desc_parse(desc_multi, (uint32_t)strlen(desc_multi), &w) == DESC_OK, "multi parses");
    uint32_t n = desc_format(&w, out, sizeof(out), b58check);
    CHECK(n > 0 && strncmp(out, "wsh(multi(2,[bdc140de/", 22) == 0 && strstr(out, "/0/*") == NULL, "multi exported in order");
    CHECK(desc_parse(out, n, &w2) == DESC_OK && same_wallet(&w, &w2), "multi parses back");
    uint8_t cbor[1024];
    uint32_t clen = ur_output_cbor(&w, cbor, sizeof(cbor));
    CHECK(clen > 6 && cbor[5] == 0x96 && desc_parse_cbor(cbor, clen, &w2) == DESC_OK && same_wallet(&w, &w2) && !w2.sorted,
          "multi as crypto-output keeps its tag and key order");

    // Through the vault copy (format 2) the export is unchanged; a format 1
    // copy loads without xpub data and is not exported; a small buffer is refused
    uint8_t blob[DESC_PACK_MAX];
    CHECK(desc_parse(desc_text, (uint32_t)strlen(desc_text), &w) == DESC_OK, "descriptor for the vault copy");
    uint32_t len = desc_pack(&w, blob);
    CHECK(blob[0] == 2 && len == DESC_PACK_LEN(3) && desc_unpack(blob, len, &w2) && same_wallet(&w, &w2), "format 2 keeps the xpub data");
    first_descriptor(desc_text, want, sizeof(want));
    CHECK(desc_format(&w2, out, sizeof(out), b58check) == strlen(want) && strcmp(out, want) == 0, "export after the vault copy");
    uint8_t v1[DESC_PACK_HEADER + DESC_PACK_KEY_V1 * 3];
    memcpy(v1, blob, DESC_PACK_HEADER);
    v1[0] = 1;
    for (int k = 0; k < 3; k++) {
        memcpy(&v1[DESC_PACK_HEADER + DESC_PACK_KEY_V1 * k], &blob[DESC_PACK_HEADER + DESC_PACK_KEY * k], DESC_PACK_KEY_V1);
    }
    CHECK(desc_unpack(v1, sizeof(v1), &w2) && !w2.keys[0].has_xpub_data, "format 1 still loads");
    CHECK(desc_format(&w2, out, sizeof(out), b58check) == 0, "format 1 is not exported");
    CHECK(ur_output_cbor(&w2, cbor, sizeof(cbor)) == 0, "format 1 is not exported as a QR either");
    CHECK(desc_format(&w, out, 200, b58check) == 0, "a small buffer is refused");
    blob[DESC_PACK_HEADER + DESC_PACK_KEY_V1] = 2;  // The known flag of key 1 must be 0 or 1
    CHECK(!desc_unpack(blob, len, &w2), "bad xpub data flag refused");
    blob[DESC_PACK_HEADER + DESC_PACK_KEY_V1] = 1;
    CHECK(desc_unpack(blob, len, &w2), "flag back to 1 loads again");
    blob[DESC_PACK_HEADER + 4] = DESC_ORIGIN_MAX;   // Origin length of key 0 (audit I1)
    CHECK(desc_unpack(blob, len, &w2), "an origin of the full length loads");
    blob[DESC_PACK_HEADER + 4] = DESC_ORIGIN_MAX + 1;
    CHECK(!desc_unpack(blob, len, &w2) && w2.key_count == 0, "an origin longer than the array is refused");
    printf("export: %u test wallets written back identical\n", (unsigned)(sizeof(cases) / sizeof(cases[0])));
}

int main(void) {
    check_repeated_key_array();
    test_nested_multisig();
    test_single_sig_checksums();
    desc_wallet_t w;
    uint8_t script[3 + 34 * DESC_MAX_KEYS];
    static const int abc[3] = {0, 1, 2}, cab[3] = {2, 0, 1};

    // Sparrow style file: comments, BIP389 descriptor first
    CHECK(desc_parse(desc_text, (uint32_t)strlen(desc_text), &w) == DESC_OK, "descriptor file parses");
    CHECK(w.sorted && w.has_checksum, "sortedmulti with checksum");
    check_keys(&w, abc, "descriptor");
    uint32_t len = wallet_script(&w, VEC_CHANGE, VEC_INDEX, script);
    CHECK(len == sizeof(vec_script_sorted) && memcmp(script, vec_script_sorted, len) == 0, "sortedmulti change script");

    // Only the descriptor line, as in the static QR of Sparrow's PDF export
    {
        const char *line = strstr(desc_text, "wsh(");
        char one[1100];
        size_t n = 0;
        while (line != NULL && line[n] != '\0' && line[n] != '\n' && line[n] != '\r' && n < sizeof(one) - 1) {
            one[n] = line[n];
            n++;
        }
        one[n] = '\0';
        CHECK(line != NULL && desc_parse(one, (uint32_t)n, &w) == DESC_OK, "one line descriptor parses");
        CHECK(w.sorted && w.has_checksum, "one line: sortedmulti with checksum");
        check_keys(&w, abc, "one line");
    }

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

    // Testnet: the same keys as tpubs give a testnet wallet; the flag survives the vault copy
    {
        uint8_t blob[DESC_PACK_MAX];
        desc_wallet_t w2;
        CHECK(desc_parse(desc_testnet, (uint32_t)strlen(desc_testnet), &w) == DESC_OK && w.testnet, "tpub descriptor parses");
        check_keys(&w, abc, "testnet descriptor");
        CHECK(w.keys[0].origin[1] == 0x80000001u, "testnet origin 48h/1h");
        uint32_t n = desc_pack(&w, blob);
        CHECK(desc_unpack(blob, n, &w2) && w2.testnet && w2.keys[2].testnet, "testnet flag unpacked");
        CHECK(desc_parse(desc_text, (uint32_t)strlen(desc_text), &w) == DESC_OK && !w.testnet, "xpub descriptor is mainnet");
    }

    test_export();
    test_crypto_output();

    // Vault copy: pack, unpack, same keys and scripts; strict refusals
    {
        uint8_t blob[DESC_PACK_MAX + 1];
        desc_wallet_t w2;
        CHECK(desc_parse(desc_text, (uint32_t)strlen(desc_text), &w) == DESC_OK, "descriptor for pack");
        uint32_t n = desc_pack(&w, blob);
        CHECK(n == DESC_PACK_LEN(3), "pack length 4 + 86 per key");
        CHECK(desc_unpack(blob, n, &w2), "unpack");
        check_keys(&w2, abc, "unpacked");
        CHECK(w2.sorted && w2.has_checksum, "unpacked flags");
        for (int i = 0; i < 3; i++) {
            CHECK(memcmp(w2.keys[i].origin, w.keys[i].origin, sizeof(w.keys[i].origin)) == 0, "unpacked origin");
        }
        len = wallet_script(&w2, VEC_CHANGE, VEC_INDEX, script);
        CHECK(len == sizeof(vec_script_sorted) && memcmp(script, vec_script_sorted, len) == 0, "unpacked change script");
        CHECK(DESC_PACK_LEN(4) <= 450 && DESC_PACK_LEN(5) > 450 && DESC_PACK_MAX <= 450 + 452, "4 keys fit one vault record, 7 fit two");

        CHECK(!desc_unpack(blob, n - 1, &w2) && w2.key_count == 0, "truncated refused, cleared");
        CHECK(!desc_unpack(blob, n + 1, &w2), "too long refused");
        blob[0] = 3;
        CHECK(!desc_unpack(blob, n, &w2), "other format refused");
        blob[0] = 1;
        CHECK(!desc_unpack(blob, n, &w2), "format 1 with the length of format 2 refused");
        blob[0] = 2; blob[1] = 0;
        CHECK(!desc_unpack(blob, n, &w2), "threshold 0 refused");
        blob[1] = 4;
        CHECK(!desc_unpack(blob, n, &w2), "threshold above keys refused");
        blob[1] = 2; blob[3] = 16;
        CHECK(!desc_unpack(blob, n, &w2), "unknown flag refused");
        blob[3] = 3; blob[DESC_PACK_HEADER + 4 + 1 + 16 + 32] = 0x04;
        CHECK(!desc_unpack(blob, n, &w2), "uncompressed key refused");
    }

    // Hardened public derivation is impossible
    uint8_t chain[32], key[33];
    CHECK(!psbt_public_ckd(vec_chain[0], vec_pub[0], 0x80000000u, chain, key), "hardened index refused");

    if (failures == 0) printf("test_descriptor: all tests passed\n");
    return failures != 0;
}
