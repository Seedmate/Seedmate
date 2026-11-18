// Hostile PSBTs against the firmware's parser (psbt.c) and signing decision
// (psbt_check_owner(), psbt_plan_signing(), copied from main.c by extract_plan.py).
//
// Two sets, both for the seed "abandon x11 about":
//   malicious/*.psbt     the psbt_faker corpus as vendored by ShieldSigner (see
//                        malicious/README.md); malicious_truth.txt says what each
//                        one is and how many outputs really belong to the seed
//   bip174_invalid.txt   the "invalid PSBT" vectors of BIP174
//
// What is checked:
//   - the outcome of each vector is the one in malicious_expected.txt (run with
//     --update to rewrite it, then review the diff)
//   - safety, against the corpus' own truth, whatever that file says: never more
//     outputs called ours than really are, a vector meant to be refused is
//     refused or listed as a known gap in malicious_gaps.txt
//
// Build and run from this folder (one line for gcc):
//   python extract_plan.py
//   gcc -std=c99 -O1 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -I../../src
//       -I../../src/crypto -I../../src/SSS -o test_malicious test_malicious.c ../../src/psbt.c
//       ../../src/psbt_sign.c ../../src/descriptor.c ../../src/ur_encode.c ../../src/bytewords.c
//       ../../src/sha256.c ../../src/sha512.c ../../src/kdf.c ../../src/SSS/memzero.c
//       ../../src/crypto/bip32.c ../../src/crypto/bignum.c ../../src/crypto/ecdsa.c
//       ../../src/crypto/secp256k1.c ../../src/crypto/ripemd160.c ../../src/crypto/segwit_addr.c
//   ./test_malicious
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "psbt.h"
#include "psbt_sign.h"
#include "descriptor.h"
#include "sha256.h"
#include "memzero.h"
#include "crypto/bip32.h"
#include "crypto/ripemd160.h"
#include "crypto/segwit_addr.h"
#include "ms_nested_vectors.h"      // Expected multisig addresses (gen_ms_nested.py)
#include "testnet_vectors.h"        // The testnet wallet and its addresses (gen_testnet.py)

// --- What the extracted code needs from main.c ------------------------------
#define PSBT_VIEW_LINE_CHARS 26
#define ST7735_LIGHTGREY 0
#define ST7735_CYAN 0
#define ST7735_GREEN 0
#define ST7735_BLACK 0
#define WHITE 0
#define BLACK 0
static void black_screen(void) {}
static void draw_title(char *t, int c) { (void)t; (void)c; }
static void rectan(int a, int b, int c, int d, int e) { (void)a; (void)b; (void)c; (void)d; (void)e; }
static void drawtext(int x, int y, const char *t, int c, int b, int s) { (void)x; (void)y; (void)t; (void)c; (void)b; (void)s; }
static void draw_bip84_wrapped_text(char *t, int x, int y, int w, int l) { (void)t; (void)x; (void)y; (void)w; (void)l; }
static void led_busy(void) {}
static void led_done(void) {}
static void fast_itoa(uint32_t v, char *b) { sprintf(b, "%u", (unsigned)v); }
static void strcat_num(char *s, uint32_t v) { fast_itoa(v, s + strlen(s)); }
static void text_at(int x, int y, const char *t, int c) { (void)x; (void)y; (void)t; (void)c; }

// Base58Check for the 3... addresses, written here from the spec (the
// firmware's own lives in a part of main.c that is not extracted)
static size_t base58_encode_check(const uint8_t *data, size_t len, char *out, size_t cap) {
    static const char alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    uint8_t buf[64], h1[32], h2[32], digits[96];
    SHA256_CTX c;
    size_t n = len + 4, nd = 0, zeros = 0, k = 0;
    if (n > sizeof(buf)) return 0;
    memcpy(buf, data, len);
    sha256_init(&c); sha256_update(&c, data, len); sha256_final(&c, h1);
    sha256_init(&c); sha256_update(&c, h1, 32); sha256_final(&c, h2);
    memcpy(buf + len, h2, 4);
    while (zeros < n && buf[zeros] == 0) zeros++;
    for (size_t i = zeros; i < n; i++) {        // Big number base 256 -> base 58
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

static bool bip84_account_cached = true;
static uint32_t bip84_master_fingerprint;
static uint32_t bip84_account_index = 0;
static bool bip84_multisig_mode = false;
#define SCRIPT_LEGACY 0
#define SCRIPT_NESTED 1
#define SCRIPT_NATIVE 2
#define SCRIPT_TAPROOT 3
static uint8_t bip84_script = SCRIPT_NATIVE;    // m/84' keys below (setup_wallet)
static HDNode bip84_receive_node_cache, bip84_change_node_cache;
static HDNode native_receive, native_change, nested_receive, nested_change;    // m/84' and m/49'
static HDNode taproot_receive, taproot_change;                                  // m/86'
static HDNode legacy_receive, legacy_change;                                    // m/44'
static HDNode testnet_receive, testnet_change;                                  // m/84'/1'/0'
static HDNode ms_receive_node_cache, ms_change_node_cache;
static HDNode ms2_receive, ms2_change, ms1_receive, ms1_change;     // m/48'/0'/0'/2' and /1'
static bool ms_account_cached = true;
static bool ms_wallet_loaded = false;
static desc_wallet_t ms_wallet;
static uint32_t ms_wallet_account = 0;
static uint8_t ms_wallet_seed_tag[8], bip84_seed_tag[8];
#include "plan_extract.inc"

// --- The test wallet ----------------------------------------------------------
// BIP39 seed of "abandon x11 about", no passphrase
static const char SEED_HEX[] =
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

// The corpus' 2-of-3 wallet (MULTISIG_DESCRIPTOR of its psbt_suite_util.py)
static const char MS_DESCRIPTOR[] =
    "wsh(sortedmulti(2,"
    "[73c5da0a/48h/0h/0h/2h]xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1VhR28mCyxUFL4r6KFrf/<0;1>/*,"
    "[28645006/48h/0h/0h/2h]xpub6DnEBNkSJKBYQmsbhS1sP9cNdtU5c9PLFGCjTJmxicxc13WB8zNNGQazabQpyFAGW5bV9tMko4uBxDxjUKL6dSAcx1tEbgEHtgSqyRsekh6/<0;1>/*,"
    "[3f635a63/48h/0h/0h/2h]xpub6FHZCoNb3tg3o1GAJQxSwgFNF8mLRtTk2GgkF7n5rwzoxBhUEdFWa8cyZRHqytAzKZWsKz8627cQEMCCfR5GDSv6yXegqirpgDUX41Pxybr/<0;1>/*"
    "))";

#define H 0x80000000u

static void setup_wallet(void) {
    uint8_t seed[64];
    HDNode root, n;
    for (int i = 0; i < 64; i++) {
        unsigned v;
        sscanf(&SEED_HEX[i * 2], "%2x", &v);
        seed[i] = (uint8_t)v;
    }
    hdnode_from_seed(seed, 64, "secp256k1", &root);
    bip84_master_fingerprint = 0x73C5DA0Au;     // Of this seed, as the corpus says

    n = root;
    hdnode_private_ckd(&n, 84 | H);
    hdnode_private_ckd(&n, 0 | H);
    hdnode_private_ckd(&n, 0 | H);
    native_receive = n;
    hdnode_private_ckd(&native_receive, 0);
    native_change = n;
    hdnode_private_ckd(&native_change, 1);

    n = root;                                   // m/84'/1'/0' for the testnet mode
    hdnode_private_ckd(&n, 84 | H);
    hdnode_private_ckd(&n, 1 | H);
    hdnode_private_ckd(&n, 0 | H);
    testnet_receive = n;
    hdnode_private_ckd(&testnet_receive, 0);
    testnet_change = n;
    hdnode_private_ckd(&testnet_change, 1);

    n = root;                                   // m/49'/0'/0' for the nested mode
    hdnode_private_ckd(&n, 49 | H);
    hdnode_private_ckd(&n, 0 | H);
    hdnode_private_ckd(&n, 0 | H);
    nested_receive = n;
    hdnode_private_ckd(&nested_receive, 0);
    nested_change = n;
    hdnode_private_ckd(&nested_change, 1);

    n = root;                                   // m/44'/0'/0' for the legacy mode
    hdnode_private_ckd(&n, 44 | H);
    hdnode_private_ckd(&n, 0 | H);
    hdnode_private_ckd(&n, 0 | H);
    legacy_receive = n;
    hdnode_private_ckd(&legacy_receive, 0);
    legacy_change = n;
    hdnode_private_ckd(&legacy_change, 1);

    n = root;                                   // m/86'/0'/0' for the taproot mode
    hdnode_private_ckd(&n, 86 | H);
    hdnode_private_ckd(&n, 0 | H);
    hdnode_private_ckd(&n, 0 | H);
    taproot_receive = n;
    hdnode_private_ckd(&taproot_receive, 0);
    taproot_change = n;
    hdnode_private_ckd(&taproot_change, 1);

    n = root;
    hdnode_private_ckd(&n, 48 | H);
    hdnode_private_ckd(&n, 0 | H);
    hdnode_private_ckd(&n, 0 | H);
    HDNode n1 = n;                              // m/48'/0'/0'/1' for nested multisig
    hdnode_private_ckd(&n, 2 | H);
    ms2_receive = n;
    hdnode_private_ckd(&ms2_receive, 0);
    ms2_change = n;
    hdnode_private_ckd(&ms2_change, 1);
    hdnode_private_ckd(&n1, 1 | H);
    ms1_receive = n1;
    hdnode_private_ckd(&ms1_receive, 0);
    ms1_change = n1;
    hdnode_private_ckd(&ms1_change, 1);

    if (desc_parse(MS_DESCRIPTOR, (uint32_t)strlen(MS_DESCRIPTOR), &ms_wallet) != DESC_OK) {
        printf("cannot parse the corpus descriptor\n");
        exit(1);
    }
}

// --- WALLET > ADDRESSES in multisig: ms_wallet_address() of the firmware ----------
// Receive and change 0..4 of the native and nested wallets against the
// independent Python generator. Returns the number of wrong addresses.
static int check_ms_addresses(void) {
    struct { const char *desc; const char *const (*addr)[MSA_N]; const char *name; } w[2] = {
        {msa_native_desc, msa_native_addr, "native"},
        {msn_desc_text, msa_nested_addr, "nested"},
    };
    int bad = 0;
    for (int k = 0; k < 2; k++) {
        desc_wallet_t wallet;
        if (desc_parse(w[k].desc, (uint32_t)strlen(w[k].desc), &wallet) != DESC_OK) {
            printf("ms addresses: cannot parse the %s descriptor\n", w[k].name);
            return 1;
        }
        for (uint32_t ch = 0; ch < 2; ch++) {
            for (uint32_t i = 0; i < MSA_N; i++) {
                char addr[76];
                if (!ms_wallet_address(&wallet, ch, i, addr, sizeof(addr)) || strcmp(addr, w[k].addr[ch][i]) != 0) {
                    printf("ms addresses: %s %s %u gives %s\n", w[k].name, ch ? "change" : "receive", (unsigned)i, addr);
                    bad++;
                }
            }
        }
        char small[40];         // A P2WSH address needs 63 bytes: refused, never cut
        if (!wallet.nested && ms_wallet_address(&wallet, 0, 0, small, sizeof(small))) {
            printf("ms addresses: a short buffer was accepted\n");
            bad++;
        }
    }
    // Testnet wallet (tpub keys): tb1q addresses
    desc_wallet_t tw;
    if (desc_parse(mst_desc, (uint32_t)strlen(mst_desc), &tw) != DESC_OK || !tw.testnet) {
        printf("ms addresses: the testnet descriptor is not a testnet wallet\n");
        return bad + 1;
    }
    for (uint32_t ch = 0; ch < 2; ch++) {
        for (uint32_t i = 0; i < 2; i++) {
            char addr[76];
            if (!ms_wallet_address(&tw, ch, i, addr, sizeof(addr)) || strcmp(addr, mst_addr[ch][i]) != 0) {
                printf("ms addresses: testnet %s %u gives %s\n", ch ? "change" : "receive", (unsigned)i, addr);
                bad++;
            }
        }
    }
    if (bad == 0) printf("Multisig addresses: receive and change 0..%d of the native and nested wallets, "
                         "and 0..1 of the testnet one, match\n", MSA_N - 1);
    return bad;
}

// --- One run ---------------------------------------------------------------------
enum { MODE_SINGLE, MODE_MULTI, MODE_MULTI_DESC, MODE_NESTED, MODE_NMULTI, MODE_NMULTI_DESC, MODE_TAPROOT, MODE_LEGACY,
       MODE_TESTNET, MODE_SINGLE_DESC, MODE_COUNT };
static const char *mode_name[MODE_COUNT] = {"single", "multi", "multi+desc", "nested", "nmulti", "nmulti+desc", "taproot", "legacy",
                                            "testnet", "single+desc"};

static bool mode_desc(int mode) { return mode == MODE_MULTI_DESC || mode == MODE_NMULTI_DESC || mode == MODE_SINGLE_DESC; }

typedef struct {
    char text[200];     // The outcome, as compared with malicious_expected.txt
    bool refused;       // Parse error or refusal: nothing can be signed
    int ours;           // Outputs verified as ours
} outcome_t;

static uint8_t buf[32768];

static void run(const uint8_t *data, uint32_t len, int mode, outcome_t *r) {
    psbt_t psbt;
    psbt_sign_plan_t plan;

    memcpy(buf, data, len);
    bool nested = mode == MODE_NESTED || mode == MODE_NMULTI || mode == MODE_NMULTI_DESC;
    bip84_multisig_mode = mode == MODE_MULTI || mode == MODE_MULTI_DESC || mode == MODE_NMULTI || mode == MODE_NMULTI_DESC;
    bool taproot = mode == MODE_TAPROOT, legacy = mode == MODE_LEGACY;
    bip84_script = nested ? SCRIPT_NESTED : taproot ? SCRIPT_TAPROOT : legacy ? SCRIPT_LEGACY : SCRIPT_NATIVE;
    bip84_receive_node_cache = nested ? nested_receive : taproot ? taproot_receive : legacy ? legacy_receive : native_receive;
    bip84_change_node_cache = nested ? nested_change : taproot ? taproot_change : legacy ? legacy_change : native_change;
    bip84_testnet = mode == MODE_TESTNET;       // Native single sig at m/84'/1'/0'
    if (bip84_testnet) {
        bip84_receive_node_cache = testnet_receive;
        bip84_change_node_cache = testnet_change;
    }
    ms_receive_node_cache = nested ? ms1_receive : ms2_receive;
    ms_change_node_cache = nested ? ms1_change : ms2_change;
    ms_wallet_loaded = mode_desc(mode);

    r->ours = 0;
    r->refused = true;
    psbt_status_t st = psbt_parse(buf, len, &psbt);
    if (st != PSBT_OK) {
        snprintf(r->text, sizeof(r->text), "PARSE %s", psbt_status_name(st));
        return;
    }
    psbt_plan_signing(&psbt, &plan);
    if (plan.refuse != NULL) {
        snprintf(r->text, sizeof(r->text), "REFUSE %s", plan.refuse);
        return;
    }
    r->refused = false;
    for (uint32_t o = 0; o < psbt.output_count && o < PSBT_OWNER_CACHE; o++) {
        if (psbt_owner_verified((psbt_owner_t)psbt_checked.out[o])) r->ours++;
    }
    snprintf(r->text, sizeof(r->text), "SIGN %u/%u ours=%d send=%llu change=%llu fee=%llu%s%s%s%s%s%s",
             (unsigned)plan.signable, (unsigned)psbt.input_count, r->ours,
             (unsigned long long)plan.send, (unsigned long long)plan.change, (unsigned long long)plan.fee,
             plan.high_fee ? " HIGH_FEE" : "", plan.burns ? " BURNS" : "",
             plan.amounts_unverified ? " AMOUNTS_UNVERIFIED" : "",
             plan.change_unverified ? " CHANGE_UNVERIFIED" : "",
             plan.high_change_index ? " HIGH_CHANGE_INDEX" : "",
             plan.other_mode_out ? " OTHER_MODE_OUT" : "");
}

// --- Files ------------------------------------------------------------------------
static uint8_t file_buf[32768];

static uint32_t read_file(const char *name) {
    FILE *f = fopen(name, "rb");
    if (!f) {
        printf("cannot open %s\n", name);
        exit(1);
    }
    uint32_t n = (uint32_t)fread(file_buf, 1, sizeof(file_buf), f);
    fclose(f);
    return n;
}

static char *expected_text;

static char *slurp(const char *name) {
    FILE *f = fopen(name, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *p = malloc((size_t)n + 1);
    n = (long)fread(p, 1, (size_t)n, f);
    p[n] = 0;
    fclose(f);
    return p;
}

static bool line_in(const char *haystack, const char *line) {
    size_t n = strlen(line);
    for (const char *p = haystack; p && (p = strstr(p, line)) != NULL; p += n) {
        if ((p == haystack || p[-1] == '\n') && (p[n] == '\n' || p[n] == '\r' || p[n] == 0)) return true;
    }
    return false;
}

// Is 'name' listed in the gaps file? The line starts with the name and a tab.
static bool in_gaps(const char *gaps, const char *name) {
    size_t n = strlen(name);
    for (const char *p = gaps; p && (p = strstr(p, name)) != NULL; p += n) {
        if ((p == gaps || p[-1] == '\n') && p[n] == '\t') return true;
    }
    return false;
}

static int failures = 0;
static FILE *update;

static void check_line(const char *line) {
    if (update) {
        fprintf(update, "%s\n", line);
    } else if (expected_text == NULL || !line_in(expected_text, line)) {
        printf("CHANGED  %s\n", line);
        failures++;
    }
}

// --- The two sets -------------------------------------------------------------------
static int run_corpus(const char *gaps) {
    char *truth = slurp("malicious_truth.txt");
    if (!truth) {
        printf("cannot open malicious_truth.txt\n");
        exit(1);
    }
    int vectors = 0, unsafe = 0, gaps_used = 0;
    char *save = NULL;
    for (char *l = strtok_r(truth, "\r\n", &save); l; l = strtok_r(NULL, "\r\n", &save)) {
        char name[64], expect[24];
        int owned;
        if (sscanf(l, "%63[^\t]\t%23[^\t]\t%d", name, expect, &owned) != 3) continue;
        char path[128];
        snprintf(path, sizeof(path), "malicious/%s.psbt", name);
        uint32_t len = read_file(path);
        vectors++;

        bool any_signs = false;
        int max_ours = 0;
        for (int mode = 0; mode < MODE_COUNT; mode++) {
            outcome_t r;
            char line[320];
            run(file_buf, len, mode, &r);
            snprintf(line, sizeof(line), "%s\t%s\t%s", name, mode_name[mode], r.text);
            check_line(line);
            if (!r.refused) any_signs = true;
            // A loaded descriptor can prove change the PSBT alone cannot
            if (!mode_desc(mode) && r.ours > max_ours) max_ours = r.ours;
        }

        // The corpus' truth. "ours" must never exceed what is really ours.
        if (owned >= 0 && max_ours > owned) {
            printf("UNSAFE   %s: %d outputs called ours, only %d are\n", name, max_ours, owned);
            unsafe++;
        }
        // Meant to be refused, and some mode would sign it: only as a reviewed gap
        if (strcmp(expect, "parses") != 0 && any_signs) {
            if (in_gaps(gaps, name)) {
                gaps_used++;
            } else {
                printf("NOT REFUSED %s (%s)\n", name, expect);
                unsafe++;
            }
        }
    }
    printf("corpus: %d vectors, %d reviewed gaps, %d problems\n", vectors, gaps_used, unsafe);
    free(truth);
    return unsafe;
}

static int hexval(char c) {
    return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
}

static int run_bip174(const char *gaps) {
    char *text = slurp("bip174_invalid.txt");
    if (!text) {
        printf("cannot open bip174_invalid.txt\n");
        exit(1);
    }
    int cases = 0, accepted = 0, unreviewed = 0;
    char *save = NULL;
    for (char *l = strtok_r(text, "\r\n", &save); l; l = strtok_r(NULL, "\r\n", &save)) {
        char *tab = strchr(l, '\t');
        if (!tab) continue;
        *tab = 0;
        const char *hex = tab + 1;
        uint32_t n = 0;
        for (; hex[0] && hex[1] && n < sizeof(file_buf); hex += 2) {
            file_buf[n++] = (uint8_t)(hexval(hex[0]) << 4 | hexval(hex[1]));
        }
        psbt_t psbt;
        memcpy(buf, file_buf, n);
        psbt_status_t st = psbt_parse(buf, n, &psbt);
        char line[256];
        snprintf(line, sizeof(line), "BIP174 %s\tparser\t%s", l, psbt_status_name(st));
        check_line(line);
        cases++;
        if (st == PSBT_OK) {
            char id[128];
            snprintf(id, sizeof(id), "BIP174 %s", l);
            accepted++;
            if (!in_gaps(gaps, id)) {
                printf("NOT REFUSED %s\n", id);
                unreviewed++;
            }
        }
    }
    printf("bip174: %d invalid vectors, %d accepted by the parser\n", cases, accepted);
    free(text);
    return unreviewed;
}

int main(int argc, char **argv) {
    bool do_update = argc > 1 && strcmp(argv[1], "--update") == 0;
    bool report = argc > 1 && strcmp(argv[1], "--report") == 0;

    setup_wallet();
    // test_malicious --file x.psbt [descriptor.txt]: the outcome of one file in
    // every mode, the "+desc" modes with that descriptor instead of the corpus one
    if (argc > 2 && strcmp(argv[1], "--file") == 0) {
        static uint8_t data[32768];
        if (argc > 3) {
            uint32_t n = read_file(argv[3]);
            memcpy(data, file_buf, n);
            if (desc_parse((const char *)data, n, &ms_wallet) != DESC_OK) { printf("bad descriptor %s\n", argv[3]); return 1; }
        }
        FILE *f = fopen(argv[2], "rb");
        if (!f) { printf("cannot open %s\n", argv[2]); return 1; }
        uint32_t len = (uint32_t)fread(data, 1, sizeof(data), f);
        fclose(f);
        for (int m = 0; m < MODE_COUNT; m++) {
            outcome_t r;
            run(data, len, m, &r);
            printf("%-12s %s\n", mode_name[m], r.text);
        }
        return 0;
    }
    if (do_update || report) {
        update = fopen(do_update ? "malicious_expected.txt" : "malicious_report.txt", "w");
    } else {
        expected_text = slurp("malicious_expected.txt");
    }
    char *gaps = slurp("malicious_gaps.txt");
    if (!gaps) gaps = (char *)"";

    int problems = check_ms_addresses();
    problems += run_corpus(gaps);
    problems += run_bip174(gaps);
    if (update) {
        fclose(update);
        return 0;
    }
    if (failures == 0 && problems == 0) {
        printf("ALL TESTS PASSED\n");
        return 0;
    }
    printf("FAILED: %d outcomes changed, %d safety problems\n", failures, problems);
    return 1;
}
