// Host-side tests for psbt.c and fountain_assemble_message(). Not part of the firmware.
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "psbt.h"
#include "fountain.h"
#include "test_vectors.h"

static int failures = 0;
static const uint8_t P2WPKH_SCRIPT[22] = {0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
                                         0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6};
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static void check_address(const uint8_t *script, uint32_t len, const char *expected) {
    char addr[PSBT_ADDRESS_MAX_LEN];
    CHECK(psbt_segwit_address(script, len, "bc", addr, sizeof(addr)));
    if (strcmp(addr, expected) != 0) {
        printf("FAIL address: got %s expected %s\n", addr, expected);
        failures++;
    }
}

static void check_btc(uint64_t sats, const char *expected) {
    char s[PSBT_BTC_STR_LEN];
    psbt_format_btc(sats, s);
    if (strcmp(s, expected) != 0) {
        printf("FAIL btc(%llu): got %s expected %s\n", (unsigned long long)sats, s, expected);
        failures++;
    }
}

static void test_v1(const uint8_t *data, uint32_t len) {
    psbt_t p;
    psbt_input_t in;
    psbt_output_t out;
    uint64_t sum_in, sum_out, fee;
    char txid[65];

    CHECK(psbt_parse(data, len, &p) == PSBT_OK);
    CHECK(p.tx_version == 2 && p.locktime == 850000);
    CHECK(p.input_count == 2 && p.output_count == 2);

    CHECK(psbt_get_input(&p, 0, &in));
    CHECK(in.prev_vout == 1 && in.sequence == 0xfffffffd);
    CHECK(in.has_amount && in.amount_from_witness && in.amount == 100000);
    CHECK(psbt_script_type(in.script, in.script_len) == PSBT_SCRIPT_P2WPKH);
    psbt_format_txid(in.prev_txid, txid);
    CHECK(strcmp(txid, expected_txid_v1_in0) == 0);

    CHECK(psbt_get_input(&p, 1, &in));
    CHECK(in.has_amount && in.amount == 50000);
    CHECK(psbt_script_type(in.script, in.script_len) == PSBT_SCRIPT_P2WSH);
    check_address(in.script, in.script_len, "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3");
    CHECK(!psbt_get_input(&p, 2, &in));

    CHECK(psbt_get_output(&p, 0, &out));
    CHECK(out.amount == 120000);
    check_address(out.script, out.script_len, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    CHECK(psbt_get_output(&p, 1, &out));
    CHECK(out.amount == 29000 && psbt_script_type(out.script, out.script_len) == PSBT_SCRIPT_P2TR);
    check_address(out.script, out.script_len, "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0");
    CHECK(!psbt_get_output(&p, 2, &out));

    CHECK(psbt_get_totals(&p, &sum_in, &sum_out));
    CHECK(sum_in == 150000 && sum_out == 149000);
    CHECK(psbt_get_fee(&p, &fee) && fee == 1000);
}

static void test_fountain_assemble(void) {
    // Pure frames (seq 1..total) carry fragment seq-1 directly
    uint8_t msg[700];
    const uint32_t frag = 250, total = 3;
    for (uint32_t i = 0; i < sizeof(msg); i++) msg[i] = (uint8_t)(i * 7 + 3);

    fountain_init();
    bool done = false;
    for (uint32_t seq = 1; seq <= total; seq++) {
        uint8_t part[250] = {0};
        uint32_t ofs = (seq - 1) * frag;
        uint32_t n = (sizeof(msg) - ofs < frag) ? sizeof(msg) - ofs : frag;
        memcpy(part, &msg[ofs], n);      // Last fragment is zero padded
        done = fountain_process_frame(seq, total, sizeof(msg), 0x12345678, part, frag);
    }
    CHECK(done);
    uint8_t *joined = fountain_assemble_message(sizeof(msg));
    CHECK(joined != NULL && memcmp(joined, msg, sizeof(msg)) == 0);
    CHECK(fountain_get_part(0) == NULL);                       // Parts invalidated
    CHECK(fountain_assemble_message(total * frag + 1) == NULL); // Longer than the parts
}

static void check_path(const psbt_keypath_t *kp, const char *expected) {
    char s[PSBT_PATH_STR_LEN];
    psbt_format_path(kp, s);
    if (strcmp(s, expected) != 0) {
        printf("FAIL path: got %s expected %s\n", s, expected);
        failures++;
    }
}

// Derivations, sighash, partial sigs, finalized inputs, multisig, RBF
static void test_metadata(void) {
    psbt_t p;
    psbt_input_t in;
    psbt_output_t out;
    psbt_keypath_t kp;
    uint8_t m = 0, n = 0;
    char fp[9];

    CHECK(psbt_parse(v4, sizeof(v4), &p) == PSBT_OK);
    CHECK(psbt_signals_rbf(&p));
    CHECK(p.locktime == 850000);

    // Global xpub
    CHECK(psbt_global_xpub(&p, 0, &kp) && kp.key_len == 78 && kp.fingerprint == 0x73C5DA0A);
    check_path(&kp, "m/84'/0'/0'");
    CHECK(!psbt_global_xpub(&p, 1, &kp));

    // Input 0: own single-sig key, explicit SIGHASH_ALL
    CHECK(psbt_get_input(&p, 0, &in));
    CHECK(in.keypath_count == 1 && in.has_sighash && in.sighash == PSBT_SIGHASH_ALL);
    CHECK(!in.finalized && in.partial_sig_count == 0 && in.witness_script == NULL);
    CHECK(psbt_input_keypath(&p, 0, 0, &kp) && kp.key_len == 33 && kp.key[0] == 0x03 && kp.key[1] == 0x30);
    CHECK(kp.fingerprint == 0x73C5DA0A && kp.path_len == 5);
    CHECK(psbt_path_element(&kp, 0) == (84 | PSBT_HARDENED) && psbt_path_element(&kp, 3) == 0);
    check_path(&kp, "m/84'/0'/0'/0/0");
    CHECK(!psbt_input_keypath(&p, 0, 1, &kp));

    // Input 1: 2-of-3 multisig, one signature, non-default sighash
    CHECK(psbt_get_input(&p, 1, &in));
    CHECK(in.keypath_count == 3 && in.partial_sig_count == 1);
    CHECK(in.has_sighash && strcmp(psbt_sighash_name(in.sighash), "NONE|ACP") == 0);
    CHECK(psbt_multisig_info(in.witness_script, in.witness_script_len, &m, &n) && m == 2 && n == 3);
    CHECK(psbt_input_keypath(&p, 1, 2, &kp) && kp.fingerprint == 0x22222222);
    check_path(&kp, "m/48'/0'/0'/2'/0/0");
    CHECK(!psbt_input_keypath(&p, 1, 3, &kp));

    // Input 2: already finalized, no derivations
    CHECK(psbt_get_input(&p, 2, &in));
    CHECK(in.finalized && in.keypath_count == 0 && !in.has_sighash);
    CHECK(!psbt_input_keypath(&p, 2, 0, &kp));

    // Outputs: external, own change, multisig change
    CHECK(psbt_get_output(&p, 0, &out) && out.keypath_count == 0 && out.witness_script == NULL);
    CHECK(psbt_get_output(&p, 1, &out) && out.keypath_count == 1);
    CHECK(psbt_output_keypath(&p, 1, 0, &kp) && kp.fingerprint == 0x73C5DA0A && kp.key[1] == 0x02);
    check_path(&kp, "m/84'/0'/0'/1/0");
    CHECK(psbt_get_output(&p, 2, &out) && out.keypath_count == 3);
    CHECK(psbt_multisig_info(out.witness_script, out.witness_script_len, &m, &n) && m == 2 && n == 3);
    CHECK(psbt_output_keypath(&p, 2, 1, &kp) && kp.fingerprint == 0x11111111);
    check_path(&kp, "m/48'/0'/0'/2'/1/0");

    // Amounts still add up with all the extra fields: 130000 in, 120000 out
    uint64_t fee;
    CHECK(psbt_get_fee(&p, &fee) && fee == 10000);

    // The device test PSBT parses and carries the expected derivations
    CHECK(psbt_parse(abandon, sizeof(abandon), &p) == PSBT_OK);
    CHECK(psbt_input_keypath(&p, 0, 0, &kp) && kp.fingerprint == 0x73C5DA0A);
    CHECK(psbt_output_keypath(&p, 1, 0, &kp));
    check_path(&kp, "m/84'/0'/0'/1/0");

    // RBF: v1 uses 0xFFFFFFFD, v2 uses final sequences
    CHECK(psbt_parse(v1, sizeof(v1), &p) == PSBT_OK && psbt_signals_rbf(&p));
    CHECK(psbt_parse(v2, sizeof(v2), &p) == PSBT_OK && !psbt_signals_rbf(&p));

    // Helpers
    psbt_format_fingerprint(0x73C5DA0A, fp);
    CHECK(strcmp(fp, "73C5DA0A") == 0);
    CHECK(strcmp(psbt_sighash_name(PSBT_SIGHASH_ALL), "ALL") == 0);
    CHECK(strcmp(psbt_sighash_name(0x42), "UNKNOWN") == 0);
    CHECK(!psbt_multisig_info(P2WPKH_SCRIPT, sizeof(P2WPKH_SCRIPT), &m, &n));

    // A path too long for the buffer is cut with "..."
    uint8_t long_path[4 * 12];
    memset(long_path, 0xFF, sizeof(long_path));
    psbt_keypath_t big = { NULL, 0, 0, long_path, 12 };
    char s[PSBT_PATH_STR_LEN];
    psbt_format_path(&big, s);
    CHECK(strlen(s) < PSBT_PATH_STR_LEN && strcmp(s + strlen(s) - 3, "...") == 0);
}

int main(void) {
    psbt_t p;
    psbt_input_t in;
    psbt_output_t out;
    uint64_t fee, sum_in, sum_out;

    test_v1(v1, sizeof(v1));
    test_v1(v1_cbor, sizeof(v1_cbor));

    // NON_WITNESS_UTXO input, legacy outputs and OP_RETURN
    CHECK(psbt_parse(v2, sizeof(v2), &p) == PSBT_OK);
    CHECK(psbt_get_input(&p, 0, &in));
    CHECK(in.has_amount && !in.amount_from_witness && in.amount == 777777 && in.prev_vout == 2);
    CHECK(psbt_get_fee(&p, &fee) && fee == 7777);
    CHECK(psbt_get_output(&p, 0, &out) && psbt_script_type(out.script, out.script_len) == PSBT_SCRIPT_P2PKH);
    CHECK(psbt_get_output(&p, 1, &out) && psbt_script_type(out.script, out.script_len) == PSBT_SCRIPT_P2SH);
    CHECK(psbt_get_output(&p, 2, &out) && psbt_script_type(out.script, out.script_len) == PSBT_SCRIPT_OP_RETURN);
    {
        char addr[PSBT_ADDRESS_MAX_LEN];
        CHECK(!psbt_segwit_address(out.script, out.script_len, "bc", addr, sizeof(addr)));
    }

    // No UTXO data: fee unknown, totals reported as incomplete
    CHECK(psbt_parse(v3, sizeof(v3), &p) == PSBT_OK);
    CHECK(psbt_get_input(&p, 0, &in) && !in.has_amount);
    CHECK(!psbt_get_totals(&p, &sum_in, &sum_out) && sum_out == 770000);
    CHECK(!psbt_get_fee(&p, &fee));

    // Error cases
    CHECK(psbt_parse(bad_magic, sizeof(bad_magic), &p) == PSBT_ERR_MAGIC);
    CHECK(psbt_parse(truncated, sizeof(truncated), &p) == PSBT_ERR_TRUNCATED);
    CHECK(psbt_parse(v2_global, sizeof(v2_global), &p) == PSBT_ERR_UNSUPPORTED);
    CHECK(psbt_parse(script_sig, sizeof(script_sig), &p) == PSBT_ERR_FORMAT);
    CHECK(psbt_parse(missing_maps, sizeof(missing_maps), &p) == PSBT_ERR_TRUNCATED);
    CHECK(psbt_parse(NULL, 0, &p) == PSBT_ERR_MAGIC);
    for (uint32_t cut = 0; cut < sizeof(v1); cut++) {   // Every truncation must fail cleanly
        CHECK(psbt_parse(v1, cut, &p) != PSBT_OK);
    }

    // BTC formatting
    check_btc(0, "0.00000000");
    check_btc(1, "0.00000001");
    check_btc(123456789, "1.23456789");
    check_btc(2100000000000000ULL, "21000000.00000000");
    check_btc(UINT64_MAX, "184467440737.09551615");

    test_fountain_assemble();
    test_metadata();

    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures != 0;
}
