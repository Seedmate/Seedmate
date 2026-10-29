// Host-side tests for psbt_sign.c and psbt_add_partial_sig(). Not part of the
// firmware. The firmware signing code must produce exactly the PSBT that the
// independent Python signer (sign_abandon.py) produced.
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "psbt.h"
#include "psbt_sign.h"
#include "test_vectors.h"
#include "ur_test_psbt.h"

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static void hex32(const char *hex, uint8_t *out) {
    for (int i = 0; i < 32; i++) {
        unsigned v;
        sscanf(&hex[2 * i], "%2x", &v);
        out[i] = (uint8_t)v;
    }
}

static void test_bip143_vector(void) {
    psbt_t p;
    uint8_t digest[32], expected[32];
    static const uint8_t pkh[20] = {0x1d, 0x0f, 0x17, 0x2a, 0x0e, 0xcb, 0x48, 0xae, 0xe1, 0xbe,
                                    0x1f, 0x26, 0x87, 0xd2, 0x96, 0x3a, 0xe3, 0x3f, 0x71, 0xa1};

    CHECK(psbt_parse(bip143_psbt, sizeof(bip143_psbt), &p) == PSBT_OK);
    CHECK(psbt_sighash_p2wpkh(&p, 1, pkh, 600000000ULL, PSBT_SIGHASH_ALL, digest));
    hex32("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670", expected);
    CHECK(memcmp(digest, expected, 32) == 0);
    CHECK(!psbt_sighash_p2wpkh(&p, 1, pkh, 600000000ULL, PSBT_SIGHASH_NONE, digest));
    CHECK(!psbt_sighash_p2wpkh(&p, 2, pkh, 600000000ULL, PSBT_SIGHASH_ALL, digest));
}

static void test_prev_tx(void) {
    psbt_t p;
    psbt_input_t in;

    CHECK(psbt_parse(prev_ok, sizeof(prev_ok), &p) == PSBT_OK && psbt_get_input(&p, 0, &in));
    CHECK(psbt_prev_tx_matches(&in));                       // SegWit serialization, real txid
    CHECK(psbt_parse(prev_ok_legacy, sizeof(prev_ok_legacy), &p) == PSBT_OK && psbt_get_input(&p, 0, &in));
    CHECK(psbt_prev_tx_matches(&in));                       // Legacy serialization
    CHECK(psbt_parse(prev_bad, sizeof(prev_bad), &p) == PSBT_OK && psbt_get_input(&p, 0, &in));
    CHECK(!psbt_prev_tx_matches(&in));                      // Amount tampered
    CHECK(psbt_parse(v2, sizeof(v2), &p) == PSBT_OK && psbt_get_input(&p, 0, &in));
    CHECK(!psbt_prev_tx_matches(&in));                      // prev_txid is not the txid
    CHECK(psbt_parse(v1, sizeof(v1), &p) == PSBT_OK && psbt_get_input(&p, 0, &in));
    CHECK(!psbt_prev_tx_matches(&in));                      // No NON_WITNESS_UTXO
}

static void test_sign_abandon(void) {
    static uint8_t buf[1024];
    psbt_t p;
    psbt_input_t in;
    psbt_keypath_t kp;
    uint8_t digest[32], sig[PSBT_SIG_MAX_LEN];
    uint32_t sig_len = 0, len;

    memcpy(buf, abandon, sizeof(abandon));
    CHECK(psbt_parse(buf, sizeof(abandon), &p) == PSBT_OK);
    CHECK(psbt_get_input(&p, 0, &in) && in.has_amount && in.script_len == 22);
    CHECK(psbt_input_keypath(&p, 0, 0, &kp) && kp.key_len == 33);

    CHECK(psbt_sighash_p2wpkh(&p, 0, &in.script[2], in.amount, PSBT_SIGHASH_ALL, digest));
    CHECK(psbt_ecdsa_sign(ur_test_priv_0_0, digest, PSBT_SIGHASH_ALL, sig, &sig_len));
    CHECK(sig_len >= 9 && sig_len <= PSBT_SIG_MAX_LEN && sig[sig_len - 1] == PSBT_SIGHASH_ALL);

    uint8_t pubkey[33];
    memcpy(pubkey, kp.key, 33);                 // kp points into buf, which is about to move
    len = psbt_add_partial_sig(buf, sizeof(buf), &p, 0, pubkey, 33, sig, sig_len);
    CHECK(len == sizeof(ur_test_signed_psbt));
    CHECK(memcmp(buf, ur_test_signed_psbt, sizeof(ur_test_signed_psbt)) == 0);

    CHECK(psbt_parse(buf, len, &p) == PSBT_OK && psbt_get_input(&p, 0, &in) && in.partial_sig_count == 1);
    CHECK(psbt_add_partial_sig(buf, len + 10, &p, 0, pubkey, 33, sig, sig_len) == 0);   // No room

    // Deterministic: signing again gives the same signature
    uint8_t sig2[PSBT_SIG_MAX_LEN];
    uint32_t sig2_len = 0;
    CHECK(psbt_ecdsa_sign(ur_test_priv_0_0, digest, PSBT_SIGHASH_ALL, sig2, &sig2_len));
    CHECK(sig2_len == sig_len && memcmp(sig, sig2, sig_len) == 0);

    // Invalid private keys are refused
    static const uint8_t zero_key[32] = {0};
    CHECK(!psbt_ecdsa_sign(zero_key, digest, PSBT_SIGHASH_ALL, sig, &sig_len));
}

// 2-of-3 P2WSH: the firmware must sign exactly like the Python signer
static void test_sign_multisig(void) {
    static uint8_t buf[2048];
    psbt_t p;
    psbt_input_t in;
    psbt_output_t out;
    psbt_keypath_t kp;
    uint8_t digest[32], sig[PSBT_SIG_MAX_LEN], pubkey[33];
    uint32_t sig_len = 0, len;

    memcpy(buf, ur_test_ms_psbt, sizeof(ur_test_ms_psbt));
    CHECK(psbt_parse(buf, sizeof(ur_test_ms_psbt), &p) == PSBT_OK);
    CHECK(psbt_get_input(&p, 0, &in) && in.has_amount && in.witness_script != NULL);
    CHECK(psbt_p2wsh_matches(in.script, in.script_len, in.witness_script, in.witness_script_len));

    // Our key: the derivation carrying the abandon fingerprint
    bool found = false;
    for (uint32_t n = 0; psbt_input_keypath(&p, 0, n, &kp); n++) {
        if (kp.fingerprint == 0x73C5DA0A) { found = true; break; }
    }
    CHECK(found && kp.key_len == 33 && kp.path_len == 6);
    memcpy(pubkey, kp.key, 33);
    CHECK(psbt_multisig_has_key(in.witness_script, in.witness_script_len, pubkey));
    CHECK(!psbt_input_has_sig_from(&p, 0, pubkey, 33));

    // The change script is not the input's witness script, and has another key of ours
    CHECK(psbt_get_output(&p, 1, &out) && out.witness_script != NULL);
    CHECK(!psbt_p2wsh_matches(in.script, in.script_len, out.witness_script, out.witness_script_len));
    CHECK(psbt_p2wsh_matches(out.script, out.script_len, out.witness_script, out.witness_script_len));
    CHECK(!psbt_multisig_has_key(out.witness_script, out.witness_script_len, pubkey));

    CHECK(psbt_sighash_segwit_v0(&p, 0, in.witness_script, in.witness_script_len, in.amount,
                                 PSBT_SIGHASH_ALL, digest));
    CHECK(psbt_ecdsa_sign(ur_test_ms_priv_0_0, digest, PSBT_SIGHASH_ALL, sig, &sig_len));
    len = psbt_add_partial_sig(buf, sizeof(buf), &p, 0, pubkey, 33, sig, sig_len);
    CHECK(len == sizeof(ur_test_ms_signed_psbt));
    CHECK(memcmp(buf, ur_test_ms_signed_psbt, sizeof(ur_test_ms_signed_psbt)) == 0);

    CHECK(psbt_parse(buf, len, &p) == PSBT_OK && psbt_input_has_sig_from(&p, 0, pubkey, 33));
    CHECK(!psbt_input_has_sig_from(&p, 0, ur_test_ms_priv_0_0, 33));   // Not a key in the map
}

// Low R grinding: same signatures as the reference, including retried ones
static void test_low_r_grinding(void) {
    uint8_t sig[PSBT_SIG_MAX_LEN];
    uint32_t sig_len = 0;
    uint32_t retried = 0;

    for (int i = 0; i < UR_TEST_GRIND_COUNT; i++) {
        CHECK(psbt_ecdsa_sign(ur_test_priv_0_0, ur_test_grind_digest[i], PSBT_SIGHASH_ALL, sig, &sig_len));
        CHECK(sig_len == ur_test_grind_sig_len[i] + 1u);
        CHECK(memcmp(sig, ur_test_grind_sig[i], ur_test_grind_sig_len[i]) == 0);
        CHECK(sig[4] < 0x80 && sig_len <= 72);          // R without the 0x00 pad
        if (ur_test_grind_retries[i] > 0) retried++;
    }
    CHECK(retried > 0);
    printf("Low R: %d signatures match, %u needed retries\n", UR_TEST_GRIND_COUNT, retried);
}

int main(void) {
    (void)expected_txid_v1_in0;     // Shared vector file; unused here
    test_bip143_vector();
    test_prev_tx();
    test_sign_abandon();
    test_sign_multisig();
    test_low_r_grinding();
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures != 0;
}
