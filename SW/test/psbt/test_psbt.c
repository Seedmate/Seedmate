// Host-side tests for psbt.c and fountain_assemble_message(). Not part of the firmware.
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "psbt.h"
#include "fountain.h"
#include "test_vectors.h"

static int failures = 0;
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

    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures != 0;
}
