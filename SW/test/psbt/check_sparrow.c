// Reads the PSBTs of gen_sparrow.py with the firmware parser (psbt.c) and
// prints what the device will show: inputs and outputs with their paths, the
// fee, RBF. It fails if a file does not parse, or a previous tx is missing or
// does not match its txid.
//   gcc -std=c99 -Wall -Wextra -O1 -I../../src check_sparrow.c ../../src/psbt.c ../../src/sha256.c ../../src/crypto/segwit_addr.c -o check_sparrow
//   check_sparrow sparrow/*.psbt
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "psbt.h"
#include "sha256.h"

static uint8_t buf[16384];

int main(int argc, char **argv) {
    int failures = 0;
    for (int f = 1; f < argc; f++) {
        FILE *fp = fopen(argv[f], "rb");
        if (!fp) { printf("%s: cannot open\n", argv[f]); failures++; continue; }
        uint32_t len = (uint32_t)fread(buf, 1, sizeof(buf), fp);
        fclose(fp);

        psbt_t psbt;
        psbt_status_t st = psbt_parse(buf, len, &psbt);
        printf("%s (%u bytes): %s\n", argv[f], (unsigned)len, psbt_status_name(st));
        if (st != PSBT_OK) { failures++; continue; }

        char path[PSBT_PATH_STR_LEN], btc[32], addr[100];
        psbt_keypath_t kp;
        for (uint32_t i = 0; i < psbt.input_count; i++) {
            psbt_input_t in;
            if (!psbt_get_input(&psbt, i, &in) || !in.has_amount || in.prev_tx == NULL) {
                printf("  input %u: no UTXO data\n", (unsigned)i);
                failures++;
                continue;
            }
            // The txid check the device does before signing (legacy serialization)
            uint32_t ofs, blen;
            uint8_t txid[32];
            SHA256_CTX ctx;
            if (!psbt_tx_txid_body(in.prev_tx, in.prev_tx_len, &ofs, &blen)) { failures++; continue; }
            sha256_init(&ctx);
            sha256_update(&ctx, in.prev_tx, 4);
            sha256_update(&ctx, &in.prev_tx[ofs], blen);
            sha256_update(&ctx, &in.prev_tx[in.prev_tx_len - 4], 4);
            sha256_final(&ctx, txid);
            sha256_init(&ctx);
            sha256_update(&ctx, txid, 32);
            sha256_final(&ctx, txid);
            if (memcmp(txid, in.prev_txid, 32) != 0) {
                printf("  input %u: PREV TX MISMATCH\n", (unsigned)i);
                failures++;
            }
            psbt_format_btc(in.amount, btc);
            path[0] = '\0';
            if (psbt_input_keypath(&psbt, i, 0, &kp)) psbt_format_path(&kp, path);
            printf("  in  %u: %s BTC  %s\n", (unsigned)i, btc, path);
        }
        for (uint32_t o = 0; o < psbt.output_count; o++) {
            psbt_output_t out;
            if (!psbt_get_output(&psbt, o, &out)) { failures++; continue; }
            psbt_format_btc(out.amount, btc);
            if (!psbt_segwit_address(out.script, out.script_len, "bc", addr, sizeof(addr))) addr[0] = '\0';
            path[0] = '\0';
            if (psbt_output_keypath(&psbt, o, 0, &kp)) psbt_format_path(&kp, path);
            printf("  out %u: %s BTC  %s %s\n", (unsigned)o, btc, addr, path[0] ? path : "(not ours)");
        }
        uint64_t fee;
        if (psbt_get_fee(&psbt, &fee)) {
            psbt_format_btc(fee, btc);
            printf("  fee %s BTC, RBF %s, global xpub %s\n", btc, psbt_signals_rbf(&psbt) ? "yes" : "no",
                   psbt_global_xpub(&psbt, 0, &kp) ? "yes" : "no");
        } else {
            failures++;
        }
    }
    printf(failures ? "\n%d PROBLEM(S)\n" : "\nALL PARSED\n", failures);
    return failures != 0;
}
