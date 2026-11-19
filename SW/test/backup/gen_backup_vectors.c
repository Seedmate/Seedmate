// Writes backup_vectors.json: what the firmware computes for the functions the
// backup HTML page (Seedmate_HTML_backup) also offers, with the firmware's own
// code (backup_extract.inc, copied from src/main.c by extract_backup.py, plus
// SSS/shamir.c and sha256.c). check_page.js runs the page's core script on the
// same inputs and compares.
//
//   python extract_backup.py
//   gcc ... gen_backup_vectors.c -o gen_backup_vectors.exe   (build_test.bat)
//   gen_backup_vectors.exe backup_vectors.json
//   node check_page.js <path of the page's index.html>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"
#include "SSS/shamir.h"
#include "SSS/memzero.h"
#include "app_defs.h"

// State of main.c that the extracted functions use
BYTE data_array_256b[36];
int size_pointer = cSIZE_12;
int bit_count_dice = 0;
size_t last_input_len = 0;
uint8_t card_sequence[132];
int card_sequence_len = 0;
int card_decks_needed = 0;
int card_view_page = 0;

#include "backup_extract.inc"

// Deterministic test data (not entropy)
static uint32_t lcg_state = 0x5EED0001u;
static uint32_t lcg(void) {
    lcg_state = lcg_state * 1664525u + 1013904223u;
    return lcg_state >> 8;
}

static FILE *out;
static bool first_item;

static void hex(const uint8_t *b, int n) {
    fputc('"', out);
    for (int i = 0; i < n; i++) fprintf(out, "%02x", b[i]);
    fputc('"', out);
}

static void item_start(void) {
    fputs(first_item ? "\n    " : ",\n    ", out);
    first_item = false;
}

static void section(const char *name, bool first) {
    fprintf(out, "%s\n  \"%s\": [", first ? "" : "\n  ],", name);
    first_item = true;
}

#define N_SEEDS 28
static uint8_t seeds[N_SEEDS][32];
static int seed_len[N_SEEDS];

static void make_seeds(void) {
    int s = 0;
    // abandon x11 about, legal winner, letter advice, zoo x11 wrong, and their 24 word forms
    const uint8_t fill[4] = {0x00, 0x7f, 0x80, 0xff};
    for (int f = 0; f < 4; f++) {
        for (int size = 16; size <= 32; size += 16) {
            memset(seeds[s], fill[f], 32);
            seed_len[s++] = size;
        }
    }
    while (s < N_SEEDS) {
        seed_len[s] = (s & 1) ? 32 : 16;
        for (int i = 0; i < 32; i++) seeds[s][i] = (uint8_t)lcg();
        s++;
    }
}

static void load(int s) {
    memset(data_array_256b, 0, sizeof(data_array_256b));
    memcpy(data_array_256b, seeds[s], seed_len[s]);
    size_pointer = (seed_len[s] == 16) ? cSIZE_12 : cSIZE_24;
}

static void obf_item(int s, const char *op, const char *param) {
    item_start();
    fputs("{\"in\": ", out);
    hex(seeds[s], seed_len[s]);
    fprintf(out, ", \"op\": \"%s\"%s, \"out\": ", op, param);
    hex(data_array_256b, seed_len[s]);
    fputc('}', out);
}

static void gen_obfuscation(void) {
    static const int shifts[] = {1, 5, 11, 64, 127, 128, 200, 256, 300};
    static const int amounts[] = {1, 7, 1024, 2047, 2048, 3000};
    static const int words[] = {0, 1, 3, 1234, 2047};
    char param[48];

    for (int s = 0; s < N_SEEDS; s++) {
        int n = seed_len[s];
        load(s); not_operator(data_array_256b, n); obf_item(s, "not", "");
        load(s); byte_swap_pairs(data_array_256b, n); obf_item(s, "swap", "");
        for (unsigned i = 0; i < sizeof(shifts) / sizeof(shifts[0]); i++) {
            for (int dir = 0; dir < 2; dir++) {
                load(s);
                for (int k = 0; k < shifts[i]; k++) {
                    if (dir == 0) shift_left(data_array_256b, n);
                    else shift_right(data_array_256b, n);
                }
                sprintf(param, ", \"dir\": \"%s\", \"n\": %d", dir ? "right" : "left", shifts[i]);
                obf_item(s, "shift", param);
            }
        }
        for (unsigned i = 0; i < sizeof(amounts) / sizeof(amounts[0]); i++) {
            for (int dir = 0; dir < 2; dir++) {
                load(s);
                addsub_11bit_groups((size_t)n, amounts[i], dir);
                sprintf(param, ", \"dir\": \"%s\", \"n\": %d", dir ? "sub" : "add", amounts[i]);
                obf_item(s, "addsub", param);
            }
        }
        for (unsigned i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
            load(s);
            apply_1word_xor(words[i], size_pointer);
            sprintf(param, ", \"word\": %d", words[i]);
            obf_item(s, "wordxor", param);
        }
    }
}

static void gen_cards(void) {
    for (int s = 0; s < N_SEEDS; s++) {
        load(s);
        calculate_card_encoding();
        item_start();
        fputs("{\"in\": ", out);
        hex(seeds[s], seed_len[s]);
        fputs(", \"seq\": [", out);
        for (int i = 0; i < card_sequence_len; i++) fprintf(out, "%s%d", i ? "," : "", card_sequence[i]);
        fprintf(out, "], \"decks\": %d}", card_decks_needed);
    }
}

// POKER CARDS: card_entropy_map bits appended as append_selected_card_entropy()
// does, until the size is reached; the entropy is the first 16 or 32 bytes
static void gen_poker(void) {
    for (int t = 0; t < 20; t++) {
        int target = (t & 1) ? 256 : 128;
        int cards[140], count = 0;
        memset(data_array_256b, 0, sizeof(data_array_256b));
        bit_count_dice = 0;
        while (bit_count_dice < target) {
            int c = (int)(lcg() % 52);
            cards[count++] = c;
            append_entropy_bits(card_entropy_map[c], strlen(card_entropy_map[c]));
        }
        item_start();
        fputs("{\"cards\": [", out);
        for (int i = 0; i < count; i++) fprintf(out, "%s%d", i ? "," : "", cards[i]);
        fprintf(out, "], \"bytes\": %d, \"out\": ", target / 8);
        hex(data_array_256b, target / 8);
        fputc('}', out);
    }
}

// Raw dice of CREATE: the bits each face enters (ROLL_DICE1 in main.c: BACK
// "01", UP "10", OK "11", LEFT "0", DOWN "1", RIGHT "00"), until the size is
// reached; a last roll of 2 bits may give one bit more, which is not used
static const char *const dice_bits[6] = {"01", "10", "11", "0", "1", "00"};

static void gen_dice(void) {
    for (int t = 0; t < 20; t++) {
        int target = (t & 1) ? 256 : 128;
        char rolls[300];
        int count = 0;
        memset(data_array_256b, 0, sizeof(data_array_256b));
        bit_count_dice = 0;
        while (bit_count_dice < target) {
            int f = (int)(lcg() % 6);
            rolls[count++] = (char)('1' + f);
            append_entropy_bits(dice_bits[f], strlen(dice_bits[f]));
        }
        rolls[count] = '\0';
        item_start();
        fprintf(out, "{\"rolls\": \"%s\", \"bytes\": %d, \"out\": ", rolls, target / 8);
        hex(data_array_256b, target / 8);
        fputc('}', out);
    }
}

// STRING HASH (DICE_STRING_INPUT in main.c): SHA-256 of the faces as typed,
// '6' written as '0' in the 0-5 (Keystone) mode; the first 16 or 32 bytes
static void gen_dice_hash(void) {
    static const int lengths[] = {50, 51, 99, 100, 150, 500};
    for (unsigned l = 0; l < sizeof(lengths) / sizeof(lengths[0]); l++) {
        for (int keystone = 0; keystone < 2; keystone++) {
            for (int bytes = 16; bytes <= 32; bytes += 16) {
                char rolls[char_hash_limit];
                int len = lengths[l];
                if (bytes == 32 && len < c24_rolls) continue;
                for (int i = 0; i < len; i++) rolls[i] = (char)('1' + lcg() % 6);
                rolls[len] = '\0';
                item_start();
                fprintf(out, "{\"rolls\": \"%s\", \"keystone\": %s, \"bytes\": %d, \"out\": ",
                        rolls, keystone ? "true" : "false", bytes);
                if (keystone) for (int i = 0; i < len; i++) if (rolls[i] == '6') rolls[i] = '0';
                BYTE hash[SHA256_BLOCK_SIZE];
                SHA256_CTX ctx;
                sha256_init(&ctx);
                sha256_update(&ctx, (BYTE *)rolls, (size_t)len);
                sha256_final(&ctx, hash);
                hex(hash, bytes);
                fputc('}', out);
            }
        }
    }
}

static void gen_shamir(void) {
    static const int kn[][2] = {{2, 2}, {2, 3}, {3, 5}, {4, 6}, {5, 9}, {6, 9}, {2, 9}};
    for (int s = 0; s < N_SEEDS; s += 3) {
        for (unsigned c = 0; c < sizeof(kn) / sizeof(kn[0]); c++) {
            int k = kn[c][0], n = kn[c][1], len = seed_len[s];
            uint8_t coeff[cK_MAX - 1][32];
            const uint8_t *coeffs[cK_MAX - 1];
            uint8_t share_buf[cN_MAX][32];
            uint8_t *shares[cN_MAX];
            for (int i = 0; i < k - 1; i++) {
                for (int j = 0; j < 32; j++) coeff[i][j] = (uint8_t)lcg();
                coeffs[i] = coeff[i];
            }
            for (int i = 0; i < n; i++) shares[i] = share_buf[i];
            if (!sss_split_kofm(seeds[s], coeffs, (size_t)k, (size_t)len, (size_t)n, shares)) {
                fprintf(stderr, "split failed\n");
                exit(1);
            }
            // The firmware's merge (shamir_interpolate) gives the secret back
            // from a subset of k shares taken from the end
            uint8_t idx[cN_MAX], *values[cN_MAX], result[32];
            for (int i = 0; i < k; i++) {
                idx[i] = (uint8_t)(n - i);
                values[i] = shares[n - 1 - i];
            }
            if (!shamir_interpolate(result, 0, idx, values, (uint8_t)k, (size_t)len) ||
                memcmp(result, seeds[s], (size_t)len) != 0) {
                fprintf(stderr, "merge does not give the secret back\n");
                exit(1);
            }
            item_start();
            fputs("{\"secret\": ", out);
            hex(seeds[s], len);
            fprintf(out, ", \"k\": %d, \"n\": %d, \"coeffs\": [", k, n);
            for (int i = 0; i < k - 1; i++) { if (i) fputc(',', out); hex(coeff[i], len); }
            fputs("], \"shares\": [", out);
            for (int i = 0; i < n; i++) { if (i) fputc(',', out); hex(shares[i], len); }
            fputs("]}", out);
        }
    }
}

int main(int argc, char **argv) {
    out = fopen(argc > 1 ? argv[1] : "backup_vectors.json", "w");
    if (!out) return 1;
    make_seeds();
    fputs("{", out);
    section("obfuscation", true); gen_obfuscation();
    section("cards", false); gen_cards();
    section("poker", false); gen_poker();
    section("dice", false); gen_dice();
    section("dicehash", false); gen_dice_hash();
    section("shamir", false); gen_shamir();
    fputs("\n  ]\n}\n", out);
    fclose(out);
    printf("wrote backup vectors\n");
    return 0;
}
