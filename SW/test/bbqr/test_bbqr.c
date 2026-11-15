// Host test of the BBQr decoder (../../src/bbqr.c, with the vendored tinf).
// The frames come from gen_bbqr.py, an independent encoder written from the
// spec. Every case is read in order, in reverse (the last part first, which
// must wait for the next round of the animation) and in a random order with
// repeats; then the refusals, random deflate data, and the frames that
// tools/ur_psbt_animator.html makes (anim_frames.js).
//
// Build and run from this folder (build_test.bat; node for the page's frames):
//   python gen_bbqr.py
//   node anim_frames.js
//   gcc -std=c99 -O1 -Wall -Wextra -I../../src -o test_bbqr test_bbqr.c ../../src/bbqr.c
//   ./test_bbqr
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "bbqr.h"
#include "bbqr_vectors.h"

// As in the firmware: the fountain part buffer and mixed frames together,
// and the 8,750 bytes a PSBT may take at its start
#define LARGE_CAP 11952u
#define PSBT_CAP  8750u
#define GUARD     64u
static uint8_t ram[LARGE_CAP + GUARD];

static int failures;
#define CHECK(cond, ...) do { if (!(cond)) { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); failures++; } } while (0)

static uint32_t rng = 2463534242u;
static uint32_t rnd(uint32_t n) {
    rng ^= rng << 13;
    rng ^= rng >> 17;
    rng ^= rng << 5;
    return rng % n;
}

static void start(char type, uint32_t cap) {
    memset(ram, 0xA5, sizeof(ram));
    bbqr_init(ram, cap, type);
}

static bbqr_result_t add(const char *s) {
    return bbqr_add_part(s, (uint32_t)strlen(s));
}

static bool guard_intact(uint32_t cap) {
    for (uint32_t i = cap; i < LARGE_CAP + GUARD; i++) {
        if (ram[i] != 0xA5) return false;
    }
    return true;
}

// The file of a case, from its hex text
static uint8_t expected[16384];
static const uint8_t *case_file(int k) {
    for (unsigned i = 0; i < cases[k].file_len; i++) {
        unsigned v;
        sscanf(&cases[k].file_hex[2 * i], "%2x", &v);
        expected[i] = (uint8_t)v;
    }
    return expected;
}

// Feeds the frames in the order of 'order' (repeated, as an animation runs)
// until complete; then joins and compares
static void run_case(int k, const unsigned *order, unsigned n_order, const char *how) {
    const char *name = cases[k].name;
    start(cases[k].type, LARGE_CAP);
    bbqr_result_t r = BBQR_PART_ADDED;
    for (unsigned round = 0; round < 3 && r != BBQR_COMPLETE; round++) {
        for (unsigned i = 0; i < n_order && r != BBQR_COMPLETE; i++) {
            r = add(cases[k].frames[order[i]]);
            CHECK(r == BBQR_PART_ADDED || r == BBQR_PART_IGNORED || r == BBQR_COMPLETE,
                  "%s %c %d %s: part %u gave %d", name, cases[k].enc, cases[k].max_chars, how, order[i], r);
        }
    }
    CHECK(r == BBQR_COMPLETE, "%s %c %d %s: not complete", name, cases[k].enc, cases[k].max_chars, how);
    uint32_t len = 0;
    r = bbqr_finish(PSBT_CAP, &len);
    // Z is inflated in the same buffer: the compressed copy at its end, the
    // output before it, so both must fit together
    if (cases[k].file_len > PSBT_CAP || (cases[k].enc == 'Z' && cases[k].file_len + cases[k].sent_len > LARGE_CAP)) {
        CHECK(r == BBQR_ERR_TOO_BIG, "%s %c %s: %d, expected TOO BIG", name, cases[k].enc, how, r);
    } else {
        CHECK(r == BBQR_COMPLETE && len == cases[k].file_len && memcmp(ram, case_file(k), len) == 0
              && ram[len] == 0,
              "%s %c %d %s: wrong result (%d, %u bytes)", name, cases[k].enc, cases[k].max_chars, how, r, (unsigned)len);
    }
    CHECK(guard_intact(LARGE_CAP), "%s %s: wrote past the buffer", name, how);
}

static void all_cases(void) {
    unsigned order[256];
    int n_cases = (int)(sizeof(cases) / sizeof(cases[0]));
    for (int k = 0; k < n_cases; k++) {
        unsigned n = cases[k].count;
        for (unsigned i = 0; i < n; i++) order[i] = i;
        run_case(k, order, n, "in order");
        for (unsigned i = 0; i < n; i++) order[i] = n - 1 - i;
        run_case(k, order, n, "reversed");
        // Every part once and as many repeats, shuffled
        unsigned m = (2 * n < 256) ? 2 * n : 256;
        for (unsigned i = 0; i < m; i++) order[i] = (i < n) ? i : rnd(n);
        for (unsigned i = m - 1; i > 0; i--) {
            unsigned j = rnd(i + 1), t = order[i];
            order[i] = order[j];
            order[j] = t;
        }
        run_case(k, order, m, "random");
    }
    printf("%d cases read in three orders\n", n_cases);
}

// The case with this file, encoding and code size
static int find(const char *name, char enc, int max_chars) {
    for (int k = 0; k < (int)(sizeof(cases) / sizeof(cases[0])); k++) {
        if (strcmp(cases[k].name, name) == 0 && cases[k].enc == enc && cases[k].max_chars == max_chars) return k;
    }
    printf("no case %s %c %d\n", name, enc, max_chars);
    failures++;
    return 0;
}

static void refusals(void) {
    char s[4100];
    int h = find("abandon taproot.psbt", 'H', 200);     // Several hex parts
    int b = find("abandon taproot.psbt", '2', 200);     // Several base32 parts
    int z = find("abandon taproot.psbt", 'Z', 468);

    start('U', LARGE_CAP);                               // A PSBT where text is asked
    CHECK(add(cases[h].frames[0]) == BBQR_ERR_TYPE, "type");

    start('P', LARGE_CAP);
    CHECK(add("B$HP01") == BBQR_ERR_HEADER, "short header");
    CHECK(add("B$HP0!00AB") == BBQR_ERR_HEADER, "bad base 36");
    CHECK(add("B$HP0202AB") == BBQR_ERR_HEADER, "index past the total");
    CHECK(add("B$HP0000AB") == BBQR_ERR_HEADER, "zero parts");
    CHECK(add("B$XP0100AB") == BBQR_ERR_ENCODING, "encoding X");
    CHECK(add("B$HP7T00AB") == BBQR_ERR_TOO_BIG, "more parts than the bitmap");
    CHECK(add("B$HP0100ABC") == BBQR_ERR_DATA, "odd hex digits");
    CHECK(add("B$HP0100AG") == BBQR_ERR_DATA, "not hex");
    CHECK(add("B$HP0100") == BBQR_ERR_DATA, "no data");

    start('P', LARGE_CAP);                               // Changing series
    CHECK(add(cases[h].frames[0]) == BBQR_PART_ADDED, "first part");
    strcpy(s, cases[h].frames[1]);
    s[5]++;                                              // Another total
    CHECK(add(s) == BBQR_ERR_SERIES, "other total");
    strcpy(s, cases[h].frames[1]);
    s[2] = '2';
    CHECK(add(s) == BBQR_ERR_SERIES, "other encoding");

    start('P', LARGE_CAP);                               // The same part with other data
    CHECK(add(cases[h].frames[0]) == BBQR_PART_ADDED, "first part");
    strcpy(s, cases[h].frames[0]);
    s[20] = (s[20] == '0') ? '1' : '0';
    CHECK(add(s) == BBQR_ERR_MISMATCH, "repeated part, other data");
    CHECK(add(cases[h].frames[0]) == BBQR_PART_ADDED, "repeated part, same data");
    strcpy(s, cases[h].frames[1]);
    s[strlen(s) - 2] = '\0';                             // A middle part one byte short
    CHECK(add(s) == BBQR_ERR_MISMATCH, "middle part of another length");
    strcpy(s, cases[h].frames[cases[h].count - 1]);
    strcpy(s + strlen(s), cases[h].frames[0] + 8);       // The last part longer than the others
    CHECK(add(s) == BBQR_ERR_MISMATCH, "last part too long");

    start('P', LARGE_CAP);                               // base32 lengths and padding bits
    strcpy(s, cases[b].frames[0]);
    s[strlen(s) - 1] = '\0';
    CHECK(add(s) == BBQR_ERR_DATA, "base32 middle part not a multiple of 8");
    start('P', LARGE_CAP);
    CHECK(add("B$2P0100AB") == BBQR_ERR_DATA, "base32 bits left over not zero");   // 'B' leaves bits 00001
    CHECK(add("B$2P0100A") == BBQR_ERR_DATA, "base32 of 1 character");
    CHECK(add("B$2P0100AE") == BBQR_COMPLETE, "base32 'AE' is the byte 0x01");
    uint32_t len;
    CHECK(bbqr_finish(PSBT_CAP, &len) == BBQR_COMPLETE && len == 1 && ram[0] == 0x01, "one byte");

    start('P', 500);                                     // The buffer is too small for the parts
    bbqr_result_t r = BBQR_PART_ADDED;
    for (unsigned i = 0; i < cases[h].count && r == BBQR_PART_ADDED; i++) r = add(cases[h].frames[i]);
    CHECK(r == BBQR_ERR_TOO_BIG, "parts past the buffer");
    CHECK(guard_intact(500), "wrote past a small buffer");

    start('P', LARGE_CAP);                               // Inflated, but over the limit given
    for (unsigned i = 0; i < cases[z].count; i++) add(cases[z].frames[i]);
    CHECK(bbqr_finish(500, &len) == BBQR_ERR_TOO_BIG, "inflated over the limit");

    start('P', LARGE_CAP);                               // Zero bytes do not inflate
    CHECK(add("B$ZP0100AAAAAAAA") == BBQR_COMPLETE, "zero bytes stored");
    CHECK(bbqr_finish(PSBT_CAP, &len) == BBQR_ERR_DAMAGED, "zero bytes inflate");

    start('P', LARGE_CAP);                               // Damage in compressed data
    strcpy(s, cases[z].frames[0]);
    for (int i = 30; i < 60; i++) s[i] = 'Q';
    add(s);
    for (unsigned i = 1; i < cases[z].count; i++) add(cases[z].frames[i]);
    r = bbqr_finish(PSBT_CAP, &len);
    CHECK(r == BBQR_ERR_DAMAGED || (r == BBQR_COMPLETE && (len != cases[z].file_len || memcmp(ram, case_file(z), len))),
          "damaged deflate taken as the file");
    printf("refusals checked\n");
}

// Random bytes as a compressed file: never a write past the buffer
static void random_deflate(void) {
    static const char b32[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    char s[1608];
    int done = 0, damaged = 0;
    for (int t = 0; t < 20000; t++) {
        uint32_t n = 8 * (1 + rnd(200));
        memcpy(s, "B$ZP0100", 8);
        for (uint32_t i = 0; i < n; i++) s[8 + i] = b32[rnd(32)];
        s[8 + n] = '\0';
        uint32_t cap = 200 + rnd(LARGE_CAP - 200);
        start('P', cap);
        if (add(s) != BBQR_COMPLETE) continue;
        uint32_t len;
        bbqr_result_t r = bbqr_finish(PSBT_CAP, &len);
        done++;
        damaged += (r == BBQR_ERR_DAMAGED);
        CHECK(guard_intact(cap), "random deflate wrote past the buffer");
        if (r == BBQR_COMPLETE) CHECK(len <= PSBT_CAP && len < cap, "random deflate length");
    }
    printf("random deflate: %d inflated, %d damaged\n", done, damaged);
}

// The animator page's frames (anim_frames.js): every series must give its file
static void animator_frames(void) {
    static char line[5000];
    static uint8_t file[16384];
    FILE *f = fopen("anim_frames.txt", "r");
    if (f == NULL) {
        printf("anim_frames.txt missing: run node anim_frames.js\n");
        failures++;
        return;
    }
    int series = 0;
    while (fgets(line, sizeof(line), f) != NULL) {
        char name[200], type;
        unsigned count;
        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "FILE ", 5) != 0) continue;
        char *bar = strchr(line, '|');
        if (bar == NULL) break;
        *bar = '\0';
        strcpy(name, line + 5);
        type = bar[1];
        count = (unsigned)atoi(bar + 3);
        FILE *g = fopen(name, "rb");
        size_t flen = (g != NULL) ? fread(file, 1, sizeof(file), g) : 0;
        if (g != NULL) fclose(g);
        start(type, LARGE_CAP);
        bbqr_result_t r = BBQR_PART_ADDED;
        for (unsigned i = 0; i < count; i++) {
            if (fgets(line, sizeof(line), f) == NULL) break;
            line[strcspn(line, "\r\n")] = '\0';
            r = add(line);
        }
        uint32_t len = 0;
        CHECK(r == BBQR_COMPLETE && bbqr_finish(PSBT_CAP, &len) == BBQR_COMPLETE && len == flen
              && memcmp(ram, file, len) == 0, "animator series %d (%s)", series, name);
        series++;
    }
    fclose(f);
    printf("%d animator series decoded\n", series);
}

int main(void) {
    all_cases();
    refusals();
    random_deflate();
    animator_frames();
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures != 0;
}
