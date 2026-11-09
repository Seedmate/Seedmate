// Host test of the EFF Short Wordlist 1 in the firmware (EFF_short.c): it
// rebuilds the official file "dddd<TAB>word\n" x 1296 from the list and its
// dice order, and compares its SHA-256 with the one of the file published by
// the EFF. Any changed, missing or reordered word fails.
// Build: gcc -Wall -I../../src -I../../src/SSS -o test_eff test_eff.c ../../src/EFF_short.c ../../src/sha256.c ../../src/SSS/memzero.c
#include <stdio.h>
#include <string.h>
#include "EFF_short.h"
#include "sha256.h"

static const char official_sha256[] = "8f5ca830b8bffb6fe39c9736c024a00a6a6411adb3f83a9be8bfeeb6e067ae69";
static int failures = 0;

#define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\n", __LINE__, #cond); failures++; } } while (0)

static int index_of_dice(const char *d) {
    return (d[0] - '1') * 216 + (d[1] - '1') * 36 + (d[2] - '1') * 6 + (d[3] - '1');
}

int main(void) {
    SHA256_CTX ctx;
    BYTE hash[SHA256_BLOCK_SIZE];
    char hex[2 * SHA256_BLOCK_SIZE + 1];
    char line[16];

    sha256_init(&ctx);
    for (int i = 0; i < EFF_SHORT_WORDS; i++) {
        char w[9];
        bool ok = get_eff_short_word(i, w);
        char dice[5];
        int v = i;
        for (int k = 3; k >= 0; k--) { dice[k] = (char)('1' + v % 6); v /= 6; }
        dice[4] = '\0';
        CHECK(ok && strlen(w) >= 3 && strlen(w) <= 5);
        CHECK(index_of_dice(dice) == i);
        snprintf(line, sizeof(line), "%s\t%s\n", dice, w);
        sha256_update(&ctx, (const BYTE *)line, strlen(line));
    }
    sha256_final(&ctx, hash);
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) sprintf(&hex[2 * i], "%02x", hash[i]);
    CHECK(strcmp(hex, official_sha256) == 0);

    // Out of range and a few known entries of the printed list
    char word[9];
    CHECK(!get_eff_short_word(-1, word) && !get_eff_short_word(EFF_SHORT_WORDS, word));
    CHECK(get_eff_short_word(index_of_dice("1111"), word) && strcmp(word, "acid") == 0);
    CHECK(get_eff_short_word(index_of_dice("6652"), word) && strcmp(word, "yo-yo") == 0);
    CHECK(get_eff_short_word(index_of_dice("6666"), word) && strcmp(word, "zoom") == 0);

    if (failures == 0) printf("test_eff: list matches the official EFF file (SHA-256 %s)\n", hex);
    return failures != 0;
}
