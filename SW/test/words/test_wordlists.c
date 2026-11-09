// Host test of the packed BIP39 list (../../src/words_opt.h, wordpack.h) and of
// the word functions of main.c that use it, copied by extract_words.py:
//   - the list rebuilds the official english.txt (SHA-256)
//   - get_word() and find_word_index() agree with the list, for every word
//   - get_valid_next_letters() and search_unique_prefix() give, for every prefix
//     of every word and for prefixes of no word, what a search of the plain list
//     gives
// Build and run from this folder (one line for gcc):
//   python extract_words.py
//   gcc -std=c99 -O1 -Wall -Wextra -I../../src -I../../src/SSS -o test_wordlists test_wordlists.c
//       ../../src/EFF_short.c ../../src/sha256.c ../../src/SSS/memzero.c
//   ./test_wordlists
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include "sha256.h"
#include "memzero.h"
#include "EFF_short.h"
#include "words_opt.h"

const char *get_word(int index);
int find_word_index(const char *word);
#include "words_extract.inc"

static const char official_sha256[] = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda";
static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\n", __LINE__, #cond); failures++; } } while (0)

static char plain[2048][9];

// What the firmware did on the plain list, as the reference
static void ref_valid(const char *prefix, bool *valid) {
    size_t n = strlen(prefix);
    memset(valid, 0, 26);
    for (int i = 0; i < 2048; i++) {
        if (strncmp(plain[i], prefix, n) == 0 && plain[i][n] >= 'a' && plain[i][n] <= 'z') {
            valid[plain[i][n] - 'a'] = true;
        }
    }
}

static const char *ref_unique(const char *prefix) {
    size_t n = strlen(prefix);
    const char *match = NULL;
    int count = 0;
    if (n == 0) return NULL;
    for (int i = 0; i < 2048; i++) {
        if (strncmp(plain[i], prefix, n) == 0) {
            if (plain[i][n] == '\0') return plain[i];
            match = plain[i];
            if (++count > 1) return NULL;
        }
    }
    return match;
}

static long checks = 0;

static void check_prefix(const char *p) {
    bool got[26], want[26];
    char result[32];

    get_valid_next_letters(p, got);
    ref_valid(p, want);
    CHECK(memcmp(got, want, 26) == 0);
    const char *u = search_unique_prefix(p, result, sizeof(result));
    const char *r = ref_unique(p);
    CHECK((u == NULL) == (r == NULL));
    if (u != NULL && r != NULL) CHECK(strcmp(u, r) == 0);
    checks++;
}

int main(void) {
    SHA256_CTX ctx;
    BYTE hash[SHA256_BLOCK_SIZE];
    char hex[2 * SHA256_BLOCK_SIZE + 1], line[16];
    wordlist_iter_t it;

    // Sequential walk: the official file
    sha256_init(&ctx);
    wordlist_seek(&it, &bip39_list, 0);
    for (int i = 0; i < 2048; i++) {
        CHECK(wordlist_next(&it));
        CHECK(strlen(it.word) >= 3 && strlen(it.word) <= 8);
        strcpy(plain[i], it.word);
        snprintf(line, sizeof(line), "%s\n", it.word);
        sha256_update(&ctx, (const BYTE *)line, strlen(line));
    }
    CHECK(!wordlist_next(&it));
    sha256_final(&ctx, hash);
    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) sprintf(&hex[2 * i], "%02x", hash[i]);
    CHECK(strcmp(hex, official_sha256) == 0);

    // Random access and search, every word
    for (int i = 0; i < 2048; i++) {
        CHECK(strcmp(get_word(i), plain[i]) == 0);
        CHECK(find_word_index(plain[i]) == i);
    }
    CHECK(get_word(-1) == NULL && get_word(2048) == NULL);

    // Two words in use at the same time (the entropy screens do this)
    const char *a = get_word(0), *b = get_word(2047);
    CHECK(strcmp(a, "abandon") == 0 && strcmp(b, "zoo") == 0);

    // Not in the list
    static const char *const none[] = {"", "a", "abando", "abandonn", "aaaa", "xylophone", "zzz", "zoom", "zooo"};
    for (size_t i = 0; i < sizeof(none) / sizeof(none[0]); i++) {
        int want = -1;
        for (int k = 0; k < 2048; k++) if (strcmp(plain[k], none[i]) == 0) want = k;
        CHECK(find_word_index(none[i]) == want);
    }

    // Every prefix of every word, and prefixes of no word
    for (int i = 0; i < 2048; i++) {
        char p[9];
        for (size_t n = 1; n <= strlen(plain[i]); n++) {
            memcpy(p, plain[i], n);
            p[n] = '\0';
            check_prefix(p);
        }
    }
    for (char c1 = 'a'; c1 <= 'z'; c1++) {
        for (char c2 = 'a'; c2 <= 'z'; c2++) {
            char p[3] = {c1, c2, 0};
            check_prefix(p);
        }
    }
    check_prefix("zzzz");

    if (failures == 0) {
        printf("test_wordlists: %ld prefixes, list matches the official BIP39 file (SHA-256 %s)\n", checks, hex);
    }
    return failures != 0;
}
