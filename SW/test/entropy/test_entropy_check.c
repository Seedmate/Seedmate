// Host test of the entropy check of CREATE (entropy_check_ok() in main.c,
// copied by extract_check.py): fair coins, dice and cards must warn about
// once in a thousand sessions (the tests run at p = 0.001), rigged ones must
// warn, and the raw dice must give the same counts as the same faces typed
// in STRING HASH.
//
// Build and run from this folder:
//   python extract_check.py
//   gcc -std=c99 -O1 -Wall -Wextra -o test_entropy_check test_entropy_check.c
//   ./test_entropy_check
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// --- What the extracted code needs from main.c ------------------------------
#define cSEED_coin 0
#define cSEED_dice 1
#define cSEED_cards 3
#define cCARD_MAX_HISTORY 128
static int seed_pointer;
static uint8_t data_array_256b[36];
static int bit_count_dice;
static uint8_t dice_two_bits[32];
static uint16_t dice_rolls;
static int card_history_count;
static uint16_t card_history_start_bits[cCARD_MAX_HISTORY];
static uint8_t card_history_bit_len[cCARD_MAX_HISTORY];
static const char card_rank_chars[13] = {'a', '2', '3', '4', '5', '6', '7', '8', '9', 't', 'j', 'q', 'k'};
static const char card_suit_chars[4] = {'c', 'd', 'h', 's'};
static const char *const card_entropy_map[52] = {
    "00000", "00001", "00010", "00011", "00100", "00101", "00110", "00111", "01000", "01001", "01010", "01011", "01100",
    "01101", "01110", "01111", "10000", "10001", "10010", "10011", "10100", "10101", "10110", "10111", "11000", "11001",
    "11010", "11011", "11100", "11101", "11110", "11111", "0000",  "0001",  "0010",  "0011",  "0100",  "0101",  "0110",
    "0111",  "1000",  "1001",  "1010",  "1011",  "1100",  "1101",  "1110",  "1111",  "00",    "01",    "10",    "11"
};

static int read_entropy_bit(const uint8_t data[36], int i) {
    return (i < 0 || i >= 288) ? 0 : (data[i / 8] >> (7 - i % 8)) & 1;
}
static void strcat_num(char *s, uint32_t v) { sprintf(s + strlen(s), "%u", (unsigned)v); }

// The warning screen: records what it would show, and says "use it"
static int warned;
static char warn_why[32], warn_l1[32], warn_l2[32];
static bool entropy_warning(const char *why, const char *l1, const char *l2) {
    warned++;
    strcpy(warn_why, why);
    strcpy(warn_l1, l1);
    strcpy(warn_l2, l2);
    return true;
}

#include "check_extract.inc"

// --- Building the inputs as the entry screens do -----------------------------
static void reset(int kind) {
    seed_pointer = kind;
    memset(data_array_256b, 0, sizeof(data_array_256b));
    memset(dice_two_bits, 0, sizeof(dice_two_bits));
    bit_count_dice = 0;
    dice_rolls = 0;
    card_history_count = 0;
}

static void put_bits(const char *bits) {
    for (; *bits; bits++, bit_count_dice++) {
        if (*bits == '1') data_array_256b[bit_count_dice / 8] |= (uint8_t)(0x80 >> (bit_count_dice % 8));
    }
}

static void coin(int side) { put_bits(side ? "1" : "0"); }

// Face 1..6 on the raw dice screen: 1 "01", 2 "10", 3 "11", 4 "0", 5 "1", 6 "00"
static void raw_die(int face) {
    static const char *const bits[6] = {"01", "10", "11", "0", "1", "00"};
    if (strlen(bits[face - 1]) == 2) dice_two_bits[dice_rolls >> 3] |= (uint8_t)(1u << (dice_rolls & 7u));
    dice_rolls++;
    put_bits(bits[face - 1]);
}

static void card(int index) {
    card_history_start_bits[card_history_count] = (uint16_t)bit_count_dice;
    card_history_bit_len[card_history_count] = (uint8_t)strlen(card_entropy_map[index]);
    card_history_count++;
    put_bits(card_entropy_map[index]);
}

// xorshift32: a fair source for the test, not for the device
static uint32_t rng = 2463534242u;
static uint32_t rnd(uint32_t n) {
    rng ^= rng << 13;
    rng ^= rng >> 17;
    rng ^= rng << 5;
    return rng % n;
}

static int failures;
#define CHECK(cond, what) do { if (!(cond)) { printf("FAIL %s\n", what); failures++; } } while (0)

static bool warns(void) {
    int before = warned;
    entropy_check_ok(NULL, 0);
    return warned != before;
}

static bool warns_string(const char *s) {
    int before = warned;
    entropy_check_ok(s, (uint32_t)strlen(s));
    return warned != before;
}

// --- Fair sources: about one warning per thousand sessions --------------------
#define SESSIONS 20000

static void fair_rates(void) {
    int w = 0;
    for (int s = 0; s < SESSIONS; s++) {           // 128 coins
        reset(cSEED_coin);
        for (int i = 0; i < 128; i++) coin((int)rnd(2));
        w += warns();
    }
    printf("fair coins:  %d warnings in %d sessions\n", w, SESSIONS);
    CHECK(w <= SESSIONS * 4 / 1000, "fair coins warn too often");      // Two tests at 0.1 %

    w = 0;
    for (int s = 0; s < SESSIONS; s++) {           // 50 dice, typed in STRING HASH
        char str[60];
        for (int i = 0; i < 50; i++) str[i] = (char)('1' + rnd(6));
        str[50] = '\0';
        reset(cSEED_dice);
        w += warns_string(str);
    }
    printf("fair dice:   %d warnings in %d sessions\n", w, SESSIONS);
    CHECK(w <= SESSIONS * 3 / 1000, "fair dice warn too often");

    for (int target = 128; target <= 256; target += 128) {
        w = 0;
        for (int s = 0; s < SESSIONS; s++) {       // Cards until 128 or 256 bits
            reset(cSEED_cards);
            while (bit_count_dice < target) card((int)rnd(52));
            w += warns();
        }
        printf("fair cards (%d bits): %d warnings in %d sessions\n", target, w, SESSIONS);
        CHECK(w <= SESSIONS * 4 / 1000, "fair cards warn too often");
    }
}

// --- Rigged sources: they must warn -----------------------------------------
static void rigged(void) {
    reset(cSEED_coin);
    for (int i = 0; i < 128; i++) coin(i & 1);      // HTHT...: too regular
    CHECK(warns() && strcmp(warn_why, "COINS DO NOT LOOK FAIR") == 0, "alternating coins");
    reset(cSEED_coin);
    for (int i = 0; i < 128; i++) coin(i >= 64);    // 64 heads, then 64 tails: too streaky
    CHECK(warns(), "two long runs of coins");
    reset(cSEED_coin);
    for (int i = 0; i < 128; i++) coin(i % 4 == 0); // 96 heads, 32 tails
    CHECK(warns() && strncmp(warn_l1, "H:96 T:32", 9) == 0, "coins with three heads in four");

    char str[100];
    memset(str, '6', 50);                           // The same face every time
    str[50] = '\0';
    reset(cSEED_dice);
    CHECK(warns_string(str) && strcmp(warn_why, "DICE DO NOT LOOK FAIR") == 0, "dice always 6");
    int loaded = 0;
    for (int s = 0; s < 1000; s++) {                // A die loaded to give 6 half the time
        for (int i = 0; i < 99; i++) str[i] = rnd(2) ? '6' : (char)('1' + rnd(5));
        str[99] = '\0';
        reset(cSEED_dice);
        loaded += warns_string(str);
    }
    printf("loaded die (99 rolls): %d warnings in 1000 sessions\n", loaded);
    CHECK(loaded >= 990, "a loaded die is not caught");

    // Raw dice: the faces rebuilt from the bits give the counts of the same string
    const char faces[] = "666666666666666666666666666666" "12345123451234512345";     // 30 sixes in 50
    reset(cSEED_dice);
    for (int i = 0; faces[i]; i++) raw_die(faces[i] - '0');
    CHECK(warns(), "raw dice skewed to 6");
    char raw1[32], raw2[32];
    strcpy(raw1, warn_l1);
    strcpy(raw2, warn_l2);
    reset(cSEED_dice);
    CHECK(warns_string(faces) && strcmp(raw1, warn_l1) == 0 && strcmp(raw2, warn_l2) == 0,
          "raw dice and string counts differ");
    printf("raw dice counts: %s/ %s\n", raw1, raw2);

    reset(cSEED_cards);                             // The same card 6 times in 29
    for (int i = 0; i < 29; i++) card((i < 6) ? 22 : 23 + i);
    CHECK(warns() && strcmp(warn_why, "CARDS NOT SHUFFLED WELL") == 0 && strcmp(warn_l1, "MOST SEEN td, 6 TIMES") == 0,
          "one card six times");
    printf("cards: %s / %s\n", warn_l1, warn_l2);
    reset(cSEED_cards);                             // Hearts only (cards 26..38)
    for (int i = 0; i < 29; i++) card(26 + i % 13);
    CHECK(warns() && strstr(warn_l2, "H:29") != NULL, "hearts only");
}

int main(void) {
    fair_rates();
    rigged();
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures != 0;
}
