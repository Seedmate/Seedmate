#include "sampler.h"
#include "prng.h"

// XC32 treats 'double' as 32-bit by default unless -fno-short-double is set.
// Using 'long double' on XC32 guarantees strict 64-bit IEEE-754 precision.
#ifdef __XC32
typedef long double ur_double_t;
#define UR_FLOAT_CONST(x) x##L
#else
typedef double ur_double_t;
#define UR_FLOAT_CONST(x) x
#endif

static ur_double_t alias_probs[MAX_UR_TOTAL_PARTS];
static int alias_table[MAX_UR_TOTAL_PARTS];
static uint32_t current_total = 0;

// Exact BC-UR RandomSampler initialization (Vose's Alias Method on 1/k harmonic distribution)
static void init_fountain_distribution(uint32_t total) {
    if (current_total == total) return;
    current_total = total;

    ur_double_t probs[MAX_UR_TOTAL_PARTS];
    ur_double_t sum = UR_FLOAT_CONST(0.0);
    for (uint32_t i = 0; i < total; i++) {
        probs[i] = UR_FLOAT_CONST(1.0) / (ur_double_t)(i + 1);
        sum += probs[i];
    }

    ur_double_t P[MAX_UR_TOTAL_PARTS];
    int S[MAX_UR_TOTAL_PARTS];
    int L[MAX_UR_TOTAL_PARTS];
    int s_count = 0;
    int l_count = 0;

    for (uint32_t i = 0; i < total; i++) {
        P[i] = (probs[i] * (ur_double_t)total) / sum;
    }

    // Partition into small and large lists in reverse order as per BC-UR reference
    for (int i = (int)total - 1; i >= 0; i--) {
        if (P[i] < UR_FLOAT_CONST(1.0)) {
            S[s_count++] = i;
        } else {
            L[l_count++] = i;
        }
    }

    while (s_count > 0 && l_count > 0) {
        int a = S[--s_count];
        int g = L[--l_count];
        alias_probs[a] = P[a];
        alias_table[a] = g;
        P[g] = (P[g] + P[a]) - UR_FLOAT_CONST(1.0);
        if (P[g] < UR_FLOAT_CONST(1.0)) {
            S[s_count++] = g;
        } else {
            L[l_count++] = g;
        }
    }

    while (l_count > 0) {
        alias_probs[L[--l_count]] = UR_FLOAT_CONST(1.0);
    }
    while (s_count > 0) {
        alias_probs[S[--s_count]] = UR_FLOAT_CONST(1.0);
    }
}

static ur_double_t rng_next_double(void) {
    // BC-UR Xoshiro256 next_double divides full uint64_t by (MAX_UINT64 + 1.0) = 2^64
    return (ur_double_t)prng_next() / UR_FLOAT_CONST(18446744073709551616.0);
}

static uint32_t rng_next_int(uint32_t low, uint32_t high) {
    return (uint32_t)((ur_double_t)low + rng_next_double() * (ur_double_t)(high - low + 1));
}

void get_fountain_parts(uint32_t seq, uint32_t total, uint32_t msg_len, uint32_t checksum, uint32_t *out_degree, uint32_t *out_fragments) {
    if (seq <= total) {
        *out_degree = 1;
        out_fragments[0] = seq - 1;
        return;
    }

    init_fountain_distribution(total);
    prng_seed(seq, total, msg_len, checksum);

    // 1. Choose degree using Vose's Alias Method (consumes EXACTLY 2 PRNG calls)
    uint32_t c = rng_next_int(0, total - 1);
    ur_double_t d = rng_next_double();
    uint32_t degree = (d < alias_probs[c]) ? (c + 1) : ((uint32_t)alias_table[c] + 1);
    *out_degree = degree;

    // 2. Shuffle / choose fragments using shift-left removal
    uint32_t indexes[MAX_UR_TOTAL_PARTS];
    for (uint32_t i = 0; i < total; i++) {
        indexes[i] = i;
    }

    uint32_t remaining = total;
    for (uint32_t i = 0; i < degree; i++) {
        uint32_t pick_idx = rng_next_int(0, remaining - 1);
        if (pick_idx >= remaining) pick_idx = remaining - 1;

        out_fragments[i] = indexes[pick_idx];

        for (uint32_t j = pick_idx; j + 1 < remaining; j++) {
            indexes[j] = indexes[j + 1];
        }
        remaining--;
    }
}