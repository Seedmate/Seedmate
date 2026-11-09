// Host test of ../../src/kef.c against gen_kef.py (independent Python, itself
// checked against the vectors of Krux v26.09.0). Only test seeds.
/* Build and run (from this folder), one line for gcc:
     python gen_kef.py
     gcc -std=c99 -O1 -Wall -Wextra -I../../src -I../../src/crypto -I../../src/SSS -o test_kef test_kef.c
         ../../src/kef.c ../../src/sha256.c ../../src/SSS/memzero.c ../../src/crypto/consteq.c
         ../../src/crypto/fault_handler_noop.c ../../src/crypto/aes/aescrypt.c ../../src/crypto/aes/aeskey.c
         ../../src/crypto/aes/aestab.c ../../src/crypto/aes/aesgcm.c ../../src/crypto/aes/gf128mul.c
     ./test_kef
*/
#include <stdio.h>
#include <string.h>
#include "kef.h"
#include "kef_vectors.h"

static int failures = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); failures++; } } while (0)

static const uint8_t *TK = (const uint8_t *)KEY_TEXT;
#define TK_LEN ((uint32_t)strlen(KEY_TEXT))

static bool cancel_at_first(uint32_t done, uint32_t total) { (void)done; (void)total; return false; }
static uint32_t calls;
static bool count_calls(uint32_t done, uint32_t total) { (void)done; (void)total; calls++; return true; }

static void test_base43(void) {
    char text[512];
    uint8_t out[400];

    // The Krux vector, both ways
    uint32_t n = kef_base43_decode(krux_b43, (uint32_t)strlen(krux_b43), out, sizeof(out));
    CHECK(n == sizeof(krux_b43_bytes) && memcmp(out, krux_b43_bytes, n) == 0);
    n = kef_base43_encode(krux_b43_bytes, sizeof(krux_b43_bytes), text, sizeof(text));
    CHECK(n == strlen(krux_b43) && memcmp(text, krux_b43, n) == 0);

    // Round trips, leading zero bytes, every length
    uint8_t data[KEF_ENVELOPE_MAX];
    for (uint32_t len = 1; len <= 120; len++) {
        for (uint32_t zeros = 0; zeros <= 3 && zeros <= len; zeros++) {
            for (uint32_t i = 0; i < len; i++) data[i] = (i < zeros) ? 0 : (uint8_t)(i * 37u + len + 1);
            uint32_t t = kef_base43_encode(data, len, text, sizeof(text));
            CHECK(t > 0);
            uint32_t b = kef_base43_decode(text, t, out, sizeof(out));
            CHECK(b == len && memcmp(out, data, len) == 0);
        }
    }
    memset(data, 0, 5);                         // Only zeros
    n = kef_base43_encode(data, 5, text, sizeof(text));
    CHECK(n == 5 && memcmp(text, "00000", 5) == 0);
    CHECK(kef_base43_decode(text, 5, out, sizeof(out)) == 5 && memcmp(out, data, 5) == 0);

    // Refusals
    CHECK(kef_base43_decode("ab", 2, out, sizeof(out)) == 0);       // Lower case
    CHECK(kef_base43_decode("A B", 3, out, sizeof(out)) == 0);
    CHECK(kef_base43_decode("A\0B", 3, out, sizeof(out)) == 0);
    CHECK(kef_base43_decode("", 0, out, sizeof(out)) == 0);
    CHECK(kef_base43_encode(krux_b43_bytes, sizeof(krux_b43_bytes), text, 10) == 0);    // No room
    CHECK(kef_base43_decode(krux_b43, (uint32_t)strlen(krux_b43), out, 10) == 0);
    CHECK(kef_base43_decode("00000", 5, out, 4) == 0);
}

static void test_kdf(void) {
    uint8_t k[32];
    for (size_t i = 0; i < sizeof(kdf_cases) / sizeof(kdf_cases[0]); i++) {
        CHECK(kef_derive_key((const uint8_t *)kdf_cases[i].secret, kdf_cases[i].secret_len,
                             (const uint8_t *)kdf_cases[i].salt, (uint32_t)strlen(kdf_cases[i].salt),
                             kdf_cases[i].iter, k, NULL));
        CHECK(memcmp(k, kdf_cases[i].key, 32) == 0);
    }
    // The progress callback runs, and can cancel; the key is then wiped
    calls = 0;
    CHECK(kef_derive_key(TK, TK_LEN, (const uint8_t *)"s", 1, 10000, k, count_calls));
    CHECK(calls >= 30);
    CHECK(!kef_derive_key(TK, TK_LEN, (const uint8_t *)"s", 1, 10000, k, cancel_at_first));
    static const uint8_t zero[32];
    CHECK(memcmp(k, zero, 32) == 0);
}

static void open_vector(const uint8_t *env_bytes, uint32_t len, const uint8_t *want, uint32_t want_len, uint32_t iter) {
    kef_envelope_t env;
    uint8_t k[32], plain[KEF_PLAIN_MAX];
    uint32_t n = 0;

    CHECK(kef_unwrap(env_bytes, len, &env) == KEF_OK);
    CHECK(env.iterations == iter && env.id_len == 7 && memcmp(env.id, ID_TEXT, 7) == 0);
    CHECK(kef_derive_key(TK, TK_LEN, env.id, env.id_len, env.iterations, k, NULL));
    CHECK(kef_open(k, &env, plain, &n) == KEF_OK);
    CHECK(n == want_len && memcmp(plain, want, n) == 0);

    // A wrong key, and every byte of the payload damaged: refused and wiped
    static const uint8_t zero[KEF_PLAIN_MAX];
    uint8_t bad[32];
    memcpy(bad, k, 32);
    bad[7] ^= 1;
    CHECK(kef_open(bad, &env, plain, &n) == KEF_ERR_AUTH);
    CHECK(memcmp(plain, zero, sizeof(zero)) == 0);

    uint8_t copy[KEF_ENVELOPE_MAX];
    uint32_t payload_at = (uint32_t)(env.payload - env_bytes);
    for (uint32_t i = payload_at; i < len; i++) {
        memcpy(copy, env_bytes, len);
        copy[i] ^= 0x40;
        kef_envelope_t e2;
        CHECK(kef_unwrap(copy, len, &e2) == KEF_OK);
        CHECK(kef_open(k, &e2, plain, &n) == KEF_ERR_AUTH);
        CHECK(memcmp(plain, zero, sizeof(zero)) == 0);
    }
}

static void test_open(void) {
    open_vector(krux_gcm, sizeof(krux_gcm), krux_gcm_plain, sizeof(krux_gcm_plain), 100000);
    open_vector(krux_ctr, sizeof(krux_ctr), krux_ctr_plain, sizeof(krux_ctr_plain), 100000);
}

static void seal_vector(const uint8_t *plain, uint32_t plain_len, const uint8_t *want, uint32_t want_len,
                        const char *want_b43, uint32_t iter) {
    uint8_t k[32], out[KEF_ENVELOPE_MAX], back[KEF_PLAIN_MAX];
    uint32_t n = 0, m = 0;
    char text[300];
    kef_envelope_t env;
    static const uint8_t id[] = "73c5da0a";

    CHECK(kef_derive_key(TK, TK_LEN, id, 8, iter, k, NULL));
    CHECK(kef_seal_v20(k, id, 8, iter, seal_iv, plain, plain_len, out, sizeof(out), &n) == KEF_OK);
    CHECK(n == want_len && memcmp(out, want, n) == 0);
    uint32_t t = kef_base43_encode(out, n, text, sizeof(text));
    CHECK(t == strlen(want_b43) && memcmp(text, want_b43, t) == 0);

    CHECK(kef_unwrap(out, n, &env) == KEF_OK && env.iterations == iter && env.version == KEF_V_GCM);
    CHECK(kef_open(k, &env, back, &m) == KEF_OK && m == plain_len && memcmp(back, plain, m) == 0);
}

static void test_seal(void) {
    uint8_t k[32] = {1}, out[KEF_ENVELOPE_MAX];
    uint32_t n;
    static const uint8_t id[] = "id";
    static const uint8_t p16[16], p32[32], p20[20];

    seal_vector(s12_plain, sizeof(s12_plain), s12_env, sizeof(s12_env), s12_b43, S12_ITER);
    seal_vector(s24_plain, sizeof(s24_plain), s24_env, sizeof(s24_env), s24_b43, S24_ITER);

    // Refusals: size, room and iterations that cannot be stored
    CHECK(kef_seal_v20(k, id, 2, 100000, seal_iv, p20, 20, out, sizeof(out), &n) == KEF_ERR_SIZE);
    CHECK(kef_seal_v20(k, id, 2, 100000, seal_iv, p16, 16, out, 10, &n) == KEF_ERR_SIZE);
    CHECK(kef_seal_v20(k, id, KEF_ID_MAX + 1, 100000, seal_iv, p16, 16, out, sizeof(out), &n) == KEF_ERR_SIZE);
    CHECK(kef_seal_v20(k, id, 2, 0, seal_iv, p16, 16, out, sizeof(out), &n) == KEF_ERR_ITERATIONS);
    CHECK(kef_seal_v20(k, id, 2, 9999, seal_iv, p16, 16, out, sizeof(out), &n) == KEF_ERR_ITERATIONS);
    CHECK(kef_seal_v20(k, id, 2, 1u << 24, seal_iv, p32, 32, out, sizeof(out), &n) == KEF_ERR_ITERATIONS);
    CHECK(kef_seal_v20(k, id, 2, 10000, seal_iv, p32, 32, out, sizeof(out), &n) == KEF_OK);
    CHECK(out[3] == KEF_V_GCM && out[4] == 0 && out[5] == 0 && out[6] == 1);    // 10,000 is stored as 1
}

static void test_unwrap(void) {
    kef_envelope_t env;
    uint8_t e[64] = {0};

    CHECK(kef_unwrap(e, 0, &env) == KEF_ERR_FORMAT);
    // id longer than the data
    e[0] = 50;
    CHECK(kef_unwrap(e, 10, &env) == KEF_ERR_FORMAT);
    e[0] = 253;
    CHECK(kef_unwrap(e, 60, &env) == KEF_ERR_FORMAT);

    memcpy(e, krux_gcm, sizeof(krux_gcm));
    e[8] = 21;                                  // Compressed GCM: not read
    CHECK(kef_unwrap(e, sizeof(krux_gcm), &env) == KEF_ERR_VERSION);
    e[8] = 10;                                  // CBC: not read
    CHECK(kef_unwrap(e, sizeof(krux_gcm), &env) == KEF_ERR_VERSION);

    memcpy(e, krux_gcm, sizeof(krux_gcm));
    e[9] = e[10] = e[11] = 0;                   // Iterations 0
    CHECK(kef_unwrap(e, sizeof(krux_gcm), &env) == KEF_ERR_ITERATIONS);

    memcpy(e, krux_gcm, sizeof(krux_gcm));
    e[9] = 0; e[10] = 0x27; e[11] = 0x11;       // 10,001: as it is
    CHECK(kef_unwrap(e, sizeof(krux_gcm), &env) == KEF_OK && env.iterations == 10001);
    e[10] = 0x27; e[11] = 0x10;                 // 10,000: times 10,000
    CHECK(kef_unwrap(e, sizeof(krux_gcm), &env) == KEF_OK && env.iterations == 100000000u);

    // No room for the IV, the tag and one byte of text
    CHECK(kef_unwrap(krux_gcm, 12 + KEF_IV_LEN + KEF_TAG_LEN, &env) == KEF_ERR_FORMAT);
    CHECK(kef_unwrap(krux_gcm, 12 + KEF_IV_LEN + KEF_TAG_LEN + 1, &env) == KEF_OK);

    // Payload too long for a seed: refused, nothing written past the buffer
    uint8_t big[KEF_ENVELOPE_MAX + 40], k[32] = {0}, plain[KEF_PLAIN_MAX];
    uint32_t n;
    memset(big, 0, sizeof(big));
    memcpy(big, krux_gcm, 12);
    CHECK(kef_unwrap(big, 12 + KEF_IV_LEN + KEF_TAG_LEN + 40, &env) == KEF_OK);
    CHECK(kef_open(k, &env, plain, &n) == KEF_ERR_SIZE);
}

int main(void) {
    test_base43();
    test_kdf();
    test_unwrap();
    test_open();
    test_seal();
    if (failures == 0) printf("test_kef: all tests passed\n");
    return failures != 0;
}
