// Host-side tests for kdf.c (HMAC-SHA512 and BIP39 PBKDF2). Not part of the
// firmware. Long passphrases used to overflow a 32-byte salt buffer.
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "kdf.h"
#include "kdf_vectors.h"

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static uint32_t progress_calls, progress_last, progress_total;
static int progress_monotonic;

static bool on_progress(uint32_t done, uint32_t total) {
    if (done <= progress_last) progress_monotonic = 0;
    progress_last = done;
    progress_total = total;
    progress_calls++;
    return true;
}

// Cancels a quarter of the way through
static bool cancel_early(uint32_t done, uint32_t total) {
    return done < total / 4;
}

int main(void) {
    uint8_t out[64];

    // HMAC-SHA512: RFC 4231 cases 2 (short key) and 6 (key longer than a block)
    static const char jefe_msg[] = "what do ya want for nothing?";
    HmacSha512((const uint8_t *)"Jefe", 4, (const uint8_t *)jefe_msg, strlen(jefe_msg), out);
    CHECK(memcmp(out, hmac_jefe_mac, 64) == 0);

    uint8_t long_key[131];
    static const char long_msg[] = "Test Using Larger Than Block-Size Key - Hash Key First";
    memset(long_key, 0xAA, sizeof(long_key));
    HmacSha512(long_key, sizeof(long_key), (const uint8_t *)long_msg, strlen(long_msg), out);
    CHECK(memcmp(out, hmac_long_key_mac, 64) == 0);

    // In place (out == data), as PBKDF2 uses it
    memcpy(out, jefe_msg, strlen(jefe_msg));
    HmacSha512((const uint8_t *)"Jefe", 4, out, strlen(jefe_msg), out);
    CHECK(memcmp(out, hmac_jefe_mac, 64) == 0);

    // BIP39 seeds, including passphrases up to the 199 characters the device allows
    char salt[8 + 200];
    for (size_t i = 0; i < sizeof(kdf_cases) / sizeof(kdf_cases[0]); i++) {
        strcpy(salt, "mnemonic");
        strcat(salt, kdf_cases[i].passphrase);
        progress_calls = progress_last = progress_total = 0;
        progress_monotonic = 1;
        memset(out, 0, sizeof(out));
        CHECK(PBKDF2_HMAC_SHA512(kdf_cases[i].mnemonic, salt, 2048, out, 64, on_progress));
        if (memcmp(out, kdf_cases[i].seed, 64) != 0) {
            printf("FAIL seed for passphrase of %u chars\n", (unsigned)strlen(kdf_cases[i].passphrase));
            failures++;
        }
        CHECK(progress_calls == 2048 / 16 && progress_last == 2048 && progress_total == 2048 && progress_monotonic);
    }

    // A NULL progress callback is allowed
    CHECK(PBKDF2_HMAC_SHA512(kdf_cases[0].mnemonic, "mnemonic", 2048, out, 64, NULL));
    CHECK(memcmp(out, kdf_cases[0].seed, 64) == 0);

    // Cancelled: returns false and leaves no partial result behind
    static const uint8_t zeros[64] = {0};
    memset(out, 0xAA, sizeof(out));
    CHECK(!PBKDF2_HMAC_SHA512(kdf_cases[0].mnemonic, "mnemonic", 2048, out, 64, cancel_early));
    CHECK(memcmp(out, zeros, 64) == 0);

    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures != 0;
}
