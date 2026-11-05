// Host test of the bootloader's firmware signature check (boot_lms.c). Not part
// of the bootloader image. Signatures from gen_lms_vectors.js, made by the signing
// page, whose script matches RFC 8554 Test Case 2 (SW/test/lms/test_lms.js).
//   gcc -std=c99 -Wall -Wextra -O1 -I../src test_boot_lms.c ../src/boot_sha.c ../src/boot_lms.c -o test_boot_lms
#include <stdio.h>
#include <string.h>
#include "boot_lms.h"
#include "lms_vectors.h"

static int failures = 0, progress_calls = 0;
static uint8_t work[BOOT_LMS_SIG_SIZE];

#define CHECK(cond) do { if (!(cond)) { printf("FAIL line %d: %s\n", __LINE__, #cond); failures++; } } while (0)

static void count_progress(uint32_t done, uint32_t total) {
    if (done <= total) progress_calls++;
}

static bool verify(const uint8_t *pub, const uint8_t *msg, const uint8_t *sig) {
    memcpy(work, sig, sizeof(work));
    return boot_lms_verify(pub, msg, work, NULL);
}

int main(void) {
    // Good signatures: first leaf, middle, last leaf
    CHECK(verify(vec_pub, vec_msg, vec_sig_0));
    CHECK(verify(vec_pub, vec_msg, vec_sig_7));
    CHECK(verify(vec_pub, vec_msg, vec_sig_1023));

    memcpy(work, vec_sig_7, sizeof(work));
    CHECK(boot_lms_verify(vec_pub, vec_msg, work, count_progress));
    CHECK(progress_calls == BOOT_LMS_CHAINS);

    // Every field of the signature counts: one flipped bit anywhere
    int refused = 0;
    for (uint32_t at = 0; at < BOOT_LMS_SIG_SIZE; at += 37) {
        uint8_t bad[BOOT_LMS_SIG_SIZE];
        memcpy(bad, vec_sig_7, sizeof(bad));
        bad[at] ^= 0x01;
        if (!verify(vec_pub, vec_msg, bad)) refused++;
    }
    CHECK(refused == (BOOT_LMS_SIG_SIZE + 36) / 37);

    // Index out of range
    uint8_t bad[BOOT_LMS_SIG_SIZE];
    memcpy(bad, vec_sig_7, sizeof(bad));
    bad[2] = 0x04;                      // q = 1024 + 7
    CHECK(!verify(vec_pub, vec_msg, bad));

    // Another file
    uint8_t msg[32];
    memcpy(msg, vec_msg, 32);
    msg[31] ^= 0x80;
    CHECK(!verify(vec_pub, msg, vec_sig_7));

    // Another public key: the one in the firmware does not take the test signature
    uint8_t pub[BOOT_LMS_PUB_SIZE];
    memcpy(pub, vec_pub, sizeof(pub));
    pub[55] ^= 1;
    CHECK(!verify(pub, vec_msg, vec_sig_7));
    pub[55] ^= 1;
    pub[10] ^= 1;
    CHECK(!verify(pub, vec_msg, vec_sig_7));
    CHECK(!verify(boot_lms_public_key, vec_msg, vec_sig_7));

    // The key in the firmware has the right types
    CHECK(boot_lms_public_key[3] == 6 && boot_lms_public_key[7] == 4);

    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures != 0;
}
