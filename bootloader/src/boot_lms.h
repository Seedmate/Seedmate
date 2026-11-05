/*******************************************************************************
  Firmware signature check (Bootloader)

  Summary:
    RFC 8554 LMS verification of UPDATE.SIG against the public key below,
    LMS_SHA256_M32_H10 with LMOTS_SHA256_N32_W8. The signed message is the
    32 byte SHA-256 of UPDATE.HEX. Made by SW/tools/lms_sign.html.
 *******************************************************************************/

#ifndef BOOT_LMS_H
#define BOOT_LMS_H

#include <stdint.h>
#include <stdbool.h>

#define BOOT_LMS_SIG_SIZE   1452u       // 4 + 4 + 32 + 34 * 32 + 4 + 10 * 32
#define BOOT_LMS_PUB_SIZE   56u         // 4 + 4 + 16 + 32
#define BOOT_LMS_CHAINS     34u

// The key official firmware is signed with
extern const uint8_t boot_lms_public_key[BOOT_LMS_PUB_SIZE];

// True if sig is a valid signature of message under pub. sig is used as work
// space and changed. progress (may be NULL) is called after each hash chain.
// Uses the single boot_sha context.
bool boot_lms_verify(const uint8_t pub[BOOT_LMS_PUB_SIZE], const uint8_t message[32],
                     uint8_t sig[BOOT_LMS_SIG_SIZE], void (*progress)(uint32_t done, uint32_t total));

#endif // BOOT_LMS_H
