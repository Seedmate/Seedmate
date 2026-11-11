/*******************************************************************************
  Firmware signature check (Bootloader). See boot_lms.h.

  Compiled inside main.c, like TFT.c in boot_ui.c, so the MPLAB project does not
  change. RFC 8554 algorithms 4b and 6a, for one parameter set. Only public data
  is handled here. Host test: test/test_boot_lms.c.
 *******************************************************************************/

#include <string.h>
#include "boot_lms.h"
#include "boot_sha.h"

// Release key (2026-11-11), made with SW/tools/lms_sign.html: LMS_SHA256_M32_H10,
// LMOTS_SHA256_N32_W8. Each of its 1024 indexes signs one firmware only
// (docs/pending.md: keep a record of the indexes used).
const uint8_t boot_lms_public_key[BOOT_LMS_PUB_SIZE] = {
    0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x04,
    0xc0, 0xf2, 0xa2, 0x17, 0x12, 0x3b, 0xd1, 0xf4,
    0x9d, 0x67, 0xa6, 0x1a, 0x35, 0xed, 0xe5, 0xc5,
    0xc1, 0x9f, 0xa6, 0x02, 0xd5, 0xef, 0xe7, 0x57,
    0xc4, 0x43, 0xeb, 0xa7, 0x9a, 0x86, 0xb1, 0x48,
    0xb3, 0x19, 0x78, 0xc2, 0x1f, 0x87, 0xfd, 0xb7,
    0x90, 0x6b, 0xc1, 0x87, 0x93, 0x94, 0xd4, 0x73,
};

#define LMS_TYPE    6u      // LMS_SHA256_M32_H10
#define OTS_TYPE    4u      // LMOTS_SHA256_N32_W8
#define LMS_LEAVES  1024u

// Signature layout
#define SIG_Q       0u      // Leaf
#define SIG_OTS     4u      // LMOTS type
#define SIG_C       8u
#define SIG_Y       40u     // The 34 chain values
#define SIG_LMS     (SIG_Y + BOOT_LMS_CHAINS * 32u)     // LMS type
#define SIG_PATH    (SIG_LMS + 4u)                      // The 10 siblings

__attribute__((noinline)) static uint32_t read_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

__attribute__((noinline)) static void write_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

// H(I || u32 || d1 d2 || a[32]..) up to the point every node hash shares
__attribute__((noinline)) static void node_start(const uint8_t *id, uint32_t value, uint8_t domain) {
    uint8_t head[22];
    memcpy(head, id, 16);
    write_be32(head + 16, value);
    head[20] = domain;
    head[21] = domain;
    boot_sha_init();
    boot_sha_update(head, sizeof(head));
}

bool boot_lms_verify(const uint8_t pub[BOOT_LMS_PUB_SIZE], const uint8_t message[32],
                     uint8_t sig[BOOT_LMS_SIG_SIZE], void (*progress)(uint32_t done, uint32_t total)) {
    const uint8_t *id = pub + 8;
    uint32_t q = read_be32(sig + SIG_Q);
    uint8_t digits[34], node[32], chain[55];

    if (read_be32(pub) != LMS_TYPE || read_be32(pub + 4) != OTS_TYPE) return false;
    if (q >= LMS_LEAVES || read_be32(sig + SIG_OTS) != OTS_TYPE || read_be32(sig + SIG_LMS) != LMS_TYPE) return false;

    // Q = H(I || q || D_MESG || C || message), then its checksum: where each chain stopped
    node_start(id, q, 0x81);
    boot_sha_update(sig + SIG_C, 32);
    boot_sha_update(message, 32);
    boot_sha_final(digits);
    uint32_t sum = 0;
    for (uint32_t i = 0; i < 32u; i++) sum += 255u - digits[i];
    digits[32] = (uint8_t)(sum >> 8);
    digits[33] = (uint8_t)sum;

    // Each value is taken to the end of its chain, in place:
    // tmp = H(I || q || i || j || tmp) for j = digit .. 254
    memcpy(chain, id, 16);
    write_be32(chain + 16, q);
    for (uint32_t i = 0; i < BOOT_LMS_CHAINS; i++) {
        uint8_t *y = sig + SIG_Y + i * 32u;
        chain[20] = 0;
        chain[21] = (uint8_t)i;
        memcpy(chain + 23, y, 32);
        for (uint32_t j = digits[i]; j < 255u; j++) {
            chain[22] = (uint8_t)j;
            boot_sha_init();
            boot_sha_update(chain, sizeof(chain));
            boot_sha_final(chain + 23);
        }
        memcpy(y, chain + 23, 32);
        if (progress != NULL) progress(i + 1u, BOOT_LMS_CHAINS);
    }

    // The one time public key, then up the tree to the root
    node_start(id, q, 0x80);
    boot_sha_update(sig + SIG_Y, BOOT_LMS_CHAINS * 32u);
    boot_sha_final(node);

    uint32_t r = LMS_LEAVES + q;
    node_start(id, r, 0x82);
    boot_sha_update(node, 32);
    boot_sha_final(node);

    const uint8_t *sibling = sig + SIG_PATH;
    while (r > 1u) {
        uint32_t odd = r & 1u;
        r >>= 1;
        node_start(id, r, 0x83);
        boot_sha_update(odd ? sibling : node, 32);
        boot_sha_update(odd ? node : sibling, 32);
        boot_sha_final(node);
        sibling += 32;
    }
    return memcmp(node, pub + 24, 32) == 0;
}
