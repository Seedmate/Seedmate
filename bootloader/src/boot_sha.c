/*******************************************************************************
  SHA-256 of the update file (Bootloader). See boot_sha.h.

  Compact implementation (FIPS 180-4) for a bootloader that has almost no
  flash left: the message schedule is a 16 word ring instead of 64 words and
  the working variables rotate in a loop, which is much smaller than the
  app's sha256.c. Checked against Python's hashlib by test/test_boot_sha.c.
 *******************************************************************************/

#include "boot_sha.h"

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static uint32_t state[8];
static uint8_t block[64];
static uint32_t block_len;      // Bytes in 'block'
static uint32_t total_len;      // Bytes hashed so far

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

// One 64 byte block of 'block' into 'state'
static void transform(void) {
    uint32_t w[16], v[8], t1, t2, t;

    for (int i = 0; i < 16; i++) {
        w[i] = (uint32_t)block[4 * i] << 24 | (uint32_t)block[4 * i + 1] << 16 |
               (uint32_t)block[4 * i + 2] << 8 | block[4 * i + 3];
    }
    for (int i = 0; i < 8; i++) v[i] = state[i];

    for (int i = 0; i < 64; i++) {
        if (i >= 16) {          // w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16], in place
            t = w[(i + 14) & 15];
            t1 = ROR(t, 17) ^ ROR(t, 19) ^ (t >> 10);
            t = w[(i + 1) & 15];
            t2 = ROR(t, 7) ^ ROR(t, 18) ^ (t >> 3);
            w[i & 15] += t1 + w[(i + 9) & 15] + t2;
        }
        t1 = v[7] + (ROR(v[4], 6) ^ ROR(v[4], 11) ^ ROR(v[4], 25)) +
             ((v[4] & v[5]) ^ (~v[4] & v[6])) + K[i] + w[i & 15];
        t2 = (ROR(v[0], 2) ^ ROR(v[0], 13) ^ ROR(v[0], 22)) +
             ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        for (int j = 7; j > 0; j--) v[j] = v[j - 1];
        v[4] += t1;
        v[0] = t1 + t2;
    }
    for (int i = 0; i < 8; i++) state[i] += v[i];
}

void boot_sha_init(void) {
    static const uint32_t h0[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    for (int i = 0; i < 8; i++) state[i] = h0[i];
    block_len = 0;
    total_len = 0;
}

void boot_sha_update(const uint8_t *data, uint32_t len) {
    total_len += len;
    while (len-- > 0) {
        block[block_len++] = *data++;
        if (block_len == 64) {
            transform();
            block_len = 0;
        }
    }
}

void boot_sha_final(uint8_t digest[32]) {
    uint32_t bits_hi = total_len >> 29, bits_lo = total_len << 3;

    block[block_len++] = 0x80;
    if (block_len > 56) {                           // No room for the length: one more block
        while (block_len < 64) block[block_len++] = 0;
        transform();
        block_len = 0;
    }
    while (block_len < 56) block[block_len++] = 0;
    for (int i = 0; i < 4; i++) {                   // 64-bit length in bits, big endian
        block[56 + i] = (uint8_t)(bits_hi >> (24 - 8 * i));
        block[60 + i] = (uint8_t)(bits_lo >> (24 - 8 * i));
    }
    transform();
    for (int i = 0; i < 32; i++) digest[i] = (uint8_t)(state[i / 4] >> (24 - 8 * (i % 4)));
}
