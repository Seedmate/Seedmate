#include "prng.h"
#include "sha256.h"
#include <stdint.h>

#ifndef BYTE
#define BYTE uint8_t
#endif

static uint64_t s[4];

static inline uint64_t rotl(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

void prng_seed(uint32_t seq, uint32_t total, uint32_t msg_len, uint32_t checksum) {
    (void)total;
    (void)msg_len;

    uint8_t seed[8];
    
    // 1. MUST BE BIG ENDIAN (8-byte seed: 4-byte seq + 4-byte checksum)
    seed[0] = (seq >> 24) & 0xFF;
    seed[1] = (seq >> 16) & 0xFF;
    seed[2] = (seq >> 8) & 0xFF;
    seed[3] = seq & 0xFF;
    
    seed[4] = (checksum >> 24) & 0xFF;
    seed[5] = (checksum >> 16) & 0xFF;
    seed[6] = (checksum >> 8) & 0xFF;
    seed[7] = checksum & 0xFF;

    uint8_t hash[32];
    
    // 2. Hash the 8-byte seed
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (BYTE*)seed, 8);
    sha256_final(&ctx, hash);

    // 3. BC-UR Xoshiro256 state initialized in BIG ENDIAN from the hash
    for (int i = 0; i < 4; i++) {
        s[i] = ((uint64_t)hash[i*8 + 0] << 56) |
               ((uint64_t)hash[i*8 + 1] << 48) |
               ((uint64_t)hash[i*8 + 2] << 40) |
               ((uint64_t)hash[i*8 + 3] << 32) |
               ((uint64_t)hash[i*8 + 4] << 24) |
               ((uint64_t)hash[i*8 + 5] << 16) |
               ((uint64_t)hash[i*8 + 6] << 8)  |
               ((uint64_t)hash[i*8 + 7]);
    }
}

uint64_t prng_next(void) {
    const uint64_t result = rotl(s[1] * 5, 7) * 9;
    const uint64_t t = s[1] << 17;

    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];

    s[2] ^= t;
    s[3] = rotl(s[3], 45);

    return result;
}