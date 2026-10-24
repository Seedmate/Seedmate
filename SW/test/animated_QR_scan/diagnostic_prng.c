#include <stdio.h>
#include <stdint.h>
#include "../../src/sha256.h"

// Fallback in case BYTE is not defined in this scope
#ifndef BYTE
#define BYTE uint8_t
#endif

static uint64_t s[4];

static inline uint64_t rotl(const uint64_t x, int k) {
    return (x << k) | (x >> (64 - k));
}

int main(void) {
    // Specific frame from your PC simulator log that generated Degree 2 [4, 3]
    uint32_t seq = 60;
    uint32_t checksum = 0xCA2D9DDE;

    printf("=== PRNG DIAGNOSTIC FOR SEQ 60 ===\n");

    // 1. Seed Construction
    uint8_t seed[8];
    seed[0] = (seq >> 24) & 0xFF;
    seed[1] = (seq >> 16) & 0xFF;
    seed[2] = (seq >> 8) & 0xFF;
    seed[3] = seq & 0xFF;
    
    seed[4] = (checksum >> 24) & 0xFF;
    seed[5] = (checksum >> 16) & 0xFF;
    seed[6] = (checksum >> 8) & 0xFF;
    seed[7] = checksum & 0xFF;

    printf("1. SEED (8 bytes): ");
    for(int i = 0; i < 8; i++) {
        printf("%02X ", seed[i]);
    }
    printf("\n");

    // 2. SHA256 Hash
    uint8_t hash[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (BYTE*)seed, 8);
    sha256_final(&ctx, hash);

    printf("2. SHA256 HASH (32 bytes): \n   ");
    for(int i = 0; i < 32; i++) {
        printf("%02X ", hash[i]);
        if ((i + 1) % 16 == 0 && i < 31) printf("\n   ");
    }
    printf("\n");

    // 3. Xoshiro States Initialization
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

    printf("3. XOSHIRO INITIAL STATES:\n");
    printf("   S0: %016llX\n", (unsigned long long)s[0]);
    printf("   S1: %016llX\n", (unsigned long long)s[1]);
    printf("   S2: %016llX\n", (unsigned long long)s[2]);
    printf("   S3: %016llX\n", (unsigned long long)s[3]);

    // 4. First 5 PRNG Generations
    printf("4. FIRST 5 PRNG OUTPUTS:\n");
    for(int i = 1; i <= 5; i++) {
        const uint64_t result = rotl(s[1] * 5, 7) * 9;
        const uint64_t t = s[1] << 17;

        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];

        s[2] ^= t;
        s[3] = rotl(s[3], 45);

        printf("   OUT %d: %016llX\n", i, (unsigned long long)result);
    }

    return 0;
}