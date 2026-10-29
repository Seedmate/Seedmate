/*******************************************************************************
 * Project:     SeedMate
 * File:        kdf.c
 *
 * Summary:
 *   HMAC-SHA512 and PBKDF2-HMAC-SHA512. See kdf.h.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include <string.h>
#include "kdf.h"
#include "sha512.h"
#include "SSS/memzero.h"

#define SHA512_BLOCK 128

#define KDF_PROGRESS_EVERY 16   // Iterations between progress callbacks

// HMAC-SHA512 over the concatenation data1 || data2 (data2 may be empty)
static void hmac_sha512_2(const uint8_t *key, size_t keyLen,
                          const uint8_t *data1, size_t len1,
                          const uint8_t *data2, size_t len2,
                          uint8_t *out) {
    uint8_t pad[SHA512_BLOCK];
    SHA512_HASH hash;
    Sha512Context ctx;

    // Keys longer than a block are hashed first (RFC 2104)
    if (keyLen > SHA512_BLOCK) {
        Sha512Initialise(&ctx);
        Sha512Update(&ctx, key, (uint32_t)keyLen);
        Sha512Finalise(&ctx, &hash);
        key = hash.bytes;
        keyLen = KDF_SHA512_SIZE;
    }

    // Inner hash: H((K ^ ipad) || data1 || data2)
    memset(pad, 0x36, sizeof(pad));
    for (size_t i = 0; i < keyLen; i++) pad[i] ^= key[i];
    Sha512Initialise(&ctx);
    Sha512Update(&ctx, pad, SHA512_BLOCK);
    Sha512Update(&ctx, data1, (uint32_t)len1);
    if (len2 > 0) Sha512Update(&ctx, data2, (uint32_t)len2);

    // Turn the inner pad into the outer pad before the key copy is lost
    for (size_t i = 0; i < SHA512_BLOCK; i++) pad[i] ^= 0x36 ^ 0x5C;
    Sha512Finalise(&ctx, &hash);

    // Outer hash: H((K ^ opad) || inner)
    Sha512Initialise(&ctx);
    Sha512Update(&ctx, pad, SHA512_BLOCK);
    Sha512Update(&ctx, hash.bytes, KDF_SHA512_SIZE);
    Sha512Finalise(&ctx, &hash);
    memcpy(out, hash.bytes, KDF_SHA512_SIZE);

    memzero(pad, sizeof(pad));
    memzero(&hash, sizeof(hash));
    memzero(&ctx, sizeof(ctx));
}

void HmacSha512(const uint8_t *key, size_t keyLen,
                const uint8_t *data, size_t dataLen,
                uint8_t *out) {
    hmac_sha512_2(key, keyLen, data, dataLen, NULL, 0, out);
}

void PBKDF2_HMAC_SHA512(const char *password, const char *salt,
                        uint32_t iterations, uint8_t *output, size_t dkLen,
                        kdf_progress_t progress) {
    uint8_t U[KDF_SHA512_SIZE];
    uint8_t T[KDF_SHA512_SIZE];
    uint8_t counter[4];
    size_t passwordLen = strlen(password);
    size_t saltLen = strlen(salt);
    uint32_t blockCount = (uint32_t)((dkLen + KDF_SHA512_SIZE - 1) / KDF_SHA512_SIZE);

    for (uint32_t i = 1; i <= blockCount; i++) {
        // U1 = HMAC(password, salt || INT_32_BE(i)): no copy of the salt
        counter[0] = (uint8_t)(i >> 24);
        counter[1] = (uint8_t)(i >> 16);
        counter[2] = (uint8_t)(i >> 8);
        counter[3] = (uint8_t)i;
        hmac_sha512_2((const uint8_t *)password, passwordLen,
                      (const uint8_t *)salt, saltLen, counter, 4, U);
        memcpy(T, U, KDF_SHA512_SIZE);

        for (uint32_t j = 2; j <= iterations; j++) {
            HmacSha512((const uint8_t *)password, passwordLen, U, KDF_SHA512_SIZE, U);
            for (int k = 0; k < KDF_SHA512_SIZE; k++) T[k] ^= U[k];
            if (progress != NULL && (j % KDF_PROGRESS_EVERY) == 0) progress(j, iterations);
        }

        size_t offset = (size_t)(i - 1) * KDF_SHA512_SIZE;
        size_t toCopy = (dkLen - offset < KDF_SHA512_SIZE) ? (dkLen - offset) : KDF_SHA512_SIZE;
        memcpy(output + offset, T, toCopy);
    }

    memzero(U, sizeof(U));
    memzero(T, sizeof(T));
}
