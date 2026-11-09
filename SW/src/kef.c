/*******************************************************************************
 * Project:     SeedMate
 * File:        kef.c
 *
 * Summary:
 *   KEF encrypted mnemonic format of Krux. See kef.h and ../docs/kef.md.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include <string.h>
#include "kef.h"
#include "sha256.h"
#include "SSS/memzero.h"
#include "crypto/aes/aes.h"
#include "crypto/aes/aesgcm.h"
#include "crypto/consteq.h"

#define SHA256_BLOCK        64
#define KEF_PROGRESS_EVERY  256u        // Iterations between progress callbacks

static const char b43_chars[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ$*+-./:";

// ---------------------------------------------------------------------------
// Base43: a big number in base 256 written in base 43, one '0' per leading zero byte
// ---------------------------------------------------------------------------
uint32_t kef_base43_encode(const uint8_t *data, uint32_t len, char *text, uint32_t cap) {
    uint8_t num[KEF_ENVELOPE_MAX];
    uint32_t zeros = 0, start, n = 0;

    if (len == 0 || len > sizeof(num)) return 0;
    while (zeros < len && data[zeros] == 0) zeros++;
    memcpy(num, data, len);
    start = zeros;
    while (start < len) {                       // Divide by 43, the rest is the next digit
        uint32_t rest = 0;
        for (uint32_t i = start; i < len; i++) {
            uint32_t v = (rest << 8) | num[i];
            num[i] = (uint8_t)(v / 43u);
            rest = v % 43u;
        }
        if (n >= cap) return 0;
        text[n++] = b43_chars[rest];
        while (start < len && num[start] == 0) start++;
    }
    if (n + zeros > cap) return 0;
    for (uint32_t i = 0; i < zeros; i++) text[n++] = '0';
    for (uint32_t i = 0; i < n / 2; i++) {      // Written backwards
        char c = text[i];
        text[i] = text[n - 1 - i];
        text[n - 1 - i] = c;
    }
    return n;
}

uint32_t kef_base43_decode(const char *text, uint32_t len, uint8_t *data, uint32_t cap) {
    uint32_t zeros = 0, n = 0;

    if (len == 0) return 0;
    while (zeros < len && text[zeros] == '0') zeros++;
    for (uint32_t k = zeros; k < len; k++) {    // data holds the number, least significant first
        const char *p = (text[k] != '\0') ? strchr(b43_chars, text[k]) : NULL;
        if (p == NULL) return 0;
        uint32_t carry = (uint32_t)(p - b43_chars);
        for (uint32_t i = 0; i < n; i++) {
            uint32_t v = data[i] * 43u + carry;
            data[i] = (uint8_t)v;
            carry = v >> 8;
        }
        while (carry != 0) {
            if (n >= cap) return 0;
            data[n++] = (uint8_t)carry;
            carry >>= 8;
        }
    }
    if (n + zeros > cap) return 0;
    for (uint32_t i = 0; i < zeros; i++) data[n++] = 0;
    for (uint32_t i = 0; i < n / 2; i++) {
        uint8_t c = data[i];
        data[i] = data[n - 1 - i];
        data[n - 1 - i] = c;
    }
    return n;
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------
kef_status_t kef_unwrap(const uint8_t *data, uint32_t len, kef_envelope_t *env) {
    if (len < 1) return KEF_ERR_FORMAT;
    uint32_t id_len = data[0];
    if (id_len > KEF_ID_MAX || len < id_len + 5u) return KEF_ERR_FORMAT;

    env->id = &data[1];
    env->id_len = (uint8_t)id_len;
    env->version = data[1 + id_len];
    if (env->version != KEF_V_GCM && env->version != KEF_V_CTR) return KEF_ERR_VERSION;

    uint32_t stored = ((uint32_t)data[2 + id_len] << 16) | ((uint32_t)data[3 + id_len] << 8) | data[4 + id_len];
    env->iterations = (stored <= KEF_ITER_MIN) ? stored * KEF_ITER_MIN : stored;
    if (env->iterations < KEF_ITER_MIN) return KEF_ERR_ITERATIONS;

    env->payload = &data[5 + id_len];
    env->payload_len = len - (5u + id_len);
    uint32_t extra = KEF_IV_LEN + ((env->version == KEF_V_GCM) ? KEF_TAG_LEN : KEF_AUTH_LEN);
    if (env->payload_len <= extra) return KEF_ERR_FORMAT;
    return KEF_OK;
}

// ---------------------------------------------------------------------------
// PBKDF2-HMAC-SHA256. The states after the two key blocks are computed once:
// two SHA-256 compressions per iteration instead of four.
// ---------------------------------------------------------------------------
bool kef_derive_key(const uint8_t *secret, uint32_t secret_len, const uint8_t *id, uint32_t id_len,
                    uint32_t iterations, uint8_t key[KEF_KEY_SIZE], kef_progress_t progress) {
    uint8_t pad[SHA256_BLOCK], hashed[SHA256_BLOCK_SIZE], u[SHA256_BLOCK_SIZE], be_one[4] = {0, 0, 0, 1};
    SHA256_CTX inner, outer, ctx;
    bool ok = true;

    if (secret_len > SHA256_BLOCK) {
        sha256_init(&ctx);
        sha256_update(&ctx, secret, secret_len);
        sha256_final(&ctx, hashed);
        secret = hashed;
        secret_len = SHA256_BLOCK_SIZE;
    }
    memset(pad, 0x36, sizeof(pad));
    for (uint32_t i = 0; i < secret_len; i++) pad[i] ^= secret[i];
    sha256_init(&inner);
    sha256_update(&inner, pad, sizeof(pad));
    for (uint32_t i = 0; i < sizeof(pad); i++) pad[i] ^= 0x36 ^ 0x5C;
    sha256_init(&outer);
    sha256_update(&outer, pad, sizeof(pad));

    // U1 = HMAC(salt || 00000001)
    ctx = inner;
    sha256_update(&ctx, id, id_len);
    sha256_update(&ctx, be_one, sizeof(be_one));
    sha256_final(&ctx, u);
    ctx = outer;
    sha256_update(&ctx, u, sizeof(u));
    sha256_final(&ctx, u);
    memcpy(key, u, KEF_KEY_SIZE);

    for (uint32_t n = 1; n < iterations; n++) {
        ctx = inner;
        sha256_update(&ctx, u, sizeof(u));
        sha256_final(&ctx, u);
        ctx = outer;
        sha256_update(&ctx, u, sizeof(u));
        sha256_final(&ctx, u);
        for (uint32_t i = 0; i < KEF_KEY_SIZE; i++) key[i] ^= u[i];
        if (progress != NULL && (n % KEF_PROGRESS_EVERY) == 0 && !progress(n, iterations)) {
            ok = false;
            break;
        }
    }
    if (!ok) memzero(key, KEF_KEY_SIZE);
    memzero(pad, sizeof(pad));
    memzero(hashed, sizeof(hashed));
    memzero(u, sizeof(u));
    memzero(&inner, sizeof(inner));
    memzero(&outer, sizeof(outer));
    memzero(&ctx, sizeof(ctx));
    return ok;
}

// ---------------------------------------------------------------------------
// Sealing and opening
// ---------------------------------------------------------------------------
kef_status_t kef_seal_v20(const uint8_t key[KEF_KEY_SIZE], const uint8_t *id, uint32_t id_len,
                          uint32_t iterations, const uint8_t iv[KEF_IV_LEN],
                          const uint8_t *plain, uint32_t plain_len,
                          uint8_t *out, uint32_t cap, uint32_t *out_len) {
    uint32_t stored;
    gcm_ctx ctx;
    bool ok;

    if (id_len > KEF_ID_MAX || (plain_len != 16 && plain_len != 32)) return KEF_ERR_SIZE;
    uint32_t total = 1u + id_len + 4u + KEF_IV_LEN + plain_len + KEF_TAG_LEN;
    if (total > cap) return KEF_ERR_SIZE;

    // A multiple of 10,000 is stored divided; anything else must be over 10,000
    if (iterations % KEF_ITER_MIN == 0) {
        stored = iterations / KEF_ITER_MIN;
        if (stored < 1u || stored > KEF_ITER_MIN) return KEF_ERR_ITERATIONS;
    } else {
        stored = iterations;
        if (stored <= KEF_ITER_MIN || stored >= (1u << 24)) return KEF_ERR_ITERATIONS;
    }

    uint32_t p = 0;
    out[p++] = (uint8_t)id_len;
    memcpy(&out[p], id, id_len);
    p += id_len;
    out[p++] = KEF_V_GCM;
    out[p++] = (uint8_t)(stored >> 16);
    out[p++] = (uint8_t)(stored >> 8);
    out[p++] = (uint8_t)stored;
    memcpy(&out[p], iv, KEF_IV_LEN);
    p += KEF_IV_LEN;
    memcpy(&out[p], plain, plain_len);

    ok = gcm_init_and_key(key, KEF_KEY_SIZE, &ctx) == RETURN_GOOD &&
         gcm_encrypt_message(iv, KEF_IV_LEN, NULL, 0, &out[p], plain_len,
                             &out[p + plain_len], KEF_TAG_LEN, &ctx) == RETURN_GOOD;
    gcm_end(&ctx);
    memzero(&ctx, sizeof(ctx));
    if (!ok) {
        memzero(out, total);
        return KEF_ERR_AUTH;
    }
    *out_len = total;
    return KEF_OK;
}

// AES-CTR with a 12 byte nonce and a 4 byte big endian counter from 0, as
// Krux's MODE_CTR. In place.
static bool ctr_crypt(const uint8_t key[KEF_KEY_SIZE], const uint8_t nonce[KEF_IV_LEN], uint8_t *data, uint32_t len) {
    aes_encrypt_ctx aes;
    uint8_t block[16], stream[16];
    bool ok = aes_encrypt_key256(key, &aes) == EXIT_SUCCESS;

    memcpy(block, nonce, KEF_IV_LEN);
    for (uint32_t i = 0; ok && i < len; i++) {
        if ((i % 16u) == 0) {
            uint32_t counter = i / 16u;
            block[12] = (uint8_t)(counter >> 24);
            block[13] = (uint8_t)(counter >> 16);
            block[14] = (uint8_t)(counter >> 8);
            block[15] = (uint8_t)counter;
            ok = aes_encrypt(block, stream, &aes) == EXIT_SUCCESS;
        }
        data[i] ^= stream[i % 16u];
    }
    memzero(&aes, sizeof(aes));
    memzero(stream, sizeof(stream));
    return ok;
}

kef_status_t kef_open(const uint8_t key[KEF_KEY_SIZE], const kef_envelope_t *env,
                      uint8_t *plain, uint32_t *plain_len) {
    const uint8_t *iv = env->payload;
    const uint8_t *body = iv + KEF_IV_LEN;
    bool ok;
    uint32_t n;

    if (env->version == KEF_V_GCM) {
        gcm_ctx ctx;
        if (env->payload_len <= KEF_IV_LEN + KEF_TAG_LEN) return KEF_ERR_SIZE;
        n = env->payload_len - KEF_IV_LEN - KEF_TAG_LEN;
        if (n > KEF_PLAIN_MAX) return KEF_ERR_SIZE;
        memcpy(plain, body, n);
        ok = gcm_init_and_key(key, KEF_KEY_SIZE, &ctx) == RETURN_GOOD &&
             gcm_decrypt_message(iv, KEF_IV_LEN, NULL, 0, plain, n, body + n, KEF_TAG_LEN, &ctx) == RETURN_GOOD;
        gcm_end(&ctx);
        memzero(&ctx, sizeof(ctx));
    } else if (env->version == KEF_V_CTR) {
        uint8_t buf[KEF_PLAIN_MAX + KEF_AUTH_LEN];
        uint8_t digest[SHA256_BLOCK_SIZE];
        SHA256_CTX sha;
        if (env->payload_len <= KEF_IV_LEN + KEF_AUTH_LEN) return KEF_ERR_SIZE;
        uint32_t total = env->payload_len - KEF_IV_LEN;
        if (total > sizeof(buf)) return KEF_ERR_SIZE;
        n = total - KEF_AUTH_LEN;
        memcpy(buf, body, total);
        ok = ctr_crypt(key, iv, buf, total);
        sha256_init(&sha);
        sha256_update(&sha, buf, n);
        sha256_final(&sha, digest);
        ok = ok && consteq(digest, &buf[n], KEF_AUTH_LEN);
        memcpy(plain, buf, n);
        memzero(buf, sizeof(buf));
        memzero(digest, sizeof(digest));
        memzero(&sha, sizeof(sha));
    } else {
        return KEF_ERR_AUTH;
    }
    if (!ok) {
        memzero(plain, KEF_PLAIN_MAX);
        return KEF_ERR_AUTH;
    }
    *plain_len = n;
    return KEF_OK;
}
