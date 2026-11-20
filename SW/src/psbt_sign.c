/*******************************************************************************
 * Project:     SeedMate
 * File:        psbt_sign.c
 *
 * Summary:
 *   BIP143 sighash, previous-tx check and RFC6979 ECDSA; BIP341 sighash, BIP86
 *   output key and BIP340 Schnorr for Taproot. See psbt_sign.h.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include <string.h>
#include "psbt_sign.h"
#include "sha256.h"
#include "crypto/bignum.h"
#include "crypto/ecdsa.h"
#include "crypto/secp256k1.h"
#include "crypto/memzero.h"
#include "kdf.h"

// Not exported by the trimmed ecdsa.h, but defined in crypto/ecdsa.c
int scalar_multiply(const ecdsa_curve *curve, const bignum256 *k, curve_point *res);
int point_multiply(const ecdsa_curve *curve, const bignum256 *k, const curve_point *p, curve_point *res);
void point_add(const ecdsa_curve *curve, const curve_point *cp1, curve_point *cp2);
int point_is_infinity(const curve_point *p);
void point_set_infinity(curve_point *p);

// ============================================================================
// Hash helpers
// ============================================================================

static void le32_write(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

// Second SHA-256 round of a double hash, in place
static void sha256_again(uint8_t hash[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, hash, 32);
    sha256_final(&ctx, hash);
}

static void hmac_sha256(const uint8_t key[32], const uint8_t *msg1, uint32_t len1,
                        const uint8_t *msg2, uint32_t len2, uint8_t out[32]) {
    uint8_t pad[64];
    SHA256_CTX ctx;

    memset(pad, 0x36, sizeof(pad));
    for (int i = 0; i < 32; i++) pad[i] ^= key[i];
    sha256_init(&ctx);
    sha256_update(&ctx, pad, 64);
    sha256_update(&ctx, msg1, len1);
    if (len2 > 0) sha256_update(&ctx, msg2, len2);
    sha256_final(&ctx, out);

    for (int i = 0; i < 64; i++) pad[i] ^= 0x36 ^ 0x5C;
    sha256_init(&ctx);
    sha256_update(&ctx, pad, 64);
    sha256_update(&ctx, out, 32);
    sha256_final(&ctx, out);
    memzero(pad, sizeof(pad));
}

// ============================================================================
// BIP143
// ============================================================================

bool psbt_sighash_segwit_v0(const psbt_t *psbt, uint32_t index, const uint8_t *script_code,
                            uint32_t script_code_len, uint64_t amount, uint32_t sighash_type,
                            uint8_t digest[32]) {
    uint8_t hash_prevouts[32], hash_sequence[32], hash_outputs[32];
    uint8_t buf[8];
    psbt_input_t in, signed_in;
    SHA256_CTX ctx;
    const uint8_t *outputs;
    uint32_t outputs_len;

    if (sighash_type != PSBT_SIGHASH_ALL) return false;   // Only SIGHASH_ALL is supported
    if (script_code == NULL || script_code_len == 0 || script_code_len > 0xFFFF) return false;
    if (!psbt_get_input(psbt, index, &signed_in) || !psbt_tx_outputs(psbt, &outputs, &outputs_len)) return false;

    // hashPrevouts and hashSequence over all inputs
    SHA256_CTX ctx_seq;
    sha256_init(&ctx);
    sha256_init(&ctx_seq);
    for (uint32_t i = 0; i < psbt->input_count; i++) {
        if (!psbt_get_input(psbt, i, &in)) return false;
        sha256_update(&ctx, in.prev_txid, 36);            // txid + vout are contiguous
        le32_write(buf, in.sequence);
        sha256_update(&ctx_seq, buf, 4);
    }
    sha256_final(&ctx, hash_prevouts);
    sha256_again(hash_prevouts);
    sha256_final(&ctx_seq, hash_sequence);
    sha256_again(hash_sequence);

    sha256_init(&ctx);
    sha256_update(&ctx, outputs, outputs_len);
    sha256_final(&ctx, hash_outputs);
    sha256_again(hash_outputs);

    // Preimage; scriptCode is serialized with its CompactSize length
    sha256_init(&ctx);
    le32_write(buf, psbt->tx_version);
    sha256_update(&ctx, buf, 4);
    sha256_update(&ctx, hash_prevouts, 32);
    sha256_update(&ctx, hash_sequence, 32);
    sha256_update(&ctx, signed_in.prev_txid, 36);
    if (script_code_len < 0xFD) {
        buf[0] = (uint8_t)script_code_len;
        sha256_update(&ctx, buf, 1);
    } else {
        buf[0] = 0xFD;
        buf[1] = (uint8_t)script_code_len;
        buf[2] = (uint8_t)(script_code_len >> 8);
        sha256_update(&ctx, buf, 3);
    }
    sha256_update(&ctx, script_code, script_code_len);
    le32_write(buf, (uint32_t)amount);
    le32_write(&buf[4], (uint32_t)(amount >> 32));
    sha256_update(&ctx, buf, 8);
    le32_write(buf, signed_in.sequence);
    sha256_update(&ctx, buf, 4);
    sha256_update(&ctx, hash_outputs, 32);
    le32_write(buf, psbt->locktime);
    sha256_update(&ctx, buf, 4);
    le32_write(buf, sighash_type);
    sha256_update(&ctx, buf, 4);
    sha256_final(&ctx, digest);
    sha256_again(digest);
    return true;
}

// CompactSize of n into the hash
static void sha256_varint(SHA256_CTX *ctx, uint32_t n) {
    uint8_t b[5];
    uint32_t len = 1;
    if (n < 0xFD) {
        b[0] = (uint8_t)n;
    } else if (n <= 0xFFFF) {
        b[0] = 0xFD;
        b[1] = (uint8_t)n;
        b[2] = (uint8_t)(n >> 8);
        len = 3;
    } else {
        b[0] = 0xFE;
        le32_write(&b[1], n);
        len = 5;
    }
    sha256_update(ctx, b, len);
}

bool psbt_sighash_legacy(const psbt_t *psbt, uint32_t index, const uint8_t *script_code,
                         uint32_t script_code_len, uint32_t sighash_type, uint8_t digest[32]) {
    uint8_t buf[4];
    psbt_input_t in;
    SHA256_CTX ctx;
    const uint8_t *outputs;
    uint32_t outputs_len;

    if (sighash_type != PSBT_SIGHASH_ALL) return false;   // Only SIGHASH_ALL is supported
    if (script_code == NULL || script_code_len == 0 || script_code_len > 0xFFFF) return false;
    if (index >= psbt->input_count || !psbt_tx_outputs(psbt, &outputs, &outputs_len)) return false;

    sha256_init(&ctx);
    le32_write(buf, psbt->tx_version);
    sha256_update(&ctx, buf, 4);
    sha256_varint(&ctx, psbt->input_count);
    for (uint32_t i = 0; i < psbt->input_count; i++) {
        if (!psbt_get_input(psbt, i, &in)) return false;
        sha256_update(&ctx, in.prev_txid, 36);            // txid + vout are contiguous
        if (i == index) {
            sha256_varint(&ctx, script_code_len);
            sha256_update(&ctx, script_code, script_code_len);
        } else {
            sha256_varint(&ctx, 0);                       // Other inputs: empty scriptSig
        }
        le32_write(buf, in.sequence);
        sha256_update(&ctx, buf, 4);
    }
    sha256_varint(&ctx, psbt->output_count);
    sha256_update(&ctx, outputs, outputs_len);
    le32_write(buf, psbt->locktime);
    sha256_update(&ctx, buf, 4);
    le32_write(buf, sighash_type);
    sha256_update(&ctx, buf, 4);
    sha256_final(&ctx, digest);
    sha256_again(digest);
    return true;
}

bool psbt_sighash_p2wpkh(const psbt_t *psbt, uint32_t index, const uint8_t *pkh,
                         uint64_t amount, uint32_t sighash_type, uint8_t digest[32]) {
    // scriptCode of P2WPKH: OP_DUP OP_HASH160 <pkh> OP_EQUALVERIFY OP_CHECKSIG
    uint8_t script_code[25] = {0x76, 0xA9, 0x14};
    memcpy(&script_code[3], pkh, 20);
    script_code[23] = 0x88;
    script_code[24] = 0xAC;
    return psbt_sighash_segwit_v0(psbt, index, script_code, sizeof(script_code), amount, sighash_type, digest);
}

bool psbt_p2wsh_matches(const uint8_t *script, uint32_t script_len,
                        const uint8_t *witness_script, uint32_t witness_script_len) {
    uint8_t hash[32];
    SHA256_CTX ctx;

    if (psbt_script_type(script, script_len) != PSBT_SCRIPT_P2WSH || witness_script == NULL) return false;
    sha256_init(&ctx);
    sha256_update(&ctx, witness_script, witness_script_len);
    sha256_final(&ctx, hash);
    return memcmp(hash, &script[2], 32) == 0;
}

bool psbt_prev_tx_matches(const psbt_input_t *in) {
    uint32_t body_ofs, body_len;
    uint8_t txid[32];
    SHA256_CTX ctx;

    if (in->prev_tx == NULL || in->prev_tx_len < 10) return false;
    if (!psbt_tx_txid_body(in->prev_tx, in->prev_tx_len, &body_ofs, &body_len)) return false;

    // txid = SHA256d of the legacy serialization (no SegWit marker or witnesses)
    sha256_init(&ctx);
    sha256_update(&ctx, in->prev_tx, 4);
    sha256_update(&ctx, &in->prev_tx[body_ofs], body_len);
    sha256_update(&ctx, &in->prev_tx[in->prev_tx_len - 4], 4);
    sha256_final(&ctx, txid);
    sha256_again(txid);
    return memcmp(txid, in->prev_txid, 32) == 0;
}

// ============================================================================
// ECDSA (RFC6979 nonces, low S)
// ============================================================================

// DER INTEGER of a 32-byte big-endian value; returns bytes written
static uint32_t der_integer(const uint8_t v[32], uint8_t *out) {
    uint32_t skip = 0;
    while (skip < 31 && v[skip] == 0) skip++;
    uint32_t len = 32 - skip;
    bool pad = (v[skip] & 0x80) != 0;
    out[0] = 0x02;
    out[1] = (uint8_t)(len + pad);
    if (pad) out[2] = 0x00;
    memcpy(&out[2 + pad], &v[skip], len);
    return 2 + pad + len;
}

// RFC6979 3.2 b-g with HMAC-SHA256, seeded as libsecp256k1 does:
// key || (digest mod n) || optional 32 bytes of extra entropy
static void rfc6979_init(uint8_t K[32], uint8_t V[32], const uint8_t priv_key[32],
                         const uint8_t h1[32], const uint8_t *extra) {
    uint8_t data[32 + 1 + 32 + 32 + 32];
    uint32_t len = extra ? sizeof(data) : sizeof(data) - 32;

    memset(V, 0x01, 32);
    memset(K, 0x00, 32);
    memcpy(&data[0], V, 32);
    data[32] = 0x00;
    memcpy(&data[33], priv_key, 32);
    memcpy(&data[65], h1, 32);
    if (extra) memcpy(&data[97], extra, 32);
    hmac_sha256(K, data, len, NULL, 0, K);
    hmac_sha256(K, V, 32, NULL, 0, V);
    memcpy(&data[0], V, 32);
    data[32] = 0x01;
    hmac_sha256(K, data, len, NULL, 0, K);
    hmac_sha256(K, V, 32, NULL, 0, V);
    memzero(data, sizeof(data));
}

// One RFC6979 signature (low S). Returns false only if no valid nonce came out.
static bool ecdsa_sign_rfc6979(const ecdsa_curve *curve, const uint8_t priv_key[32], const bignum256 *z,
                               const uint8_t h1[32], const uint8_t *extra, bignum256 *r, bignum256 *s) {
    uint8_t K[32], V[32];
    bignum256 k;
    curve_point R;
    bool ok = false;

    rfc6979_init(K, V, priv_key, h1, extra);
    for (int attempt = 0; attempt < 16 && !ok; attempt++) {
        if (attempt > 0) {                          // Next candidate (RFC6979 3.2 h.3)
            static const uint8_t zero = 0x00;
            hmac_sha256(K, V, 32, &zero, 1, K);
            hmac_sha256(K, V, 32, NULL, 0, V);
        }
        hmac_sha256(K, V, 32, NULL, 0, V);
        bn_read_be(V, &k);
        if (bn_is_zero(&k) || !bn_is_less(&k, &curve->order)) continue;

        // r = (k * G).x mod n
        scalar_multiply(curve, &k, &R);
        bn_mod(&R.x, &curve->order);
        if (bn_is_zero(&R.x)) continue;

        // s = k^-1 * (z + r * d) mod n
        bn_read_be(priv_key, s);
        bn_inverse(&k, &curve->order);
        bn_multiply(&R.x, s, &curve->order);
        bn_add(s, z);
        bn_multiply(&k, s, &curve->order);
        bn_mod(s, &curve->order);
        if (bn_is_zero(s)) continue;

        if (bn_is_less(&curve->order_half, s)) {    // Low S (BIP146)
            bn_subtract(&curve->order, s, s);
        }
        *r = R.x;
        ok = true;
    }
    memzero(K, sizeof(K));
    memzero(V, sizeof(V));
    memzero(&k, sizeof(k));
    return ok;
}

// ECDSA verification with the same steps as trezor-crypto's
// ecdsa_verify_digest(): R' = (z/s) * G + (r/s) * Q, valid if R'.x mod n == r.
// r, s and z are already reduced mod n.
// A compressed public key only: after a 0x04 prefix ecdsa_read_pubkey() reads
// 65 bytes, past these 33 byte buffers (audit IND-H5)
static int read_pub33(const ecdsa_curve *curve, const uint8_t pub[33], curve_point *p) {
    if (pub[0] != 0x02 && pub[0] != 0x03) return 0;
    return ecdsa_read_pubkey(curve, pub, p);
}

static bool ecdsa_verify(const ecdsa_curve *curve, const uint8_t pub_key[33],
                         const bignum256 *r, const bignum256 *s, const bignum256 *z) {
    curve_point pub, res;
    bignum256 u1 = *z, u2 = *s;

    if (!read_pub33(curve, pub_key, &pub)) return false;
    if (bn_is_zero(r) || bn_is_zero(s) || !bn_is_less(r, &curve->order) || !bn_is_less(s, &curve->order)) return false;

    bn_inverse(&u2, &curve->order);         // u2 = s^-1
    bn_multiply(&u2, &u1, &curve->order);   // u1 = z / s
    bn_mod(&u1, &curve->order);
    bignum256 rr = *r;
    bn_multiply(&u2, &rr, &curve->order);   // rr = r / s
    bn_mod(&rr, &curve->order);
    if (bn_is_zero(&u1)) return false;      // Digest is zero mod n: never signed

    scalar_multiply(curve, &u1, &res);
    if (point_multiply(curve, &rr, &pub, &pub) != 0) return false;
    point_add(curve, &pub, &res);           // Handles points at infinity
    bn_mod(&res.x, &curve->order);
    return bn_is_equal(&res.x, r) != 0;
}

bool psbt_ecdsa_sign(const uint8_t priv_key[32], const uint8_t pub_key[33], const uint8_t digest[32],
                     uint8_t sighash_type, uint8_t *sig, uint32_t *sig_len, void (*on_verify)(void)) {
    const ecdsa_curve *curve = &secp256k1;
    uint8_t h1[32], extra[32], r_be[32], s_be[32];
    bignum256 z, r, s;
    bool ok = false;

    bn_read_be(priv_key, &s);
    if (bn_is_zero(&s) || !bn_is_less(&s, &curve->order)) return false;

    // z = digest mod n, also the RFC6979 bits2octets(h1)
    bn_read_be(digest, &z);
    bn_mod(&z, &curve->order);
    bn_write_be(&z, h1);

    // Low R grinding as Bitcoin Core, libsecp256k1 and embit do: retry with a
    // little-endian counter as extra entropy until R has its top bit clear
    memset(extra, 0, sizeof(extra));
    for (uint32_t counter = 0; counter < 256 && !ok; counter++) {
        extra[0] = (uint8_t)counter;
        if (!ecdsa_sign_rfc6979(curve, priv_key, &z, h1, counter ? extra : NULL, &r, &s)) break;
        bn_write_be(&r, r_be);
        ok = (r_be[0] & 0x80) == 0;
    }

    // Check the result with the public key before releasing it: a glitched
    // computation could otherwise produce a signature that leaks the key
    if (ok && on_verify != NULL) on_verify();
    ok = ok && ecdsa_verify(curve, pub_key, &r, &s, &z);

    if (ok) {
        bn_write_be(&s, s_be);
        uint32_t len = der_integer(r_be, &sig[2]);
        len += der_integer(s_be, &sig[2 + len]);
        sig[0] = 0x30;
        sig[1] = (uint8_t)len;
        sig[2 + len] = sighash_type;
        *sig_len = 3 + len;
    }
    memzero(&s, sizeof(s));
    return ok;
}

// ============================================================================
// Taproot: BIP341 signature hash, BIP86 output key, BIP340 Schnorr
// ============================================================================

// SHA256(SHA256(tag) || SHA256(tag) || ...): the BIP340 tagged hash, ready
// for the data
static void tagged_init(SHA256_CTX *ctx, const char *tag) {
    uint8_t t[32];
    sha256_init(ctx);
    sha256_update(ctx, (const BYTE *)tag, strlen(tag));
    sha256_final(ctx, t);
    sha256_init(ctx);
    sha256_update(ctx, t, 32);
    sha256_update(ctx, t, 32);
}

// CompactSize length of a script, as hashed in sha_scriptpubkeys
static void sha256_script(SHA256_CTX *ctx, const uint8_t *script, uint32_t len) {
    uint8_t n[3];
    if (len < 0xFD) {
        n[0] = (uint8_t)len;
        sha256_update(ctx, n, 1);
    } else {
        n[0] = 0xFD;
        n[1] = (uint8_t)len;
        n[2] = (uint8_t)(len >> 8);
        sha256_update(ctx, n, 3);
    }
    sha256_update(ctx, script, len);
}

bool psbt_sighash_taproot(const psbt_t *psbt, uint32_t index, uint8_t hash_type, uint8_t digest[32]) {
    uint8_t sha[5][32];                     // prevouts, amounts, scriptpubkeys, sequences, outputs
    uint8_t buf[8];
    psbt_input_t in;
    SHA256_CTX ctx;
    const uint8_t *outputs;
    uint32_t outputs_len;

    if (hash_type != PSBT_SIGHASH_DEFAULT && hash_type != PSBT_SIGHASH_ALL) return false;
    if (index >= psbt->input_count || !psbt_tx_outputs(psbt, &outputs, &outputs_len)) return false;

    // One pass over the inputs per hash: every input's amount and script are signed
    for (int h = 0; h < 4; h++) {
        sha256_init(&ctx);
        for (uint32_t i = 0; i < psbt->input_count; i++) {
            if (!psbt_get_input(psbt, i, &in) || !in.has_amount || in.script == NULL ||
                in.script_len > 0xFFFF) return false;
            if (h == 0) {
                sha256_update(&ctx, in.prev_txid, 36);    // txid + vout are contiguous
            } else if (h == 1) {
                le32_write(buf, (uint32_t)in.amount);
                le32_write(&buf[4], (uint32_t)(in.amount >> 32));
                sha256_update(&ctx, buf, 8);
            } else if (h == 2) {
                sha256_script(&ctx, in.script, in.script_len);
            } else {
                le32_write(buf, in.sequence);
                sha256_update(&ctx, buf, 4);
            }
        }
        sha256_final(&ctx, sha[h]);
    }
    sha256_init(&ctx);                      // The outputs, without their count
    sha256_update(&ctx, outputs, outputs_len);
    sha256_final(&ctx, sha[4]);

    // Epoch 0, hash type, version, locktime, the five hashes, spend type 0
    // (key path, no annex), input index
    tagged_init(&ctx, "TapSighash");
    buf[0] = 0x00;
    buf[1] = hash_type;
    sha256_update(&ctx, buf, 2);
    le32_write(buf, psbt->tx_version);
    le32_write(&buf[4], psbt->locktime);
    sha256_update(&ctx, buf, 8);
    sha256_update(&ctx, &sha[0][0], sizeof(sha));
    buf[0] = 0x00;
    le32_write(&buf[1], index);
    sha256_update(&ctx, buf, 5);
    sha256_final(&ctx, digest);
    return true;
}

// y = p - y: the same point with the other y (the "negation")
static void point_negate_y(const ecdsa_curve *curve, curve_point *pt) {
    bn_subtract(&curve->prime, &pt->y, &pt->y);
}

// Tagged hash of up to three 32 byte parts, as a scalar mod n (BIP340 e and k)
static void tagged_scalar(const char *tag, const uint8_t *a, const uint8_t *b, const uint8_t *c,
                          bignum256 *out) {
    uint8_t h[32];
    SHA256_CTX ctx;
    tagged_init(&ctx, tag);
    sha256_update(&ctx, a, 32);
    if (b != NULL) sha256_update(&ctx, b, 32);
    if (c != NULL) sha256_update(&ctx, c, 32);
    sha256_final(&ctx, h);
    bn_read_be(h, out);
    bn_mod(out, &secp256k1.order);
    memzero(h, sizeof(h));
}

// BIP86 output key point Q = P + t*G, P the even-y point of the internal key
// (given compressed) and t = hash_TapTweak(x(P)). t is returned too.
static bool taproot_output_point(const uint8_t pub33[33], bignum256 *t, curve_point *q) {
    const ecdsa_curve *curve = &secp256k1;
    uint8_t h[32];
    curve_point p;
    SHA256_CTX ctx;

    if (!read_pub33(curve, pub33, &p)) return false;
    if (p.y.val[0] & 1) point_negate_y(curve, &p);
    tagged_init(&ctx, "TapTweak");
    sha256_update(&ctx, &pub33[1], 32);
    sha256_final(&ctx, h);
    bn_read_be(h, t);
    if (!bn_is_less(t, &curve->order)) return false;    // Never for a real key (p < 2^-127)
    scalar_multiply(curve, t, q);
    point_add(curve, &p, q);
    return !point_is_infinity(q);
}

bool psbt_taproot_output_key(const uint8_t pub33[33], uint8_t q_x[32]) {
    bignum256 t;
    curve_point q;
    if (!taproot_output_point(pub33, &t, &q)) return false;
    bn_write_be(&q.x, q_x);
    return true;
}

// BIP340 verification against the even-y point p with x bytes px:
// R = s*G - e*P must have even y and x(R) = r
static bool bip340_verify_point(const curve_point *p, const uint8_t px[32], const uint8_t msg[32],
                                const uint8_t sig[64]) {
    const ecdsa_curve *curve = &secp256k1;
    bignum256 r, s, e;
    curve_point sg, ep;

    bn_read_be(sig, &r);
    bn_read_be(&sig[32], &s);
    if (!bn_is_less(&r, &curve->prime) || !bn_is_less(&s, &curve->order)) return false;
    tagged_scalar("BIP0340/challenge", sig, px, msg, &e);
    scalar_multiply(curve, &s, &sg);
    if (bn_is_zero(&e)) {
        point_set_infinity(&ep);
    } else if (point_multiply(curve, &e, p, &ep) != 0) {
        return false;
    } else {
        point_negate_y(curve, &ep);
    }
    point_add(curve, &ep, &sg);             // s*G - e*P (handles infinity)
    return !point_is_infinity(&sg) && (sg.y.val[0] & 1) == 0 && bn_is_equal(&sg.x, &r);
}

bool psbt_bip340_verify(const uint8_t px[32], const uint8_t msg[32], const uint8_t sig[64]) {
    uint8_t pub33[33];
    curve_point p;
    pub33[0] = 0x02;                        // lift_x: the even y
    memcpy(&pub33[1], px, 32);
    if (!ecdsa_read_pubkey(&secp256k1, pub33, &p)) return false;
    return bip340_verify_point(&p, px, msg, sig);
}

// BIP340 signing with secret d, already negated so that d*G has even y, and
// px = x(d*G). sig = R || s.
static bool bip340_sign_even(bignum256 *d, const uint8_t px[32], const uint8_t msg[32],
                             const uint8_t aux[32], uint8_t sig[64]) {
    const ecdsa_curve *curve = &secp256k1;
    uint8_t t[32], dbytes[32];
    bignum256 k, e;
    curve_point r;
    SHA256_CTX ctx;
    bool ok = false;

    // t = bytes(d) xor hash_aux(aux); k = hash_nonce(t || px || msg) mod n
    tagged_init(&ctx, "BIP0340/aux");
    sha256_update(&ctx, aux, 32);
    sha256_final(&ctx, t);
    bn_write_be(d, dbytes);
    for (int i = 0; i < 32; i++) t[i] ^= dbytes[i];
    tagged_scalar("BIP0340/nonce", t, px, msg, &k);
    if (!bn_is_zero(&k)) {
        scalar_multiply(curve, &k, &r);
        if (r.y.val[0] & 1) bn_subtract(&curve->order, &k, &k);
        bn_write_be(&r.x, sig);
        // s = k + e*d mod n
        tagged_scalar("BIP0340/challenge", sig, px, msg, &e);
        bn_multiply(d, &e, &curve->order);
        bn_mod(&e, &curve->order);
        bn_addmod(&e, &k, &curve->order);
        bn_mod(&e, &curve->order);
        bn_write_be(&e, &sig[32]);
        ok = true;
    }
    memzero(t, sizeof(t));
    memzero(dbytes, sizeof(dbytes));
    memzero(&k, sizeof(k));
    memzero(&e, sizeof(e));
    return ok;
}

bool psbt_bip340_sign(const uint8_t seckey[32], const uint8_t msg[32], const uint8_t aux[32], uint8_t sig[64]) {
    const ecdsa_curve *curve = &secp256k1;
    uint8_t px[32];
    bignum256 d;
    curve_point p;
    bool ok;

    bn_read_be(seckey, &d);
    if (bn_is_zero(&d) || !bn_is_less(&d, &curve->order)) return false;
    scalar_multiply(curve, &d, &p);
    if (p.y.val[0] & 1) {
        bn_subtract(&curve->order, &d, &d);
        point_negate_y(curve, &p);
    }
    bn_write_be(&p.x, px);
    ok = bip340_sign_even(&d, px, msg, aux, sig) && bip340_verify_point(&p, px, msg, sig);
    memzero(&d, sizeof(d));
    return ok;
}

bool psbt_taproot_sign(const uint8_t priv_key[32], const uint8_t pub_key[33], const uint8_t digest[32],
                       uint8_t sig[64], void (*on_verify)(void)) {
    const ecdsa_curve *curve = &secp256k1;
    static const uint8_t zero_aux[32];      // Deterministic nonces (BIP340 allows it)
    uint8_t qx[32];
    bignum256 d, t;
    curve_point q;
    bool ok = false;

    bn_read_be(priv_key, &d);
    if (bn_is_zero(&d) || !bn_is_less(&d, &curve->order)) return false;

    // Q from the public key alone; the tweaked secret must give the same point
    if (taproot_output_point(pub_key, &t, &q)) {
        if (pub_key[0] == 0x03) bn_subtract(&curve->order, &d, &d);     // Even-y internal key
        bn_addmod(&d, &t, &curve->order);                               // d + t
        bn_mod(&d, &curve->order);
        ok = !bn_is_zero(&d);
    }
    if (ok) {
        if (q.y.val[0] & 1) {                                           // Even-y output key
            bn_subtract(&curve->order, &d, &d);
            point_negate_y(curve, &q);
        }
        bn_write_be(&q.x, qx);
        ok = bip340_sign_even(&d, qx, digest, zero_aux, sig);
    }
    memzero(&d, sizeof(d));

    // Checked with the output key before it is released (see psbt_ecdsa_sign)
    if (ok && on_verify != NULL) on_verify();
    return ok && bip340_verify_point(&q, qx, digest, sig);
}

// ============================================================================
// BIP32 public derivation
// ============================================================================

bool psbt_public_ckd(const uint8_t chain_code[32], const uint8_t public_key[33], uint32_t index,
                     uint8_t child_chain[32], uint8_t child_key[33]) {
    const ecdsa_curve *curve = &secp256k1;
    uint8_t data[37];
    uint8_t I[64];
    bignum256 il;
    curve_point parent, child;

    if (index & 0x80000000u) return false;
    if (!read_pub33(curve, public_key, &parent)) return false;

    // I = HMAC-SHA512(chain code, key || index); child = I_L * G + parent
    memcpy(data, public_key, 33);
    data[33] = (uint8_t)(index >> 24);
    data[34] = (uint8_t)(index >> 16);
    data[35] = (uint8_t)(index >> 8);
    data[36] = (uint8_t)index;
    HmacSha512(chain_code, 32, data, sizeof(data), I);

    bn_read_be(I, &il);
    if (!bn_is_less(&il, &curve->order)) return false;   // Next index per BIP32 (p < 2^-127)
    scalar_multiply(curve, &il, &child);
    point_add(curve, &parent, &child);
    if (point_is_infinity(&child)) return false;

    child_key[0] = (uint8_t)(0x02 | (child.y.val[0] & 1));
    bn_write_be(&child.x, &child_key[1]);
    memcpy(child_chain, &I[32], 32);
    return true;
}
