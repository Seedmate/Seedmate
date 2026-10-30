/*******************************************************************************
 * Project:     SeedMate
 * File:        ur_encode.c
 *
 * Summary:
 *   UR "crypto-psbt" encoder. See ur_encode.h.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include <string.h>
#include "ur_encode.h"
#include "bytewords.h"

#define UR_MIN_FRAGMENT 10u     // Same lower bound as the UR reference code

uint32_t ur_crc32_update(uint32_t crc, const uint8_t *data, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
    }
    return crc;
}

// Byte i of the message (CBOR header + PSBT); 0 past the end (padding)
static uint8_t msg_byte(const ur_encoder_t *e, uint32_t i) {
    if (i < e->hdr_len) return e->hdr[i];
    i -= e->hdr_len;
    return (i < e->psbt_len) ? e->psbt[i] : 0;
}

bool ur_encoder_init(ur_encoder_t *e, const uint8_t *psbt, uint32_t psbt_len, uint32_t max_fragment_len) {
    return ur_encoder_init_type(e, "CRYPTO-PSBT", psbt, psbt_len, true, max_fragment_len);
}

bool ur_encoder_init_type(ur_encoder_t *e, const char *type, const uint8_t *psbt, uint32_t psbt_len,
                          bool wrap_bstr, uint32_t max_fragment_len) {
    memset(e, 0, sizeof(*e));
    if (type == NULL || strlen(type) > 18) return false;
    if (psbt == NULL || psbt_len == 0 || psbt_len > 0xFFFF || max_fragment_len < UR_MIN_FRAGMENT) return false;
    e->type = type;

    // CBOR major type 2 (byte string) header
    if (!wrap_bstr) {
        e->hdr_len = 0;
    } else if (psbt_len < 24) {
        e->hdr[0] = (uint8_t)(0x40 | psbt_len);
        e->hdr_len = 1;
    } else if (psbt_len < 256) {
        e->hdr[0] = 0x58;
        e->hdr[1] = (uint8_t)psbt_len;
        e->hdr_len = 2;
    } else {
        e->hdr[0] = 0x59;
        e->hdr[1] = (uint8_t)(psbt_len >> 8);
        e->hdr[2] = (uint8_t)psbt_len;
        e->hdr_len = 3;
    }
    e->psbt = psbt;
    e->psbt_len = psbt_len;
    e->msg_len = e->hdr_len + psbt_len;

    uint32_t crc = ur_crc32_update(0xFFFFFFFFu, e->hdr, e->hdr_len);
    e->checksum = ur_crc32_update(crc, psbt, psbt_len) ^ 0xFFFFFFFFu;

    // Fewest parts whose equal size fits max_fragment_len
    uint32_t max_count = e->msg_len / UR_MIN_FRAGMENT;
    if (max_count == 0) max_count = 1;
    for (uint32_t count = 1; count <= max_count; count++) {
        e->fragment_len = (e->msg_len + count - 1) / count;
        if (e->fragment_len <= max_fragment_len) break;
    }
    e->seq_len = (e->msg_len + e->fragment_len - 1) / e->fragment_len;
    return true;
}

// Writes bytes as Bytewords while accumulating their CRC32
typedef struct {
    char *out;
    uint32_t pos;
    uint32_t size;
    uint32_t crc;
    bool overflow;
} emitter_t;

static void emit_text(emitter_t *em, const char *s, uint32_t len) {
    if (em->overflow || len > em->size - em->pos) {
        em->overflow = true;
        return;
    }
    memcpy(&em->out[em->pos], s, len);
    em->pos += len;
}

static void emit_number(emitter_t *em, uint32_t v) {
    char tmp[10];
    uint32_t n = 0;
    do {
        tmp[9 - n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v != 0);
    emit_text(em, &tmp[10 - n], n);
}

static void emit_byte(emitter_t *em, uint8_t b) {
    char pair[2];
    em->crc = ur_crc32_update(em->crc, &b, 1);
    encode_bytewords_pair(b, pair);
    emit_text(em, pair, 2);
}

// CBOR head: major type (high 3 bits of 'major') and an unsigned value
static void emit_cbor_head(emitter_t *em, uint8_t major, uint32_t v) {
    if (v < 24) {
        emit_byte(em, (uint8_t)(major | v));
    } else if (v < 0x100) {
        emit_byte(em, (uint8_t)(major | 24));
        emit_byte(em, (uint8_t)v);
    } else if (v < 0x10000) {
        emit_byte(em, (uint8_t)(major | 25));
        emit_byte(em, (uint8_t)(v >> 8));
        emit_byte(em, (uint8_t)v);
    } else {
        emit_byte(em, (uint8_t)(major | 26));
        emit_byte(em, (uint8_t)(v >> 24));
        emit_byte(em, (uint8_t)(v >> 16));
        emit_byte(em, (uint8_t)(v >> 8));
        emit_byte(em, (uint8_t)v);
    }
}

// Appends the final CRC32 (big-endian) without hashing it
static void emit_crc(emitter_t *em) {
    uint32_t crc = em->crc ^ 0xFFFFFFFFu;
    for (int shift = 24; shift >= 0; shift -= 8) {
        char pair[2];
        encode_bytewords_pair((uint8_t)(crc >> shift), pair);
        emit_text(em, pair, 2);
    }
}

uint32_t ur_encoder_part(const ur_encoder_t *e, uint32_t seq, char *out, uint32_t out_size) {
    if (seq == 0 || seq > e->seq_len || out_size == 0) return 0;

    emitter_t em = { out, 0, out_size - 1, 0xFFFFFFFFu, false };   // Keep room for NUL
    emit_text(&em, "UR:", 3);
    emit_text(&em, e->type, (uint32_t)strlen(e->type));
    emit_text(&em, "/", 1);

    if (e->seq_len == 1) {
        // Single part: the message itself
        for (uint32_t i = 0; i < e->msg_len; i++) emit_byte(&em, msg_byte(e, i));
    } else {
        emit_number(&em, seq);
        emit_text(&em, "-", 1);
        emit_number(&em, e->seq_len);
        emit_text(&em, "/", 1);

        em.crc = 0xFFFFFFFFu;   // The part CRC covers the CBOR only
        emit_cbor_head(&em, 0x80, 5);               // Array of 5
        emit_cbor_head(&em, 0x00, seq);
        emit_cbor_head(&em, 0x00, e->seq_len);
        emit_cbor_head(&em, 0x00, e->msg_len);
        emit_cbor_head(&em, 0x00, e->checksum);
        emit_cbor_head(&em, 0x40, e->fragment_len); // Byte string
        uint32_t start = (seq - 1) * e->fragment_len;
        for (uint32_t i = 0; i < e->fragment_len; i++) emit_byte(&em, msg_byte(e, start + i));
    }
    emit_crc(&em);

    if (em.overflow) return 0;
    out[em.pos] = '\0';
    return em.pos;
}

// ============================================================================
// crypto-account (BCR-2020-015) with crypto-output (BCR-2020-010) and
// crypto-hdkey (BCR-2020-007)
// ============================================================================

#define TAG_HDKEY       303
#define TAG_KEYPATH     304
#define TAG_OUTPUT      308
#define TAG_WSH         401
#define TAG_WPKH        404
#define TAG_COSIGNER    410

// Bounded CBOR writer
typedef struct {
    uint8_t *out;
    uint32_t pos;
    uint32_t size;
    bool overflow;
} cbor_writer_t;

static void cbor_bytes(cbor_writer_t *w, const uint8_t *data, uint32_t len) {
    if (w->overflow || len > w->size - w->pos) {
        w->overflow = true;
        return;
    }
    memcpy(&w->out[w->pos], data, len);
    w->pos += len;
}

// Major type (high 3 bits of 'major') with the shortest argument encoding
static void cbor_head(cbor_writer_t *w, uint8_t major, uint32_t v) {
    uint8_t b[5];
    uint32_t n;
    if (v < 24) {
        b[0] = (uint8_t)(major | v);
        n = 1;
    } else if (v < 0x100) {
        b[0] = (uint8_t)(major | 24);
        b[1] = (uint8_t)v;
        n = 2;
    } else if (v < 0x10000) {
        b[0] = (uint8_t)(major | 25);
        b[1] = (uint8_t)(v >> 8);
        b[2] = (uint8_t)v;
        n = 3;
    } else {
        b[0] = (uint8_t)(major | 26);
        b[1] = (uint8_t)(v >> 24);
        b[2] = (uint8_t)(v >> 16);
        b[3] = (uint8_t)(v >> 8);
        b[4] = (uint8_t)v;
        n = 5;
    }
    cbor_bytes(w, b, n);
}

#define CBOR_UINT   0x00
#define CBOR_BYTES  0x40
#define CBOR_ARRAY  0x80
#define CBOR_MAP    0xA0
#define CBOR_TAG    0xC0
#define CBOR_TRUE   0xF5
#define CBOR_FALSE  0xF4

uint32_t ur_account_cbor(const ur_account_key_t *key, uint8_t *out, uint32_t out_size) {
    cbor_writer_t w = { out, 0, out_size, false };
    static const uint8_t cbor_true = CBOR_TRUE, cbor_false = CBOR_FALSE;

    cbor_head(&w, CBOR_MAP, 2);                     // crypto-account
    cbor_head(&w, CBOR_UINT, 1);                    //   master-fingerprint
    cbor_head(&w, CBOR_UINT, key->master_fingerprint);
    cbor_head(&w, CBOR_UINT, 2);                    //   output-descriptors
    cbor_head(&w, CBOR_ARRAY, 1);

    cbor_head(&w, CBOR_TAG, TAG_OUTPUT);            // crypto-output
    if (key->multisig) {
        cbor_head(&w, CBOR_TAG, TAG_WSH);           //   wsh(cosigner(key))
        cbor_head(&w, CBOR_TAG, TAG_COSIGNER);
    } else {
        cbor_head(&w, CBOR_TAG, TAG_WPKH);          //   wpkh(key)
    }

    cbor_head(&w, CBOR_TAG, TAG_HDKEY);             // crypto-hdkey
    cbor_head(&w, CBOR_MAP, 4);
    cbor_head(&w, CBOR_UINT, 3);                    //   key-data
    cbor_head(&w, CBOR_BYTES, 33);
    cbor_bytes(&w, key->public_key, 33);
    cbor_head(&w, CBOR_UINT, 4);                    //   chain-code
    cbor_head(&w, CBOR_BYTES, 32);
    cbor_bytes(&w, key->chain_code, 32);
    cbor_head(&w, CBOR_UINT, 6);                    //   origin: crypto-keypath
    cbor_head(&w, CBOR_TAG, TAG_KEYPATH);
    cbor_head(&w, CBOR_MAP, 2);
    cbor_head(&w, CBOR_UINT, 1);                    //     components: [index, hardened]...
    cbor_head(&w, CBOR_ARRAY, 2u * key->path_len);
    for (uint32_t i = 0; i < key->path_len; i++) {
        cbor_head(&w, CBOR_UINT, key->path[i] & 0x7FFFFFFFu);
        cbor_bytes(&w, (key->path[i] & 0x80000000u) ? &cbor_true : &cbor_false, 1);
    }
    cbor_head(&w, CBOR_UINT, 2);                    //     source-fingerprint
    cbor_head(&w, CBOR_UINT, key->master_fingerprint);
    cbor_head(&w, CBOR_UINT, 8);                    //   parent-fingerprint
    cbor_head(&w, CBOR_UINT, key->parent_fingerprint);

    return w.overflow ? 0 : w.pos;
}
