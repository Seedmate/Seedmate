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

#define UR_PREFIX       "UR:CRYPTO-PSBT/"
#define UR_PREFIX_LEN   15u
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
    memset(e, 0, sizeof(*e));
    if (psbt == NULL || psbt_len == 0 || psbt_len > 0xFFFF || max_fragment_len < UR_MIN_FRAGMENT) return false;

    // CBOR major type 2 (byte string) header
    if (psbt_len < 24) {
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
    emit_text(&em, UR_PREFIX, UR_PREFIX_LEN);

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
