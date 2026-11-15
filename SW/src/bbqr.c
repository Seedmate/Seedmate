// BBQr decoder, see bbqr.h. The parts go straight to their place in the
// caller's buffer; the Z encoding is inflated in that same buffer: the
// compressed file is moved to its end and inflated towards the start, with
// the output limited to the bytes before it, so it can never overwrite
// data not read yet (unmodified tinf checks every write against that end).
#include "tinf/tinflate.c"          // Vendored tinf 1.2.1 (zlib license), unchanged

#include "bbqr.h"
#include <string.h>

static uint8_t *bb_buf;
static uint32_t bb_cap;
static char bb_want;                // File type accepted
static char bb_enc, bb_type;        // Of the first part
static uint16_t bb_total;           // 0: no part yet
static uint16_t bb_count;
static uint16_t bb_part_len;        // Bytes of every part but the last; 0 until one is seen
static uint16_t bb_last_len;        // Bytes of the last part; 0 until it is stored
static uint8_t bb_have[BBQR_MAX_PARTS / 8];

bool bbqr_is_part(const char *code, uint32_t len) {
    return len >= 2 && code[0] == 'B' && code[1] == '$';
}

void bbqr_init(uint8_t *buf, uint32_t cap, char want_type) {
    bb_buf = buf;
    bb_cap = cap;
    bb_want = want_type;
    bb_enc = bb_type = 0;
    bb_total = bb_count = bb_part_len = bb_last_len = 0;
    memset(bb_have, 0, sizeof(bb_have));
}

uint32_t bbqr_received(void) { return bb_count; }
uint32_t bbqr_total(void) { return bb_total; }

// Value of one character in the alphabet of the encoding, -1 if not in it
static int char_value(char c, char enc) {
    if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
    if (enc == 'H') {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    } else {                        // RFC 4648 base32: A-Z then 2-7
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= '2' && c <= '7') return c - '2' + 26;
    }
    return -1;
}

// Two base 36 digits, -1 if not
static int base36_pair(const char *s) {
    int v = 0;
    for (int i = 0; i < 2; i++) {
        char c = s[i];
        if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
        int d = (c >= '0' && c <= '9') ? c - '0' : (c >= 'A' && c <= 'Z') ? c - 'A' + 10 : -1;
        if (d < 0) return -1;
        v = v * 36 + d;
    }
    return v;
}

// Bytes that n characters decode to; -1 if n is not a valid length (every
// part must decode to whole bytes: an even number of hex digits; base32
// without padding, a multiple of 8 characters except in the last part)
static int32_t decoded_length(uint32_t n, char enc, bool last) {
    if (enc == 'H') return (n % 2) ? -1 : (int32_t)(n / 2);
    uint32_t r = n % 8;
    if (r != 0 && (!last || r == 1 || r == 3 || r == 6)) return -1;
    return (int32_t)(n * 5 / 8);
}

// Decodes n characters into dst, or compares them with dst. The bits left
// over at the end of base32 must be zero. BBQR_PART_ADDED, BBQR_ERR_DATA
// or BBQR_ERR_MISMATCH.
static bbqr_result_t decode_into(const char *s, uint32_t n, char enc, uint8_t *dst, bool compare) {
    uint32_t acc = 0;
    int bits = 0, per = (enc == 'H') ? 4 : 5;
    for (uint32_t i = 0; i < n; i++) {
        int v = char_value(s[i], enc);
        if (v < 0) return BBQR_ERR_DATA;
        acc = (acc << per) | (uint32_t)v;
        bits += per;
        if (bits >= 8) {
            bits -= 8;
            uint8_t b = (uint8_t)(acc >> bits);
            if (compare) {
                if (*dst != b) return BBQR_ERR_MISMATCH;
            } else {
                *dst = b;
            }
            dst++;
            acc &= (1u << bits) - 1u;
        }
    }
    return (acc != 0) ? BBQR_ERR_DATA : BBQR_PART_ADDED;
}

bbqr_result_t bbqr_add_part(const char *code, uint32_t len) {
    if (len < 8 || !bbqr_is_part(code, len)) return BBQR_ERR_HEADER;
    char enc = code[2], type = code[3];
    int total = base36_pair(&code[4]), idx = base36_pair(&code[6]);
    if (total <= 0 || idx < 0 || idx >= total) return BBQR_ERR_HEADER;
    if (enc != 'H' && enc != '2' && enc != 'Z') return BBQR_ERR_ENCODING;
    if (type != bb_want) return BBQR_ERR_TYPE;
    if ((uint32_t)total > BBQR_MAX_PARTS) return BBQR_ERR_TOO_BIG;
    if (bb_total == 0) {
        bb_enc = enc;
        bb_type = type;
        bb_total = (uint16_t)total;
    } else if (enc != bb_enc || type != bb_type || total != bb_total) {
        return BBQR_ERR_SERIES;
    }

    const char *data = &code[8];
    uint32_t n = len - 8;
    bool last = (idx == total - 1);
    int32_t blen = decoded_length(n, enc, last);
    if (blen <= 0) return BBQR_ERR_DATA;
    if (blen > 0xFFFF) return BBQR_ERR_TOO_BIG;

    // Where it goes: every part but the last has the length of the first one seen
    if (!last) {
        if (bb_part_len == 0) bb_part_len = (uint16_t)blen;
        else if ((uint32_t)blen != bb_part_len) return BBQR_ERR_MISMATCH;
    } else if (total > 1) {
        if (bb_part_len == 0) return BBQR_PART_IGNORED;    // Its place is not known yet
        if ((uint32_t)blen > bb_part_len) return BBQR_ERR_MISMATCH;
    }
    uint32_t off = (uint32_t)idx * bb_part_len;
    if (off + (uint32_t)blen > bb_cap) return BBQR_ERR_TOO_BIG;

    uint8_t bit = (uint8_t)(1u << (idx & 7));
    if (bb_have[idx >> 3] & bit) {
        // Seen already: it must be the same data
        if (last && (uint32_t)blen != bb_last_len) return BBQR_ERR_MISMATCH;
        bbqr_result_t r = decode_into(data, n, enc, &bb_buf[off], true);
        return (r == BBQR_PART_ADDED && bb_count == bb_total) ? BBQR_COMPLETE : r;
    }
    bbqr_result_t r = decode_into(data, n, enc, &bb_buf[off], false);
    if (r != BBQR_PART_ADDED) {
        memset(&bb_buf[off], 0, (size_t)blen);
        return r;
    }
    bb_have[idx >> 3] |= bit;
    if (last) bb_last_len = (uint16_t)blen;
    bb_count++;
    return (bb_count == bb_total) ? BBQR_COMPLETE : BBQR_PART_ADDED;
}

bbqr_result_t bbqr_finish(uint32_t max_len, uint32_t *out_len) {
    *out_len = 0;
    if (bb_total == 0 || bb_count != bb_total) return BBQR_ERR_DATA;
    uint32_t c = (uint32_t)(bb_total - 1u) * bb_part_len + bb_last_len;
    uint32_t got = c;

    if (bb_enc == 'Z') {
        // Compressed file at the end of the buffer, output from the start up to it
        uint8_t *src = bb_buf + bb_cap - c;
        memmove(src, bb_buf, c);
        unsigned int room = bb_cap - c;
        if (room > max_len) room = max_len;
        int r = tinf_uncompress(bb_buf, &room, src, c);
        memset(bb_buf + room, 0, bb_cap - room);            // The compressed copy goes
        if (r == TINF_BUF_ERROR) return BBQR_ERR_TOO_BIG;
        if (r != TINF_OK) return BBQR_ERR_DAMAGED;
        got = room;
    } else if (c > max_len) {
        return BBQR_ERR_TOO_BIG;
    }
    if (got < bb_cap) bb_buf[got] = 0;
    *out_len = got;
    return BBQR_COMPLETE;
}
