/*******************************************************************************
 * Project:     SeedMate
 * File:        psbt.c
 *
 * Summary:
 *   Minimal zero-copy PSBT (BIP174 v0) parser. See psbt.h.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include <string.h>
#include "psbt.h"
#include "crypto/segwit_addr.h"

#define PSBT_MAX_MONEY 2100000000000000ULL  // 21M BTC in satoshis

// Key types used by this parser (BIP174)
#define PSBT_GLOBAL_UNSIGNED_TX   0x00
#define PSBT_GLOBAL_XPUB          0x01
#define PSBT_GLOBAL_VERSION       0xFB
#define PSBT_IN_NON_WITNESS_UTXO  0x00
#define PSBT_IN_WITNESS_UTXO      0x01
#define PSBT_IN_PARTIAL_SIG       0x02
#define PSBT_IN_SIGHASH_TYPE      0x03
#define PSBT_IN_REDEEM_SCRIPT     0x04
#define PSBT_IN_WITNESS_SCRIPT    0x05
#define PSBT_IN_BIP32_DERIVATION  0x06
#define PSBT_IN_FINAL_SCRIPTSIG   0x07
#define PSBT_IN_FINAL_WITNESS     0x08
#define PSBT_OUT_REDEEM_SCRIPT    0x00
#define PSBT_OUT_WITNESS_SCRIPT   0x01
#define PSBT_OUT_BIP32_DERIVATION 0x02

#define XPUB_SERIALIZED_LEN       78

// ============================================================================
// Bounded byte reader. Any out-of-range access sets 'err' and every later
// read returns 0/NULL, so callers only need to check 'err' at the end.
// ============================================================================
typedef struct {
    const uint8_t *p;
    uint32_t pos;
    uint32_t end;       // Exclusive limit
    bool err;
} reader_t;

static void rd_init(reader_t *r, const uint8_t *p, uint32_t pos, uint32_t end) {
    r->p = p;
    r->pos = pos;
    r->end = end;
    r->err = (pos > end);
}

static bool rd_need(reader_t *r, uint32_t n) {
    if (r->err || n > r->end - r->pos) {
        r->err = true;
        return false;
    }
    return true;
}

static const uint8_t *rd_bytes(reader_t *r, uint32_t n) {
    if (!rd_need(r, n)) return NULL;
    const uint8_t *ptr = r->p + r->pos;
    r->pos += n;
    return ptr;
}

static uint8_t rd_u8(reader_t *r) {
    const uint8_t *b = rd_bytes(r, 1);
    return b ? b[0] : 0;
}

static uint32_t rd_le32(reader_t *r) {
    const uint8_t *b = rd_bytes(r, 4);
    if (!b) return 0;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static uint64_t rd_le64(reader_t *r) {
    uint32_t lo = rd_le32(r);
    uint32_t hi = rd_le32(r);
    return (uint64_t)lo | ((uint64_t)hi << 32);
}

// Bitcoin CompactSize. 64-bit values are rejected: they can never fit in RAM.
static uint32_t rd_varint(reader_t *r) {
    uint8_t b = rd_u8(r);
    if (b < 0xFD) return b;
    if (b == 0xFD) {
        const uint8_t *v = rd_bytes(r, 2);
        return v ? ((uint32_t)v[0] | ((uint32_t)v[1] << 8)) : 0;
    }
    if (b == 0xFE) return rd_le32(r);
    r->err = true;
    return 0;
}

static void rd_skip(reader_t *r, uint32_t n) {
    (void)rd_bytes(r, n);
}

// ============================================================================
// Transaction and key/value map helpers
// ============================================================================

// Skips one tx input: prev txid (32), vout (4), scriptSig, sequence (4)
static void tx_skip_input(reader_t *r) {
    rd_skip(r, 36);
    rd_skip(r, rd_varint(r));
    rd_skip(r, 4);
}

// Skips one tx output: value (8), scriptPubKey
static void tx_skip_output(reader_t *r) {
    rd_skip(r, 8);
    rd_skip(r, rd_varint(r));
}

// Last key read by map_next(): key[0] is the key type, the rest its key data
static const uint8_t *last_key;

// Reads one key/value pair. Returns false at the 0x00 map separator or on error.
static bool map_next(reader_t *r, uint8_t *key_type, uint32_t *key_len,
                     const uint8_t **val, uint32_t *val_len) {
    uint32_t klen = rd_varint(r);
    if (r->err || klen == 0) return false;
    const uint8_t *key = rd_bytes(r, klen);
    uint32_t vlen = rd_varint(r);
    const uint8_t *v = rd_bytes(r, vlen);
    if (r->err) return false;

    last_key = key;
    *key_type = key[0];
    *key_len = klen;
    *val = v;
    *val_len = vlen;
    return true;
}

static void map_skip(reader_t *r) {
    uint8_t type;
    uint32_t key_len, val_len;
    const uint8_t *val;
    while (map_next(r, &type, &key_len, &val, &val_len)) {
    }
}

// Positions r at the start of map number 'index' in a run of maps
static void map_seek(reader_t *r, const psbt_t *psbt, uint32_t first_map_ofs, uint32_t index) {
    rd_init(r, psbt->buf, first_map_ofs, psbt->len);
    for (uint32_t i = 0; i < index && !r->err; i++) {
        map_skip(r);
    }
}

// A key/value pair is a valid BIP32 derivation if the key is a public key
// (or an xpub for globals) and the value is fingerprint + whole path elements
static bool is_keypath(uint32_t key_len, uint32_t val_len, bool global) {
    uint32_t pub_len = key_len - 1;
    bool key_ok = global ? (pub_len == XPUB_SERIALIZED_LEN) : (pub_len == 33 || pub_len == 65);
    return key_ok && val_len >= 4 && (val_len % 4) == 0;
}

// Finds the n-th BIP32 derivation of 'type' in the map at r
static bool map_find_keypath(reader_t *r, uint8_t wanted, bool global, uint32_t n, psbt_keypath_t *kp) {
    uint8_t type;
    uint32_t key_len, val_len;
    const uint8_t *val;

    while (map_next(r, &type, &key_len, &val, &val_len)) {
        if (type != wanted || !is_keypath(key_len, val_len, global)) continue;
        if (n-- != 0) continue;

        kp->key = last_key + 1;     // Key data follows the type byte
        kp->key_len = key_len - 1;
        kp->fingerprint = ((uint32_t)val[0] << 24) | ((uint32_t)val[1] << 16) |
                          ((uint32_t)val[2] << 8) | val[3];
        kp->path = val + 4;
        kp->path_len = (val_len - 4) / 4;
        return true;
    }
    return false;
}

// Parses the PSBT_GLOBAL_UNSIGNED_TX value located at [ofs, ofs + len)
static psbt_status_t parse_unsigned_tx(psbt_t *psbt, uint32_t ofs, uint32_t len) {
    reader_t r;
    rd_init(&r, psbt->buf, ofs, ofs + len);

    psbt->tx_version = rd_le32(&r);

    // The unsigned tx uses the legacy serialization: a 0x00 here would be the
    // SegWit marker (or zero inputs), both invalid in a PSBT.
    if (r.err || r.pos >= r.end || psbt->buf[r.pos] == 0x00) return PSBT_ERR_FORMAT;

    psbt->input_count = rd_varint(&r);
    psbt->tx_inputs_ofs = r.pos;
    for (uint32_t i = 0; i < psbt->input_count && !r.err; i++) {
        rd_skip(&r, 36);
        if (rd_varint(&r) != 0) return PSBT_ERR_FORMAT;  // scriptSig must be empty
        rd_skip(&r, 4);
    }

    psbt->output_count = rd_varint(&r);
    psbt->tx_outputs_ofs = r.pos;
    for (uint32_t i = 0; i < psbt->output_count && !r.err; i++) {
        tx_skip_output(&r);
    }

    psbt->locktime = rd_le32(&r);

    if (r.err) return PSBT_ERR_TRUNCATED;
    if (r.pos != r.end || psbt->output_count == 0) return PSBT_ERR_FORMAT;
    return PSBT_OK;
}

// Reads output 'vout' of a full previous transaction (NON_WITNESS_UTXO).
// Accepts both legacy and SegWit serializations.
static bool read_prev_tx_output(const uint8_t *data, uint32_t len, uint32_t vout,
                                uint64_t *amount, const uint8_t **script, uint32_t *script_len) {
    reader_t r;
    rd_init(&r, data, 0, len);

    rd_skip(&r, 4);                                   // version
    if (len >= 6 && data[4] == 0x00 && data[5] == 0x01) {
        rd_skip(&r, 2);                               // SegWit marker and flag
    }

    uint32_t n_in = rd_varint(&r);
    for (uint32_t i = 0; i < n_in && !r.err; i++) {
        tx_skip_input(&r);
    }

    uint32_t n_out = rd_varint(&r);
    if (r.err || vout >= n_out) return false;
    for (uint32_t i = 0; i < vout && !r.err; i++) {
        tx_skip_output(&r);
    }

    *amount = rd_le64(&r);
    *script_len = rd_varint(&r);
    *script = rd_bytes(&r, *script_len);
    return !r.err;
}

// ============================================================================
// Public API
// ============================================================================

psbt_status_t psbt_parse(const uint8_t *data, uint32_t len, psbt_t *psbt) {
    memset(psbt, 0, sizeof(*psbt));
    if (data == NULL || len < 5) return PSBT_ERR_MAGIC;

    // Optional CBOR byte-string wrapper (major type 2), as used by ur:crypto-psbt
    if ((data[0] >> 5) == 2) {
        uint8_t ai = data[0] & 0x1F;
        uint32_t hdr, blen;
        if (ai < 24) {
            hdr = 1; blen = ai;
        } else if (ai == 24) {
            hdr = 2; blen = data[1];
        } else if (ai == 25) {
            hdr = 3; blen = ((uint32_t)data[1] << 8) | data[2];
        } else if (ai == 26) {
            hdr = 5;
            blen = ((uint32_t)data[1] << 24) | ((uint32_t)data[2] << 16) |
                   ((uint32_t)data[3] << 8) | data[4];
        } else {
            return PSBT_ERR_FORMAT;
        }
        if (hdr > len || blen > len - hdr) return PSBT_ERR_TRUNCATED;
        data += hdr;
        len = blen;
    }

    if (len < 5 || memcmp(data, "psbt\xff", 5) != 0) return PSBT_ERR_MAGIC;
    psbt->buf = data;
    psbt->len = len;

    // Global map
    reader_t r;
    rd_init(&r, data, 5, len);
    bool have_tx = false;
    uint8_t type;
    uint32_t key_len, val_len;
    const uint8_t *val;

    while (map_next(&r, &type, &key_len, &val, &val_len)) {
        if (key_len != 1) continue;

        if (type == PSBT_GLOBAL_UNSIGNED_TX) {
            if (have_tx) return PSBT_ERR_FORMAT;      // Duplicate key
            psbt_status_t st = parse_unsigned_tx(psbt, (uint32_t)(val - data), val_len);
            if (st != PSBT_OK) return st;
            have_tx = true;
        } else if (type == PSBT_GLOBAL_VERSION) {
            if (val_len != 4) return PSBT_ERR_FORMAT;
            if (val[0] | val[1] | val[2] | val[3]) return PSBT_ERR_UNSUPPORTED;
        }
    }
    if (r.err) return PSBT_ERR_TRUNCATED;
    if (!have_tx) return PSBT_ERR_NO_TX;

    // One map per input and per output, in order
    psbt->input_maps_ofs = r.pos;
    for (uint32_t i = 0; i < psbt->input_count && !r.err; i++) {
        map_skip(&r);
    }
    psbt->output_maps_ofs = r.pos;
    for (uint32_t i = 0; i < psbt->output_count && !r.err; i++) {
        map_skip(&r);
    }
    if (r.err) return PSBT_ERR_TRUNCATED;

    return PSBT_OK;
}

bool psbt_get_input(const psbt_t *psbt, uint32_t index, psbt_input_t *in) {
    if (psbt == NULL || psbt->buf == NULL || index >= psbt->input_count) return false;
    memset(in, 0, sizeof(*in));

    // Outpoint and sequence from the unsigned tx
    reader_t r;
    rd_init(&r, psbt->buf, psbt->tx_inputs_ofs, psbt->len);
    for (uint32_t i = 0; i < index && !r.err; i++) {
        tx_skip_input(&r);
    }
    in->prev_txid = rd_bytes(&r, 32);
    in->prev_vout = rd_le32(&r);
    rd_skip(&r, rd_varint(&r));
    in->sequence = rd_le32(&r);
    if (r.err) return false;

    // UTXO data, scripts and signing metadata from this input's map
    map_seek(&r, psbt, psbt->input_maps_ofs, index);

    const uint8_t *witness_utxo = NULL;
    const uint8_t *prev_tx = NULL;
    uint32_t witness_len = 0, prev_tx_len = 0;
    uint8_t type;
    uint32_t key_len, val_len;
    const uint8_t *val;

    while (map_next(&r, &type, &key_len, &val, &val_len)) {
        if (type == PSBT_IN_PARTIAL_SIG) {
            in->partial_sig_count++;
        } else if (type == PSBT_IN_BIP32_DERIVATION) {
            if (is_keypath(key_len, val_len, false)) in->keypath_count++;
        } else if (key_len != 1) {
            continue;
        } else if (type == PSBT_IN_WITNESS_UTXO) {
            witness_utxo = val;
            witness_len = val_len;
        } else if (type == PSBT_IN_NON_WITNESS_UTXO) {
            prev_tx = val;
            prev_tx_len = val_len;
        } else if (type == PSBT_IN_SIGHASH_TYPE && val_len == 4) {
            in->has_sighash = true;
            in->sighash = (uint32_t)val[0] | ((uint32_t)val[1] << 8) |
                          ((uint32_t)val[2] << 16) | ((uint32_t)val[3] << 24);
        } else if (type == PSBT_IN_REDEEM_SCRIPT) {
            in->redeem_script = val;
            in->redeem_script_len = val_len;
        } else if (type == PSBT_IN_WITNESS_SCRIPT) {
            in->witness_script = val;
            in->witness_script_len = val_len;
        } else if (type == PSBT_IN_FINAL_SCRIPTSIG || type == PSBT_IN_FINAL_WITNESS) {
            in->finalized = true;
        }
    }
    if (r.err) return false;

    in->prev_tx = prev_tx;
    in->prev_tx_len = prev_tx_len;

    // Prefer the full previous tx: its amount is committed by prev_txid
    if (prev_tx != NULL &&
        read_prev_tx_output(prev_tx, prev_tx_len, in->prev_vout,
                            &in->amount, &in->script, &in->script_len)) {
        in->has_amount = true;
        in->amount_from_witness = false;
    }

    if (!in->has_amount && witness_utxo != NULL) {
        reader_t w;
        rd_init(&w, witness_utxo, 0, witness_len);
        uint64_t amount = rd_le64(&w);
        uint32_t script_len = rd_varint(&w);
        const uint8_t *script = rd_bytes(&w, script_len);
        if (!w.err && w.pos == w.end) {
            in->amount = amount;
            in->script = script;
            in->script_len = script_len;
            in->has_amount = true;
            in->amount_from_witness = true;
        }
    }

    if (in->has_amount && in->amount > PSBT_MAX_MONEY) {
        in->has_amount = false;
    }
    return true;
}

bool psbt_get_output(const psbt_t *psbt, uint32_t index, psbt_output_t *out) {
    if (psbt == NULL || psbt->buf == NULL || index >= psbt->output_count) return false;

    memset(out, 0, sizeof(*out));

    reader_t r;
    rd_init(&r, psbt->buf, psbt->tx_outputs_ofs, psbt->len);
    for (uint32_t i = 0; i < index && !r.err; i++) {
        tx_skip_output(&r);
    }
    out->amount = rd_le64(&r);
    out->script_len = rd_varint(&r);
    out->script = rd_bytes(&r, out->script_len);
    if (r.err) return false;

    // Scripts and derivations from this output's map
    map_seek(&r, psbt, psbt->output_maps_ofs, index);
    uint8_t type;
    uint32_t key_len, val_len;
    const uint8_t *val;

    while (map_next(&r, &type, &key_len, &val, &val_len)) {
        if (type == PSBT_OUT_BIP32_DERIVATION) {
            if (is_keypath(key_len, val_len, false)) out->keypath_count++;
        } else if (key_len != 1) {
            continue;
        } else if (type == PSBT_OUT_REDEEM_SCRIPT) {
            out->redeem_script = val;
            out->redeem_script_len = val_len;
        } else if (type == PSBT_OUT_WITNESS_SCRIPT) {
            out->witness_script = val;
            out->witness_script_len = val_len;
        }
    }
    return !r.err;
}

bool psbt_input_keypath(const psbt_t *psbt, uint32_t index, uint32_t n, psbt_keypath_t *kp) {
    if (psbt == NULL || psbt->buf == NULL || index >= psbt->input_count) return false;
    reader_t r;
    map_seek(&r, psbt, psbt->input_maps_ofs, index);
    return map_find_keypath(&r, PSBT_IN_BIP32_DERIVATION, false, n, kp);
}

bool psbt_output_keypath(const psbt_t *psbt, uint32_t index, uint32_t n, psbt_keypath_t *kp) {
    if (psbt == NULL || psbt->buf == NULL || index >= psbt->output_count) return false;
    reader_t r;
    map_seek(&r, psbt, psbt->output_maps_ofs, index);
    return map_find_keypath(&r, PSBT_OUT_BIP32_DERIVATION, false, n, kp);
}

bool psbt_global_xpub(const psbt_t *psbt, uint32_t n, psbt_keypath_t *kp) {
    if (psbt == NULL || psbt->buf == NULL) return false;
    reader_t r;
    rd_init(&r, psbt->buf, 5, psbt->len);   // Global map starts after the magic
    return map_find_keypath(&r, PSBT_GLOBAL_XPUB, true, n, kp);
}

uint32_t psbt_path_element(const psbt_keypath_t *kp, uint32_t i) {
    const uint8_t *p = kp->path + 4 * i;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Appends the decimal form of v at out[pos]; returns the new length
static uint32_t append_u32(char *out, uint32_t pos, uint32_t v) {
    char tmp[10];
    int n = 0;
    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v != 0);
    while (n > 0) out[pos++] = tmp[--n];
    return pos;
}

void psbt_format_path(const psbt_keypath_t *kp, char *out) {
    uint32_t pos = 0;
    out[pos++] = 'm';
    for (uint32_t i = 0; i < kp->path_len; i++) {
        // Worst case element "/4294967295'" is 12 chars; keep room for "..." + NUL
        if (pos + 12 + 4 > PSBT_PATH_STR_LEN) {
            memcpy(&out[pos], "...", 3);
            pos += 3;
            break;
        }
        uint32_t e = psbt_path_element(kp, i);
        out[pos++] = '/';
        pos = append_u32(out, pos, e & ~PSBT_HARDENED);
        if (e & PSBT_HARDENED) out[pos++] = '\'';
    }
    out[pos] = '\0';
}

void psbt_format_fingerprint(uint32_t fingerprint, char *out) {
    static const char hex[] = "0123456789ABCDEF";
    for (int i = 0; i < 8; i++) {
        out[i] = hex[(fingerprint >> (28 - 4 * i)) & 0x0F];
    }
    out[8] = '\0';
}

bool psbt_multisig_info(const uint8_t *s, uint32_t len, uint8_t *m, uint8_t *n) {
    // OP_1..OP_16 are 0x51..0x60; each key is pushed as 0x21 + 33 bytes
    if (s == NULL || len < 3 || s[0] < 0x51 || s[0] > 0x60) return false;
    uint8_t keys = s[len - 2] - 0x50;
    uint8_t req = s[0] - 0x50;
    if (s[len - 2] < 0x51 || s[len - 2] > 0x60 || s[len - 1] != 0xAE) return false;  // OP_CHECKMULTISIG
    if (req > keys || len != 3u + 34u * keys) return false;
    for (uint32_t i = 0; i < keys; i++) {
        const uint8_t *k = &s[1 + 34 * i];
        if (k[0] != 0x21 || (k[1] != 0x02 && k[1] != 0x03)) return false;
    }
    *m = req;
    *n = keys;
    return true;
}

bool psbt_multisig_has_key(const uint8_t *script, uint32_t len, const uint8_t *pubkey) {
    uint8_t m, n;
    if (!psbt_multisig_info(script, len, &m, &n)) return false;
    for (uint32_t i = 0; i < n; i++) {
        if (memcmp(&script[2 + 34 * i], pubkey, 33) == 0) return true;
    }
    return false;
}

bool psbt_input_has_sig_from(const psbt_t *psbt, uint32_t index, const uint8_t *pubkey, uint32_t pubkey_len) {
    reader_t r;
    uint8_t type;
    uint32_t key_len, val_len;
    const uint8_t *val;

    if (psbt == NULL || psbt->buf == NULL || index >= psbt->input_count) return false;
    map_seek(&r, psbt, psbt->input_maps_ofs, index);
    while (map_next(&r, &type, &key_len, &val, &val_len)) {
        if (type == PSBT_IN_PARTIAL_SIG && key_len == pubkey_len + 1 &&
            memcmp(last_key + 1, pubkey, pubkey_len) == 0) {
            return true;
        }
    }
    return false;
}

const char *psbt_sighash_name(uint32_t sighash) {
    switch (sighash) {
        case PSBT_SIGHASH_ALL:                                  return "ALL";
        case PSBT_SIGHASH_NONE:                                 return "NONE";
        case PSBT_SIGHASH_SINGLE:                               return "SINGLE";
        case PSBT_SIGHASH_ALL | PSBT_SIGHASH_ANYONECANPAY:      return "ALL|ACP";
        case PSBT_SIGHASH_NONE | PSBT_SIGHASH_ANYONECANPAY:     return "NONE|ACP";
        case PSBT_SIGHASH_SINGLE | PSBT_SIGHASH_ANYONECANPAY:   return "SINGLE|ACP";
        default:                                                return "UNKNOWN";
    }
}

void psbt_base64_init(psbt_base64_t *b) {
    memset(b, 0, sizeof(*b));
}

// Value of a base64 character, -1 if it is not one
static int base64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool psbt_base64_feed(psbt_base64_t *b, const char *text, uint32_t len,
                      uint8_t *out, uint32_t out_size, uint32_t *out_len) {
    for (uint32_t i = 0; i < len && !b->err; i++) {
        char c = text[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') continue;

        if (c == '=') {
            b->padded = true;
        } else {
            int v = base64_value(c);
            if (v < 0 || b->padded) {
                b->err = true;
                break;
            }
            b->acc = (b->acc << 6) | (uint32_t)v;
            b->bits += 6;
            if (b->bits >= 8) {
                b->bits -= 8;
                if (*out_len >= out_size) {
                    b->err = true;
                    break;
                }
                out[(*out_len)++] = (uint8_t)(b->acc >> b->bits);
            }
        }
        b->quad = (b->quad + 1) & 3;
    }
    return !b->err;
}

bool psbt_base64_finish(const psbt_base64_t *b) {
    return !b->err && b->quad == 0;
}

bool psbt_tx_outputs(const psbt_t *psbt, const uint8_t **outputs, uint32_t *len) {
    reader_t r;
    rd_init(&r, psbt->buf, psbt->tx_outputs_ofs, psbt->len);
    for (uint32_t i = 0; i < psbt->output_count && !r.err; i++) {
        tx_skip_output(&r);
    }
    if (r.err) return false;
    *outputs = psbt->buf + psbt->tx_outputs_ofs;
    *len = r.pos - psbt->tx_outputs_ofs;
    return true;
}

bool psbt_tx_txid_body(const uint8_t *tx, uint32_t len, uint32_t *body_ofs, uint32_t *body_len) {
    reader_t r;
    rd_init(&r, tx, 0, len);
    rd_skip(&r, 4);                                   // version
    bool segwit = len >= 6 && tx[4] == 0x00 && tx[5] == 0x01;
    if (segwit) rd_skip(&r, 2);                       // marker and flag

    uint32_t start = r.pos;
    uint32_t n_in = rd_varint(&r);
    for (uint32_t i = 0; i < n_in && !r.err; i++) {
        tx_skip_input(&r);
    }
    uint32_t n_out = rd_varint(&r);
    for (uint32_t i = 0; i < n_out && !r.err; i++) {
        tx_skip_output(&r);
    }
    uint32_t end = r.pos;

    if (segwit) {                                     // One witness stack per input
        for (uint32_t i = 0; i < n_in && !r.err; i++) {
            uint32_t items = rd_varint(&r);
            for (uint32_t j = 0; j < items && !r.err; j++) {
                rd_skip(&r, rd_varint(&r));
            }
        }
    }
    rd_skip(&r, 4);                                   // locktime
    if (r.err || r.pos != len) return false;

    *body_ofs = start;
    *body_len = end - start;
    return true;
}

uint32_t psbt_add_partial_sig(uint8_t *buf, uint32_t capacity, const psbt_t *psbt, uint32_t index,
                              const uint8_t *pubkey, uint32_t pubkey_len,
                              const uint8_t *sig, uint32_t sig_len) {
    if (psbt->buf != buf || index >= psbt->input_count || pubkey_len + 1 >= 0xFD || sig_len >= 0xFD) return 0;

    // Position of this input map's 0x00 separator
    reader_t r;
    uint8_t type;
    uint32_t key_len, val_len;
    const uint8_t *val;
    map_seek(&r, psbt, psbt->input_maps_ofs, index);
    while (map_next(&r, &type, &key_len, &val, &val_len)) {
    }
    if (r.err) return 0;
    uint32_t at = r.pos - 1;

    // <keylen> 0x02 <pubkey> <siglen> <sig>
    uint32_t add = 1 + 1 + pubkey_len + 1 + sig_len;
    if (psbt->len + add > capacity) return 0;
    memmove(&buf[at + add], &buf[at], psbt->len - at);
    buf[at++] = (uint8_t)(pubkey_len + 1);
    buf[at++] = PSBT_IN_PARTIAL_SIG;
    memcpy(&buf[at], pubkey, pubkey_len);
    at += pubkey_len;
    buf[at++] = (uint8_t)sig_len;
    memcpy(&buf[at], sig, sig_len);
    return psbt->len + add;
}

bool psbt_signals_rbf(const psbt_t *psbt) {
    reader_t r;
    rd_init(&r, psbt->buf, psbt->tx_inputs_ofs, psbt->len);
    for (uint32_t i = 0; i < psbt->input_count && !r.err; i++) {
        rd_skip(&r, 36);
        rd_skip(&r, rd_varint(&r));
        if (rd_le32(&r) < PSBT_SEQUENCE_RBF_LIMIT && !r.err) return true;
    }
    return false;
}

bool psbt_get_totals(const psbt_t *psbt, uint64_t *in_total, uint64_t *out_total) {
    bool ok = true;
    uint64_t sum_in = 0, sum_out = 0;

    for (uint32_t i = 0; i < psbt->input_count; i++) {
        psbt_input_t in;
        if (!psbt_get_input(psbt, i, &in) || !in.has_amount) {
            ok = false;
            continue;
        }
        sum_in += in.amount;
        if (sum_in > PSBT_MAX_MONEY) {
            ok = false;
            break;
        }
    }

    for (uint32_t i = 0; i < psbt->output_count; i++) {
        psbt_output_t out;
        if (!psbt_get_output(psbt, i, &out) || out.amount > PSBT_MAX_MONEY) {
            ok = false;
            continue;
        }
        sum_out += out.amount;
        if (sum_out > PSBT_MAX_MONEY) {
            ok = false;
            break;
        }
    }

    if (in_total) *in_total = sum_in;
    if (out_total) *out_total = sum_out;
    return ok;
}

bool psbt_get_fee(const psbt_t *psbt, uint64_t *fee) {
    uint64_t sum_in, sum_out;
    if (!psbt_get_totals(psbt, &sum_in, &sum_out) || sum_in < sum_out) return false;
    *fee = sum_in - sum_out;
    return true;
}

psbt_script_type_t psbt_script_type(const uint8_t *s, uint32_t len) {
    if (s == NULL || len == 0) return PSBT_SCRIPT_UNKNOWN;
    if (len == 25 && s[0] == 0x76 && s[1] == 0xA9 && s[2] == 0x14 && s[23] == 0x88 && s[24] == 0xAC) {
        return PSBT_SCRIPT_P2PKH;
    }
    if (len == 23 && s[0] == 0xA9 && s[1] == 0x14 && s[22] == 0x87) return PSBT_SCRIPT_P2SH;
    if (len == 22 && s[0] == 0x00 && s[1] == 0x14) return PSBT_SCRIPT_P2WPKH;
    if (len == 34 && s[0] == 0x00 && s[1] == 0x20) return PSBT_SCRIPT_P2WSH;
    if (len == 34 && s[0] == 0x51 && s[1] == 0x20) return PSBT_SCRIPT_P2TR;
    if (s[0] == 0x6A) return PSBT_SCRIPT_OP_RETURN;
    return PSBT_SCRIPT_UNKNOWN;
}

const char *psbt_script_type_name(psbt_script_type_t type) {
    switch (type) {
        case PSBT_SCRIPT_P2PKH:     return "P2PKH";
        case PSBT_SCRIPT_P2SH:      return "P2SH";
        case PSBT_SCRIPT_P2WPKH:    return "P2WPKH";
        case PSBT_SCRIPT_P2WSH:     return "P2WSH";
        case PSBT_SCRIPT_P2TR:      return "P2TR";
        case PSBT_SCRIPT_OP_RETURN: return "OP_RETURN";
        default:                    return "UNKNOWN";
    }
}

bool psbt_segwit_address(const uint8_t *script, uint32_t len, const char *hrp,
                         char *out, size_t out_size) {
    psbt_script_type_t type = psbt_script_type(script, len);
    if (out_size < PSBT_ADDRESS_MAX_LEN) return false;
    if (type != PSBT_SCRIPT_P2WPKH && type != PSBT_SCRIPT_P2WSH && type != PSBT_SCRIPT_P2TR) return false;

    int witness_version = (script[0] == 0x00) ? 0 : 1;   // OP_0 or OP_1
    return segwit_addr_encode(out, hrp, witness_version, &script[2], script[1]) == 1;
}

// Decimal conversion by repeated subtraction: avoids pulling the 64-bit
// division routines from libgcc into flash.
static const uint64_t pow10_table[20] = {
    1ULL, 10ULL, 100ULL, 1000ULL, 10000ULL, 100000ULL, 1000000ULL, 10000000ULL,
    100000000ULL, 1000000000ULL, 10000000000ULL, 100000000000ULL, 1000000000000ULL,
    10000000000000ULL, 100000000000000ULL, 1000000000000000ULL, 10000000000000000ULL,
    100000000000000000ULL, 1000000000000000000ULL, 10000000000000000000ULL
};

void psbt_format_btc(uint64_t sats, char *out) {
    char digits[20];
    int n = 0;
    bool started = false;

    for (int i = 19; i >= 0; i--) {
        uint8_t d = 0;
        while (sats >= pow10_table[i]) {
            sats -= pow10_table[i];
            d++;
        }
        // Keep at least 9 digits so there is always "0." before the decimals
        if (d != 0 || started || i <= 8) {
            digits[n++] = (char)('0' + d);
            started = true;
        }
    }

    int k = 0;
    for (int i = 0; i < n - 8; i++) out[k++] = digits[i];
    out[k++] = '.';
    for (int i = n - 8; i < n; i++) out[k++] = digits[i];
    out[k] = '\0';
}

void psbt_format_txid(const uint8_t *txid, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        uint8_t b = txid[31 - i];
        out[2 * i] = hex[b >> 4];
        out[2 * i + 1] = hex[b & 0x0F];
    }
    out[64] = '\0';
}

const char *psbt_status_name(psbt_status_t status) {
    switch (status) {
        case PSBT_OK:              return "OK";
        case PSBT_ERR_MAGIC:       return "NOT A PSBT";
        case PSBT_ERR_TRUNCATED:   return "TRUNCATED";
        case PSBT_ERR_FORMAT:      return "BAD FORMAT";
        case PSBT_ERR_NO_TX:       return "NO UNSIGNED TX";
        case PSBT_ERR_UNSUPPORTED: return "UNSUPPORTED (V2?)";
        default:                   return "UNKNOWN ERROR";
    }
}
