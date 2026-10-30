/*******************************************************************************
 * Project:     SeedMate
 * File:        descriptor.c
 *
 * Summary:
 *   Multisig wallet descriptor parser (see descriptor.h).
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include "descriptor.h"
#include "sha256.h"
#include <string.h>

#define HARDENED        0x80000000u

// Extended public key versions (SLIP-0132)
#define VER_XPUB        0x0488B21Eu     // xpub
#define VER_ZPUB_MS     0x02AA7ED3u     // Zpub: P2WSH multisig (Coldcard files)
#define VER_YPUB_MS     0x0295B43Fu     // Ypub: P2SH-P2WSH multisig (not signed here)
#define VER_TPUB        0x043587CFu     // tpub
#define VER_VPUB_MS     0x02575483u     // Vpub
#define VER_UPUB_MS     0x024289EFu     // Upub

typedef struct {
    const char *p;
    const char *end;
} cursor_t;

static bool accept(cursor_t *c, char ch) {
    if (c->p < c->end && *c->p == ch) {
        c->p++;
        return true;
    }
    return false;
}

static bool accept_str(cursor_t *c, const char *s) {
    size_t n = strlen(s);
    if ((size_t)(c->end - c->p) >= n && memcmp(c->p, s, n) == 0) {
        c->p += n;
        return true;
    }
    return false;
}

static void skip_spaces(cursor_t *c) {
    while (c->p < c->end && (*c->p == ' ' || *c->p == '\t')) c->p++;
}

// Decimal number below 2^31 (a path element before the hardened flag)
static bool read_uint(cursor_t *c, uint32_t *v) {
    uint32_t n = 0;
    const char *start = c->p;
    while (c->p < c->end && *c->p >= '0' && *c->p <= '9') {
        n = n * 10u + (uint32_t)(*c->p - '0');
        if (n >= HARDENED) return false;
        c->p++;
    }
    *v = n;
    return c->p > start;
}

static int hex_value(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

// 8 hex digits: a master fingerprint
static bool read_fingerprint(cursor_t *c, uint8_t fp[4]) {
    if (c->end - c->p < 8) return false;
    for (int i = 0; i < 4; i++) {
        int hi = hex_value(c->p[2 * i]);
        int lo = hex_value(c->p[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        fp[i] = (uint8_t)(hi << 4 | lo);
    }
    c->p += 8;
    return true;
}

// Path elements "/48h/0'/2H..." after a fingerprint or "m"
static bool read_path(cursor_t *c, desc_key_t *k) {
    k->origin_len = 0;
    while (accept(c, '/')) {
        uint32_t v;
        if (!read_uint(c, &v)) return false;
        if (accept(c, '\'') || accept(c, 'h') || accept(c, 'H')) v |= HARDENED;
        if (k->origin_len < DESC_ORIGIN_MAX) k->origin[k->origin_len] = v;
        if (k->origin_len < 255) k->origin_len++;
    }
    return true;
}

// --- Base58Check extended public key ------------------------------------------

static const char b58_alphabet[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static bool is_b58(char ch) {
    return ch != '\0' && strchr(b58_alphabet, ch) != NULL;
}

// Decodes a serialized extended key (78 bytes + 4 bytes of checksum)
static bool b58check_decode_xkey(const char *s, uint32_t n, uint8_t out[78]) {
    uint8_t buf[82];
    uint8_t hash[32];
    SHA256_CTX ctx;

    if (n == 0 || n > 120) return false;
    memset(buf, 0, sizeof(buf));
    for (uint32_t i = 0; i < n; i++) {
        uint32_t carry = (uint32_t)(strchr(b58_alphabet, s[i]) - b58_alphabet);
        for (int j = (int)sizeof(buf) - 1; j >= 0; j--) {
            carry += (uint32_t)buf[j] * 58u;
            buf[j] = (uint8_t)carry;
            carry >>= 8;
        }
        if (carry != 0) return false;       // Longer than an extended key
    }
    sha256_init(&ctx);
    sha256_update(&ctx, buf, 78);
    sha256_final(&ctx, hash);
    sha256_init(&ctx);
    sha256_update(&ctx, hash, 32);
    sha256_final(&ctx, hash);
    if (memcmp(hash, &buf[78], 4) != 0) return false;
    memcpy(out, buf, 78);
    return true;
}

static desc_result_t read_xpub(cursor_t *c, desc_key_t *k) {
    uint8_t raw[78];
    const char *start = c->p;
    while (c->p < c->end && is_b58(*c->p)) c->p++;
    if (!b58check_decode_xkey(start, (uint32_t)(c->p - start), raw)) return DESC_ERR_KEY;

    uint32_t version = (uint32_t)raw[0] << 24 | (uint32_t)raw[1] << 16 | (uint32_t)raw[2] << 8 | raw[3];
    if (version == VER_TPUB || version == VER_VPUB_MS || version == VER_UPUB_MS) return DESC_ERR_NETWORK;
    if (version == VER_YPUB_MS) return DESC_ERR_SCRIPT;
    if (version != VER_XPUB && version != VER_ZPUB_MS) return DESC_ERR_KEY;
    if (raw[45] != 0x02 && raw[45] != 0x03) return DESC_ERR_KEY;

    memcpy(k->chain_code, &raw[13], 32);
    memcpy(k->public_key, &raw[45], 33);
    return DESC_OK;
}

// --- Output descriptor -----------------------------------------------------------

// One step of the BIP380 checksum (a BCH code over GF(32))
static uint64_t desc_polymod(uint64_t c, uint32_t val) {
    uint64_t c0 = c >> 35;
    c = ((c & 0x7FFFFFFFFull) << 5) ^ val;
    if (c0 & 1) c ^= 0xF5DEE51989ull;
    if (c0 & 2) c ^= 0xA9FDCA3312ull;
    if (c0 & 4) c ^= 0x1BAB10E32Dull;
    if (c0 & 8) c ^= 0x3706B1677Aull;
    if (c0 & 16) c ^= 0x644D626FFDull;
    return c;
}

// BIP380 descriptor checksum of s[0..n)
static bool desc_checksum(const char *s, uint32_t n, char out[8]) {
    static const char input_charset[] =
        "0123456789()[],'/*abcdefgh@:$%{}"
        "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
        "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
    static const char checksum_charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    uint64_t c = 1;
    uint32_t cls = 0, cls_count = 0;

    for (uint32_t i = 0; i < n; i++) {
        const char *pos = (s[i] != '\0') ? strchr(input_charset, s[i]) : NULL;
        if (pos == NULL) return false;
        uint32_t p = (uint32_t)(pos - input_charset);
        c = desc_polymod(c, p & 31u);
        cls = cls * 3u + (p >> 5);      // Character class, three per extra symbol
        if (++cls_count == 3) {
            c = desc_polymod(c, cls);
            cls = 0;
            cls_count = 0;
        }
    }
    if (cls_count > 0) c = desc_polymod(c, cls);
    for (int j = 0; j < 8; j++) c = desc_polymod(c, 0);
    c ^= 1;
    for (int j = 0; j < 8; j++) out[j] = checksum_charset[(c >> (5 * (7 - j))) & 31];
    return true;
}

// One key: optional [fingerprint/path] origin, the xpub, then the branches
static desc_result_t parse_desc_key(cursor_t *c, desc_key_t *k) {
    if (accept(c, '[')) {
        if (!read_fingerprint(c, k->fingerprint) || !read_path(c, k) || !accept(c, ']')) return DESC_ERR_FORMAT;
    }
    desc_result_t r = read_xpub(c, k);
    if (r != DESC_OK) return r;
    if (accept_str(c, "/<0;1>/*") || accept_str(c, "/0/*") || accept_str(c, "/1/*")) return DESC_OK;
    return DESC_ERR_PATH;
}

static desc_result_t parse_descriptor(const char *s, uint32_t len, desc_wallet_t *w) {
    cursor_t c = { s, s + len };
    const char *hash = memchr(s, '#', len);

    if (hash != NULL) {
        char expected[8];
        uint32_t body = (uint32_t)(hash - s);
        if (len - body - 1 != 8 || !desc_checksum(s, body, expected) || memcmp(expected, hash + 1, 8) != 0) {
            return DESC_ERR_CHECKSUM;
        }
        w->has_checksum = true;
        c.end = hash;
    }

    if (!accept_str(&c, "wsh(")) {
        // Another script type ("sh(", "wpkh(", "tr("...) or not a descriptor
        const char *p = s;
        while (p < c.end && *p >= 'a' && *p <= 'z') p++;
        return (p > s && p < c.end && *p == '(') ? DESC_ERR_SCRIPT : DESC_ERR_FORMAT;
    }
    if (accept_str(&c, "sortedmulti(")) {
        w->sorted = true;
    } else if (!accept_str(&c, "multi(")) {
        return DESC_ERR_SCRIPT;
    }
    uint32_t m;
    if (!read_uint(&c, &m)) return DESC_ERR_FORMAT;
    while (accept(&c, ',')) {
        if (w->key_count == DESC_MAX_KEYS) return DESC_ERR_TOO_MANY;
        desc_result_t r = parse_desc_key(&c, &w->keys[w->key_count]);
        if (r != DESC_OK) return r;
        w->key_count++;
    }
    if (!accept_str(&c, "))") || c.p != c.end) return DESC_ERR_FORMAT;
    if (m == 0 || m > w->key_count) return DESC_ERR_THRESHOLD;
    w->threshold = (uint8_t)m;
    return DESC_OK;
}

// --- Coldcard multisig setup file -------------------------------------------------

// "Label:" at the start of a line, any case; moves the cursor past it
static bool accept_label(cursor_t *c, const char *label) {
    size_t n = strlen(label);
    if ((size_t)(c->end - c->p) < n) return false;
    for (size_t i = 0; i < n; i++) {
        char a = c->p[i], b = label[i];
        if (a >= 'a' && a <= 'z') a = (char)(a - 32);
        if (a != b) return false;
    }
    c->p += n;
    skip_spaces(c);
    return true;
}

static bool is_line_end(const cursor_t *c) {
    return c->p == c->end;
}

static desc_result_t parse_coldcard(const char *s, uint32_t len, desc_wallet_t *w) {
    desc_key_t origin;              // Derivation of the keys that follow
    uint32_t m = 0, n = 0;
    bool have_policy = false, p2wsh = false;
    const char *line = s, *text_end = s + len;

    memset(&origin, 0, sizeof(origin));
    w->sorted = true;
    while (line < text_end) {
        const char *eol = line;
        while (eol < text_end && *eol != '\n' && *eol != '\r') eol++;
        cursor_t c = { line, eol };
        while (c.end > c.p && (c.end[-1] == ' ' || c.end[-1] == '\t')) c.end--;
        skip_spaces(&c);
        line = eol + 1;

        if (is_line_end(&c) || *c.p == '#') continue;
        if (accept_label(&c, "NAME:")) continue;
        if (accept_label(&c, "POLICY:")) {
            // "2 of 3" (also "2/3")
            if (!read_uint(&c, &m)) return DESC_ERR_FORMAT;
            skip_spaces(&c);
            if (!accept_label(&c, "OF") && !accept(&c, '/')) return DESC_ERR_FORMAT;
            skip_spaces(&c);
            if (!read_uint(&c, &n) || !is_line_end(&c)) return DESC_ERR_FORMAT;
            have_policy = true;
        } else if (accept_label(&c, "DERIVATION:")) {
            if (!accept(&c, 'm') && !accept(&c, 'M')) return DESC_ERR_FORMAT;
            if (!read_path(&c, &origin) || !is_line_end(&c)) return DESC_ERR_FORMAT;
        } else if (accept_label(&c, "FORMAT:")) {
            if (!accept_label(&c, "P2WSH") || !is_line_end(&c)) return DESC_ERR_SCRIPT;
            p2wsh = true;
        } else {
            // "B0B0B0B0: xpub..."
            if (w->key_count == DESC_MAX_KEYS) return DESC_ERR_TOO_MANY;
            desc_key_t *k = &w->keys[w->key_count];
            if (!read_fingerprint(&c, k->fingerprint)) return DESC_ERR_FORMAT;
            skip_spaces(&c);
            if (!accept(&c, ':')) return DESC_ERR_FORMAT;
            skip_spaces(&c);
            k->origin_len = origin.origin_len;
            memcpy(k->origin, origin.origin, sizeof(k->origin));
            desc_result_t r = read_xpub(&c, k);
            if (r != DESC_OK) return r;
            if (!is_line_end(&c)) return DESC_ERR_FORMAT;
            w->key_count++;
        }
    }
    if (!have_policy || w->key_count == 0) return DESC_ERR_FORMAT;
    if (!p2wsh) return DESC_ERR_SCRIPT;     // A missing Format means P2SH for Coldcard
    if (m == 0 || m > n || n != w->key_count) return DESC_ERR_THRESHOLD;
    w->threshold = (uint8_t)m;
    return DESC_OK;
}

// --- Public functions ---------------------------------------------------------

desc_result_t desc_parse(const char *text, uint32_t len, desc_wallet_t *out) {
    const char *p = text, *end = text + len;
    desc_result_t r = DESC_ERR_FORMAT;

    memset(out, 0, sizeof(*out));
    if (len >= 3 && (uint8_t)p[0] == 0xEF && (uint8_t)p[1] == 0xBB && (uint8_t)p[2] == 0xBF) p += 3;

    // The first line that is not empty or a comment decides the format
    while (p < end) {
        const char *eol = p;
        while (eol < end && *eol != '\n' && *eol != '\r') eol++;
        const char *a = p, *b = eol;
        while (a < b && (*a == ' ' || *a == '\t')) a++;
        while (b > a && (b[-1] == ' ' || b[-1] == '\t')) b--;
        if (a < b && *a != '#') {
            cursor_t c = { a, b };
            uint8_t fp[4];
            bool coldcard = accept_label(&c, "NAME:") || accept_label(&c, "POLICY:") ||
                            accept_label(&c, "DERIVATION:") || accept_label(&c, "FORMAT:") ||
                            (read_fingerprint(&c, fp) && (skip_spaces(&c), accept(&c, ':')));
            r = coldcard ? parse_coldcard(p, (uint32_t)(end - p), out)
                         : parse_descriptor(a, (uint32_t)(b - a), out);
            break;
        }
        p = eol + 1;
    }

    // The same key twice would weaken the policy without showing it
    for (uint8_t i = 0; r == DESC_OK && i < out->key_count; i++) {
        for (uint8_t j = i + 1; j < out->key_count; j++) {
            if (memcmp(out->keys[i].public_key, out->keys[j].public_key, 33) == 0) r = DESC_ERR_DUPLICATE;
        }
    }
    if (r != DESC_OK) memset(out, 0, sizeof(*out));
    return r;
}

#define DESC_STR2(x) #x
#define DESC_STR(x) DESC_STR2(x)

const char *desc_error_text(desc_result_t r) {
    switch (r) {
        case DESC_OK:            return "OK";
        case DESC_ERR_SCRIPT:    return "ONLY WSH MULTISIG";
        case DESC_ERR_CHECKSUM:  return "BAD CHECKSUM";
        case DESC_ERR_KEY:       return "BAD XPUB";
        case DESC_ERR_NETWORK:   return "TESTNET KEY";
        case DESC_ERR_TOO_MANY:  return "MAX " DESC_STR(DESC_MAX_KEYS) " COSIGNERS";
        case DESC_ERR_THRESHOLD: return "BAD M-OF-N";
        case DESC_ERR_PATH:      return "KEY PATH NOT /0/*";
        case DESC_ERR_DUPLICATE: return "DUPLICATE KEY";
        default:                 return "UNKNOWN FORMAT";
    }
}

uint32_t desc_witness_script(const uint8_t keys[][33], uint8_t n, uint8_t m, bool sorted, uint8_t *out) {
    uint8_t order[DESC_MAX_KEYS];
    uint32_t len = 0;

    for (uint8_t i = 0; i < n; i++) order[i] = i;
    if (sorted) {
        // BIP67: compressed keys in lexicographic order (insertion sort, n <= 7)
        for (uint8_t i = 1; i < n; i++) {
            uint8_t v = order[i];
            int j = i - 1;
            while (j >= 0 && memcmp(keys[order[j]], keys[v], 33) > 0) {
                order[j + 1] = order[j];
                j--;
            }
            order[j + 1] = v;
        }
    }
    out[len++] = (uint8_t)(0x50 + m);       // OP_m
    for (uint8_t i = 0; i < n; i++) {
        out[len++] = 33;
        memcpy(&out[len], keys[order[i]], 33);
        len += 33;
    }
    out[len++] = (uint8_t)(0x50 + n);       // OP_n
    out[len++] = 0xAE;                      // OP_CHECKMULTISIG
    return len;
}
