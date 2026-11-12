// Checks tools/ur_psbt_animator.html against the firmware's own code, with
// the frames and QR matrices that gen_frames.js wrote from the page's script:
//  - pure parts: byte-identical to ur_encode.c
//  - every case decodes with fountain.c / sampler.c / prng.c (as main.c does)
//    back to the PSBT file, also from mixed parts only and with lost frames
//  - single part URs: ur_decode_single()
//  - QR matrices: identical to qrcode.c at the same version, ECC and mask
// Build and run: build_test.bat
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ur_encode.h"
#include "bytewords.h"
#include "fountain.h"
#include "qrcode.h"

static int failures = 0;
#define FAIL(...) do { printf("FAIL: "); printf(__VA_ARGS__); printf("\n"); failures++; } while (0)

static uint8_t *read_file(const char *name, uint32_t *len) {
    char path[256];
    snprintf(path, sizeof(path), "../psbt/sparrow/%s", name);
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    static uint8_t buf[8192];
    *len = (uint32_t)fread(buf, 1, sizeof(buf), f);
    fclose(f);
    return buf;
}

static uint32_t get_uint(const uint8_t *p, uint32_t *pos, uint8_t major) {
    uint8_t b = p[(*pos)++];
    if ((b & 0xE0) != major) return 0xFFFFFFFFu;
    uint8_t ai = b & 0x1F;
    if (ai < 24) return ai;
    uint32_t n = ai == 24 ? 1 : ai == 25 ? 2 : ai == 26 ? 4 : 0, v = 0;
    if (n == 0) return 0xFFFFFFFFu;
    while (n--) v = (v << 8) | p[(*pos)++];
    return v;
}

// Bytewords of a part to bytes; checks the CRC32. Returns the CBOR length or 0
static uint32_t decode_body(const char *bw, uint8_t *out, uint32_t cap) {
    uint32_t n = (uint32_t)strlen(bw);
    if (n % 2 || n / 2 > cap || n < 10) return 0;
    for (uint32_t i = 0; i < n / 2; i++) {
        int v = decode_bytewords_pair(bw[2 * i], bw[2 * i + 1]);
        if (v < 0) return 0;
        out[i] = (uint8_t)v;
    }
    uint32_t len = n / 2 - 4;
    uint32_t crc = ur_crc32_update(0xFFFFFFFFu, out, len) ^ 0xFFFFFFFFu;
    uint32_t got = ((uint32_t)out[len] << 24) | ((uint32_t)out[len + 1] << 16) | ((uint32_t)out[len + 2] << 8) | out[len + 3];
    return crc == got ? len : 0;
}

static int hexval(char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; }

int main(void) {
    FILE *f = fopen("frames.txt", "r");
    if (!f) { printf("frames.txt missing: run node gen_frames.js\n"); return 1; }
    static char line[16384];
    char name[128] = "", kind[16] = "";
    uint32_t frag = 0, psbt_len = 0, used = 0;
    const uint8_t *psbt = NULL;
    bool done = false;
    ur_encoder_t enc;
    int cases = 0, frames = 0, pure_checked = 0, qr_checked = 0, singles = 0;
    init_bytewords_lookup();

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        if (line[0] == 'P') {
            if (sscanf(line + 2, "%127[^\t]\t%u\t%15s", name, &frag, kind) != 3) { FAIL("bad line %s", line); continue; }
            psbt = read_file(name, &psbt_len);
            if (!psbt) { FAIL("cannot read %s", name); return 1; }
            ur_encoder_init(&enc, psbt, psbt_len, frag);
            fountain_init();
            done = false;
            used = 0;
            cases++;
        } else if (line[0] == 'F') {
            const char *t = line + 2;
            frames++;
            if (done) continue;                         // The device stops at completion
            used++;
            uint32_t seq, total;
            int off = 0;
            if (sscanf(t, "UR:CRYPTO-PSBT/%u-%u/%n", &seq, &total, &off) != 2 || off == 0) { FAIL("%s: bad header", name); continue; }
            if (seq <= enc.seq_len) {
                static char ref[4096];
                uint32_t n = ur_encoder_part(&enc, seq, ref, sizeof(ref));
                if (n == 0 || strlen(t) != n || memcmp(ref, t, n) != 0) FAIL("%s frag %u: part %u differs from ur_encode.c", name, frag, seq);
                pure_checked++;
            }
            static uint8_t body[2048];
            uint32_t len = decode_body(t + off, body, sizeof(body));
            if (len == 0) { FAIL("%s: part %u bad bytewords or CRC", name, seq); continue; }
            uint32_t p = 0;
            if (body[p++] != 0x85) { FAIL("%s: part %u not array(5)", name, seq); continue; }
            uint32_t cs = get_uint(body, &p, 0), ct = get_uint(body, &p, 0), ml = get_uint(body, &p, 0);
            uint32_t ck = get_uint(body, &p, 0), fl = get_uint(body, &p, 0x40);
            if (cs != seq || ct != total || ml != enc.msg_len || ck != enc.checksum || fl != enc.fragment_len || p + fl != len) {
                FAIL("%s: part %u CBOR fields wrong", name, seq);
                continue;
            }
            done = fountain_process_frame(cs, ct, ml, ck, &body[p], fl);
        } else if (strcmp(line, "END") == 0) {
            if (!done) { FAIL("%s frag %u %s: not complete after %u frames", name, frag, kind, used); continue; }
            uint8_t *msg = fountain_assemble_message(enc.msg_len);
            if (!msg || memcmp(msg + enc.hdr_len, psbt, psbt_len) != 0) FAIL("%s frag %u %s: wrong message", name, frag, kind);
            else printf("ok  %-28s frag %3u, %2u parts, %-5s: decoded after %u frames\n", name, frag, enc.seq_len, kind, used);
        } else if (line[0] == 'S') {
            char *tab = strchr(line, '\t');
            if (!tab) { FAIL("bad S line"); continue; }
            *tab = 0;
            psbt = read_file(line + 2, &psbt_len);
            static uint8_t out[8192];
            if (!psbt || strncmp(tab + 1, "UR:CRYPTO-PSBT/", 15) != 0) { FAIL("single: bad line"); continue; }
            uint32_t n = ur_decode_single(tab + 16, out, sizeof(out));
            uint32_t hl = psbt_len < 24 ? 1 : psbt_len < 256 ? 2 : 3;
            if (n != psbt_len + hl || memcmp(out + hl, psbt, psbt_len) != 0) FAIL("single part %s", line + 2);
            singles++;
        } else if (line[0] == 'Q') {
            int v, ecc, mask;
            char *t1 = strchr(line, '\t'), *t2 = t1 ? strchr(t1 + 1, '\t') : NULL;
            if (!t2 || sscanf(line + 2, "%d %d %d", &v, &ecc, &mask) != 3) { FAIL("bad Q line"); continue; }
            *t2 = 0;
            const char *text = t1 + 1, *hex = t2 + 1;
            static uint8_t modules[4096];
            QRCode q;
            qrcode_initText(&q, modules, (uint8_t)v, (uint8_t)ecc, text);
            uint32_t nbytes = qrcode_getBufferSize((uint8_t)v);
            bool same = strlen(hex) == 2 * nbytes && q.mask == mask;
            for (uint32_t i = 0; same && i < nbytes; i++)
                if (((hexval(hex[2 * i]) << 4) | hexval(hex[2 * i + 1])) != modules[i]) same = false;
            if (!same) FAIL("QR v%d ecc %d (C mask %d, page mask %d) differs: %.40s", v, ecc, q.mask, mask, text);
            qr_checked++;
        }
    }
    fclose(f);
    printf("%d cases, %d frames, %d pure parts equal to ur_encode.c, %d single parts, %d QR codes equal to qrcode.c\n",
           cases, frames, pure_checked, singles, qr_checked);
    if (failures) printf("%d FAILURES\n", failures);
    else printf("ALL PASSED\n");
    return failures != 0;
}
