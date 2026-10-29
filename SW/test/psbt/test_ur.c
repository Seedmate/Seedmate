// Host-side tests for ur_encode.c. Not part of the firmware.
// 1) Real frames captured from Sparrow are decoded and encoded again: the
//    encoder must reproduce Sparrow's text exactly.
// 2) The signed test PSBT survives an encode/decode round trip.
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "ur_encode.h"
#include "bytewords.h"
#include "fountain.h"
#include "psbt.h"
#include "ur_test_psbt.h"

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { printf("FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); failures++; } } while (0)

static uint32_t cbor_uint(const uint8_t *b, uint32_t *pos) {
    uint8_t ai = b[(*pos)++] & 0x1F;
    uint32_t n = (ai < 24) ? 0 : (ai == 24) ? 1 : (ai == 25) ? 2 : 4;
    uint32_t v = (ai < 24) ? ai : 0;
    while (n--) v = (v << 8) | b[(*pos)++];
    return v;
}

// Decodes the bytewords after the last '/' and checks their CRC32.
// Returns the payload length without the CRC, or -1.
static int decode_words(const char *text, uint8_t *out, uint32_t out_size) {
    const char *w = strrchr(text, '/') + 1;
    uint32_t n = 0;
    while (w[0] && w[1] && !isspace((unsigned char)w[0])) {
        int v = decode_bytewords_pair(w[0], w[1]);
        if (v < 0 || n >= out_size) return -1;
        out[n++] = (uint8_t)v;
        w += 2;
    }
    if (n < 4) return -1;
    uint32_t crc = ur_crc32_update(0xFFFFFFFFu, out, n - 4) ^ 0xFFFFFFFFu;
    uint32_t got = ((uint32_t)out[n - 4] << 24) | ((uint32_t)out[n - 3] << 16) | ((uint32_t)out[n - 2] << 8) | out[n - 1];
    return (crc == got) ? (int)(n - 4) : -1;
}

// Feeds one multipart frame to the fountain decoder; fills the header fields
static bool feed_part(const char *text, uint32_t *seq_len, uint32_t *msg_len, uint32_t *frag_len, bool *complete) {
    uint8_t b[600];
    int n = decode_words(text, b, sizeof(b));
    if (n < 0 || b[0] != 0x85) return false;
    uint32_t pos = 1;
    uint32_t seq = cbor_uint(b, &pos);
    *seq_len = cbor_uint(b, &pos);
    *msg_len = cbor_uint(b, &pos);
    uint32_t checksum = cbor_uint(b, &pos);
    *frag_len = cbor_uint(b, &pos);
    if (pos + *frag_len != (uint32_t)n) return false;
    *complete = fountain_process_frame(seq, *seq_len, *msg_len, checksum, &b[pos], *frag_len);
    return true;
}

static void test_sparrow_frames(const char *path) {
    char lines[8][400];
    uint32_t count = 0, seq_len = 0, msg_len = 0, frag_len = 0;
    bool complete = false;
    FILE *f = fopen(path, "r");
    if (!f) { printf("FAIL cannot open %s\n", path); failures++; return; }

    fountain_init();
    while (count < 8 && fgets(lines[count], sizeof(lines[count]), f)) {
        lines[count][strcspn(lines[count], "\r\n")] = '\0';
        if (lines[count][0] == '\0') continue;
        CHECK(feed_part(lines[count], &seq_len, &msg_len, &frag_len, &complete));
        count++;
    }
    fclose(f);
    CHECK(complete && count >= seq_len);   // The capture may end with mixed parts (seq > n)

    // Message = CBOR byte string holding the PSBT
    uint8_t *msg = fountain_assemble_message(msg_len);
    CHECK(msg != NULL && msg[0] == 0x59);
    if (msg == NULL) return;
    uint32_t psbt_len = ((uint32_t)msg[1] << 8) | msg[2];
    CHECK(psbt_len + 3 == msg_len);

    static uint8_t psbt[1200];
    memcpy(psbt, &msg[3], psbt_len);

    ur_encoder_t e;
    CHECK(ur_encoder_init(&e, psbt, psbt_len, frag_len));
    CHECK(e.seq_len == seq_len && e.fragment_len == frag_len && e.msg_len == msg_len);

    char part[400];
    for (uint32_t i = 0; i < seq_len; i++) {     // Pure parts 1..n; we never emit mixed ones
        CHECK(ur_encoder_part(&e, i + 1, part, sizeof(part)) == strlen(lines[i]));
        if (strcmp(part, lines[i]) != 0) {
            printf("FAIL part %u differs from Sparrow:\n  ours    %s\n  sparrow %s\n", i + 1, part, lines[i]);
            failures++;
        }
    }
    printf("Sparrow frames: %u pure parts of %u bytes reproduced\n", seq_len, frag_len);
}

static void test_round_trip(void) {
    ur_encoder_t e;
    char part[UR_PART_MAX_CHARS(100) + 1];
    uint32_t seq_len = 0, msg_len = 0, frag_len = 0;
    bool complete = false;

    CHECK(ur_encoder_init(&e, ur_test_signed_psbt, sizeof(ur_test_signed_psbt), 100));
    CHECK(e.fragment_len <= 100 && e.seq_len == (e.msg_len + e.fragment_len - 1) / e.fragment_len);

    // Parts come out in any order and repeated, as a looping display would
    fountain_init();
    uint32_t order[] = {2, 4, 2, 1, 3, 4, 1};
    for (uint32_t k = 0; k < sizeof(order) / sizeof(order[0]); k++) {
        uint32_t seq = (order[k] - 1) % e.seq_len + 1;
        uint32_t len = ur_encoder_part(&e, seq, part, sizeof(part));
        CHECK(len > 0 && len <= UR_PART_MAX_CHARS(100) && len == strlen(part));
        CHECK(strncmp(part, "UR:CRYPTO-PSBT/", 15) == 0);
        CHECK(len <= 279);                      // Fits QR version 8, ECC L, alphanumeric
        CHECK(feed_part(part, &seq_len, &msg_len, &frag_len, &complete));
    }
    CHECK(complete);
    uint8_t *msg = fountain_assemble_message(msg_len);
    CHECK(msg != NULL && memcmp(&msg[3], ur_test_signed_psbt, sizeof(ur_test_signed_psbt)) == 0);

    psbt_t p;
    psbt_input_t in;
    CHECK(msg != NULL && psbt_parse(msg, msg_len, &p) == PSBT_OK);      // CBOR wrapper accepted
    CHECK(psbt_get_input(&p, 0, &in) && in.partial_sig_count == 1);
    printf("Round trip: %u parts of %u bytes, longest frame %u chars\n", e.seq_len, e.fragment_len,
           ur_encoder_part(&e, 1, part, sizeof(part)));

    // Single part: no "seq-n/" and the message bytes directly
    static char single[1000];
    CHECK(ur_encoder_init(&e, ur_test_signed_psbt, sizeof(ur_test_signed_psbt), 1000) && e.seq_len == 1);
    CHECK(ur_encoder_part(&e, 1, single, sizeof(single)) > 0 && strchr(single + 15, '/') == NULL);
    static uint8_t raw[600];
    int n = decode_words(single, raw, sizeof(raw));
    CHECK(n == (int)e.msg_len && memcmp(&raw[3], ur_test_signed_psbt, sizeof(ur_test_signed_psbt)) == 0);

    // Bad arguments
    CHECK(ur_encoder_init(&e, ur_test_signed_psbt, sizeof(ur_test_signed_psbt), 100));
    CHECK(ur_encoder_part(&e, 0, part, sizeof(part)) == 0);
    CHECK(ur_encoder_part(&e, e.seq_len + 1, part, sizeof(part)) == 0);
    CHECK(ur_encoder_part(&e, 1, part, 50) == 0);
    CHECK(!ur_encoder_init(&e, ur_test_signed_psbt, 0, 100));
    CHECK(!ur_encoder_init(&e, ur_test_signed_psbt, sizeof(ur_test_signed_psbt), 5));
}

int main(void) {
    init_bytewords_lookup();
    test_sparrow_frames("../animated_QR_scan/captures_pure.txt");
    test_round_trip();
    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures != 0;
}
