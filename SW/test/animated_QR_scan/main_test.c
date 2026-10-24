#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include "../../src/bytewords.h"
#include "../../src/fountain.h"
#include "../../src/sampler.h"

// Standard IEEE 802.3 CRC-32 calculation
static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320U;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc;
}

// Explicit declaration from bytewords.c to avoid warnings
extern int decode_bytewords_pair(char c1, char c2);

// Decodes a full Bytewords string, validates CRC-32, and returns payload length
static size_t bytewords_decode(const char *in, uint8_t *out, size_t max_out_len) {
    size_t in_len = strlen(in);
    if (in_len % 2 != 0) return 0; // Must be pairs of characters
    
    size_t total_bytes = in_len / 2;
    if (total_bytes < 4 || (total_bytes - 4) > max_out_len) return 0;
    
    for (size_t i = 0; i < total_bytes; i++) {
        int val = decode_bytewords_pair(in[i*2], in[i*2+1]);
        if (val < 0) return 0; // Invalid pair
        out[i] = (uint8_t)val;
    }
    
    // Verify CRC-32 (last 4 bytes of decoded data)
    size_t payload_len = total_bytes - 4;
    uint32_t expected_crc = ((uint32_t)out[payload_len] << 24) |
                            ((uint32_t)out[payload_len+1] << 16) |
                            ((uint32_t)out[payload_len+2] << 8)  |
                            ((uint32_t)out[payload_len+3]);
                            
    uint32_t calc_crc = crc32_update(0xFFFFFFFFU, out, payload_len) ^ 0xFFFFFFFFU;
    
    if (calc_crc != expected_crc) return 0;
    
    return payload_len;
}

// Helper to decode a CBOR unsigned integer item
static bool cbor_read_uint(const uint8_t *buf, size_t len, size_t *offset, uint32_t *out_val) {
    if (*offset >= len) return false;
    uint8_t initial = buf[(*offset)++];
    uint8_t major = initial >> 5;
    uint8_t info = initial & 0x1F;

    if (major != 0) return false; // Must be unsigned integer (major type 0)

    if (info < 24) {
        *out_val = info;
        return true;
    } else if (info == 24) {
        if (*offset + 1 > len) return false;
        *out_val = buf[(*offset)++];
        return true;
    } else if (info == 25) {
        if (*offset + 2 > len) return false;
        *out_val = ((uint32_t)buf[*offset] << 8) |
                   ((uint32_t)buf[*offset + 1]);
        *offset += 2;
        return true;
    } else if (info == 26) {
        if (*offset + 4 > len) return false;
        *out_val = ((uint32_t)buf[*offset] << 24) |
                   ((uint32_t)buf[*offset + 1] << 16) |
                   ((uint32_t)buf[*offset + 2] << 8)  |
                   ((uint32_t)buf[*offset + 3]);
        *offset += 4;
        return true;
    }
    return false;
}

// Parses a 5-element BC-UR Fountain CBOR array
static bool parse_ur_cbor_frame(const uint8_t *cbor, size_t len,
                                uint32_t *seq, uint32_t *total,
                                uint32_t *msg_len, uint32_t *checksum,
                                const uint8_t **payload, uint32_t *payload_len) {
    size_t offset = 0;
    if (offset >= len || cbor[offset++] != 0x85) {
        return false; // Expected 5-element CBOR array (0x85)
    }

    if (!cbor_read_uint(cbor, len, &offset, seq)) return false;
    if (!cbor_read_uint(cbor, len, &offset, total)) return false;
    if (!cbor_read_uint(cbor, len, &offset, msg_len)) return false;
    if (!cbor_read_uint(cbor, len, &offset, checksum)) return false;

    if (offset >= len) return false;
    uint8_t bstr_initial = cbor[offset++];
    uint8_t bstr_major = bstr_initial >> 5;
    uint8_t bstr_info = bstr_initial & 0x1F;

    if (bstr_major != 2) return false; // Expected byte string (major type 2)

    uint32_t plen = 0;
    if (bstr_info < 24) {
        plen = bstr_info;
    } else if (bstr_info == 24) {
        if (offset + 1 > len) return false;
        plen = cbor[offset++];
    } else if (bstr_info == 25) {
        if (offset + 2 > len) return false;
        plen = ((uint32_t)cbor[offset] << 8) | ((uint32_t)cbor[offset + 1]);
        offset += 2;
    } else {
        return false;
    }

    if (offset + plen > len) return false;

    *payload = &cbor[offset];
    *payload_len = plen;
    return true;
}

int main(int argc, char *argv[]) {
    const char *filename = (argc > 1) ? argv[1] : "captures_mixed.txt";
    FILE *file = fopen(filename, "r");
    if (!file) {
        printf("ERROR: Could not open file '%s'\n", filename);
        return 1;
    }

    printf("=== UR FOUNTAIN CODE SIMULATOR ===\n");
    fountain_init();

    char line[2048];
    uint32_t frame_num = 0;

    while (fgets(line, sizeof(line), file)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len - 1] == '\r' || line[len - 1] == '\n' || isspace((unsigned char)line[len - 1]))) {
            line[--len] = '\0';
        }
        if (len == 0) continue;

        frame_num++;
        printf("\n--- PROCESSING FRAME %u ---\n", frame_num);

        const char *last_slash = strrchr(line, '/');
        const char *bw_str = last_slash ? (last_slash + 1) : line;

        uint8_t decoded_cbor[1024];
        size_t cbor_len = bytewords_decode(bw_str, decoded_cbor, sizeof(decoded_cbor));
        if (cbor_len == 0) {
            printf("ERROR: Bytewords decoding or CRC failed.\n");
            continue;
        }
        printf("OK: BW CRC valid.\n");

        uint32_t cbor_seq = 0, cbor_total = 0, cbor_msg_len = 0, cbor_checksum = 0, payload_len = 0;
        const uint8_t *payload_ptr = NULL;

        if (!parse_ur_cbor_frame(decoded_cbor, cbor_len, &cbor_seq, &cbor_total, &cbor_msg_len, &cbor_checksum, &payload_ptr, &payload_len)) {
            printf("ERROR: Invalid CBOR Fountain frame structure.\n");
            continue;
        }

        printf("CBOR Header -> SEQ: %u, TOTAL: %u, MSG_LEN: %u, CHK: %08X\n",
               cbor_seq, cbor_total, cbor_msg_len, cbor_checksum);
        printf("CBOR Payload Length: %u bytes\n", payload_len);

        uint32_t degree = 0;
        uint32_t fragments[MAX_FOUNTAIN_PARTS];
        get_fountain_parts(cbor_seq, cbor_total, cbor_msg_len, cbor_checksum, &degree, fragments);

        printf("SAMPLER -> Degree: %u | Fragments: [", degree);
        for (uint32_t i = 0; i < degree; i++) {
            printf("%u%s", fragments[i], (i + 1 < degree) ? ", " : "");
        }
        printf("]\n");

        bool complete = fountain_process_frame(cbor_seq, cbor_total, cbor_msg_len, cbor_checksum, payload_ptr, payload_len);

        printf("FOUNTAIN STATE -> PURE: %u/%u | MIXED_BUF: %u\n",
               fountain_get_pure_count(), fountain_get_total_parts(), fountain_get_mixed_count());

        if (complete) {
            printf("\n>>> RECONSTRUCTION COMPLETE. VERIFYING FINAL CRC...\n");

            uint32_t crc = 0xFFFFFFFFU;
            uint32_t bytes_checked = 0;

            for (uint32_t i = 0; i < cbor_total; i++) {
                uint8_t *part_data = fountain_get_part(i);
                uint32_t part_len = fountain_get_part_length(i);

                if (bytes_checked + part_len > cbor_msg_len) {
                    part_len = cbor_msg_len - bytes_checked;
                }

                if (part_len > 0 && part_data != NULL) {
                    crc = crc32_update(crc, part_data, part_len);
                    bytes_checked += part_len;
                }

                if (bytes_checked >= cbor_msg_len) {
                    break;
                }
            }

            crc ^= 0xFFFFFFFFU;
            printf("CALCULATED CRC: %08X\n", crc);
            printf("EXPECTED CRC  : %08X\n", cbor_checksum);

            if (crc == cbor_checksum) {
                uint8_t *p0 = fountain_get_part(0);
                printf("SUCCESS! Message reconstructed properly. First 4 bytes: %02X %02X %02X %02X\n",
                       p0[0], p0[1], p0[2], p0[3]);
                fclose(file);
                return 0;
            } else {
                printf("CRITICAL ERROR: FINAL CRC MISMATCH. RESETTING BUFFER...\n");
                fountain_init();
            }
        }
    }

    printf("\nFAILURE: Ran out of frames without reconstructing the message.\n");
    fclose(file);
    return 1;
}