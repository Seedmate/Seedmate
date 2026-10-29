/*******************************************************************************
 * Project:     SeedMate
 * File:        ur_encode.h
 *
 * Summary:
 *   Uniform Resources (BCR-2020-005) encoder for "crypto-psbt".
 *
 * Description:
 *   Turns a PSBT into the text of QR frames that wallets such as Sparrow
 *   scan back: "UR:CRYPTO-PSBT/<seq>-<n>/<bytewords>". The message is the
 *   PSBT wrapped in a CBOR byte string; each part is the CBOR array
 *   [seq, n, message length, message CRC32, fragment] plus its own CRC32,
 *   written as minimal Bytewords in uppercase (QR alphanumeric mode).
 *
 *   Only the "pure" parts 1..n are produced; showing them in a loop is
 *   enough for any decoder. Nothing is copied: the CBOR header is generated
 *   on the fly and the PSBT is read in place, so the encoder needs no buffer.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#ifndef UR_ENCODE_H
#define UR_ENCODE_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    const uint8_t *psbt;        // PSBT bytes (not copied)
    uint32_t psbt_len;
    uint8_t hdr[3];             // CBOR byte-string header that wraps the PSBT
    uint8_t hdr_len;
    uint32_t msg_len;           // hdr_len + psbt_len
    uint32_t checksum;          // CRC32 of the whole message
    uint32_t fragment_len;      // Bytes per part (the last one is zero padded)
    uint32_t seq_len;           // Number of parts
} ur_encoder_t;

// Upper bound of a part's text length (NUL excluded) for a given fragment size
#define UR_PART_MAX_CHARS(fragment_len) (15u + 12u + 2u * (21u + (fragment_len) + 4u))

// Splits a PSBT (up to 65535 bytes) into parts of at most max_fragment_len
// bytes, all the same size, as the UR reference implementation does.
bool ur_encoder_init(ur_encoder_t *e, const uint8_t *psbt, uint32_t psbt_len, uint32_t max_fragment_len);

// Writes the text of part seq (1..seq_len) into out, NUL terminated. With a
// single part the "seq-n/" field is omitted. Returns the text length, or 0
// if seq is out of range or out_size is too small.
uint32_t ur_encoder_part(const ur_encoder_t *e, uint32_t seq, char *out, uint32_t out_size);

// CRC-32 (IEEE, reflected) as used by UR and Bytewords. Start with
// 0xFFFFFFFF and XOR the final value with 0xFFFFFFFF.
uint32_t ur_crc32_update(uint32_t crc, const uint8_t *data, uint32_t len);

#endif // UR_ENCODE_H
