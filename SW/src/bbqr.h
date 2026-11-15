// BBQr ("Better Bitcoin QR", Coinkite, public domain spec): a file split
// over a series of QR codes that can be read in any order. Each code is
// "B$" + encoding + file type + total parts (2 base 36 digits) + part index
// (2 base 36 digits) + data. Encodings: H hex, 2 base32 (RFC 4648, no
// padding), Z raw deflate then base32. Every part but the last decodes to
// the same length, so each one goes straight to its place in the buffer.
// There is no checksum: the caller parses the result strictly and shows it.
// No UI here.
#ifndef BBQR_H
#define BBQR_H

#include <stdint.h>
#include <stdbool.h>

#define BBQR_MAX_PARTS 256u     // Bitmap of 32 bytes; low density Sparrow codes need far fewer

typedef enum {
    BBQR_PART_ADDED = 0,        // New part stored (or a repeated one, same data)
    BBQR_PART_IGNORED,          // The last part before its length can be placed: it will come again
    BBQR_COMPLETE,              // Every part received: call bbqr_finish()
    BBQR_ERR_HEADER,            // Not a valid BBQr header
    BBQR_ERR_ENCODING,          // Encoding other than H, 2 or Z
    BBQR_ERR_TYPE,              // Another file type than the one asked for
    BBQR_ERR_SERIES,            // Encoding, type or count differ from the first part
    BBQR_ERR_DATA,              // Characters that are not of the encoding, or bad length
    BBQR_ERR_MISMATCH,          // A part again with other data, or of another length
    BBQR_ERR_TOO_BIG,           // Does not fit the buffer
    BBQR_ERR_DAMAGED            // The compressed data does not inflate
} bbqr_result_t;

// True if the code starts with the BBQr marker "B$"
bool bbqr_is_part(const char *code, uint32_t len);

// Starts a new series in buf (cap bytes); want_type is the file type
// accepted ('P' PSBT, 'U' text)
void bbqr_init(uint8_t *buf, uint32_t cap, char want_type);

// One code read by the scanner (not NUL terminated)
bbqr_result_t bbqr_add_part(const char *code, uint32_t len);

uint32_t bbqr_received(void);
uint32_t bbqr_total(void);      // 0 until the first part

// After BBQR_COMPLETE: the file is joined (and inflated for Z) at the start
// of buf, at most max_len bytes, and NUL terminated when there is room.
// BBQR_COMPLETE on success, BBQR_ERR_TOO_BIG or BBQR_ERR_DAMAGED otherwise.
bbqr_result_t bbqr_finish(uint32_t max_len, uint32_t *out_len);

#endif // BBQR_H
