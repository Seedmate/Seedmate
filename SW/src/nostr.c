/*******************************************************************************
 * Project:     SeedMate
 * File:        nostr.c
 *
 * Summary:
 *   NIP-19 npub / nsec strings (see nostr.h), on the bech32 encoder of
 *   crypto/segwit_addr.c. Host tests in ../test/derive/ (NIP-06 vectors).
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include <stddef.h>
#include "nostr.h"
#include "crypto/segwit_addr.h"
#include "memzero.h"

bool nostr_bech32(const char *hrp, const uint8_t key[32], char *out) {
    uint8_t data[52];                       // 256 bits in groups of 5, the last one padded
    uint32_t acc = 0;
    int bits = 0, n = 0;

    for (int i = 0; i < 32; i++) {
        acc = (acc << 8) | key[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            data[n++] = (uint8_t)((acc >> bits) & 31u);
        }
    }
    if (bits > 0) data[n++] = (uint8_t)((acc << (5 - bits)) & 31u);
    bool ok = bech32_encode(out, hrp, data, (size_t)n, BECH32_ENCODING_BECH32) == 1;
    memzero(data, sizeof(data));
    acc = 0;
    return ok;
}
