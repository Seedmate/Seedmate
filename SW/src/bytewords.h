#ifndef BYTEWORDS_H
#define BYTEWORDS_H

#include <stdint.h>
#include <stdbool.h>

// Initializes the fast lookup table in RAM. Call this once at startup.
void init_bytewords_lookup(void);

// Decodes a 2-character Bytewords minimal string into a byte.
// Returns -1 if the character pair is invalid.
int decode_bytewords_pair(char c1, char c2);

// Writes the 2 uppercase characters of a byte's minimal Bytewords form to out.
// Needs no lookup table (the RAM table is only for decoding).
void encode_bytewords_pair(uint8_t value, char *out);

#endif // BYTEWORDS_H