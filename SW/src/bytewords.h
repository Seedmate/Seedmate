#ifndef BYTEWORDS_H
#define BYTEWORDS_H

#include <stdint.h>
#include <stdbool.h>

// Initializes the fast lookup table in RAM. Call this once at startup.
void init_bytewords_lookup(void);

// Decodes a 2-character Bytewords minimal string into a byte.
// Returns -1 if the character pair is invalid.
int decode_bytewords_pair(char c1, char c2);

#endif // BYTEWORDS_H