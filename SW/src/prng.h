#ifndef PRNG_H
#define PRNG_H

#include <stdint.h>

// Initializes the PRNG state using the BC-UR standard: SHA256(seq || total || msg_len || checksum)
void prng_seed(uint32_t seq, uint32_t total, uint32_t msg_len, uint32_t checksum);

// Generates the next 64-bit random number in the sequence
uint64_t prng_next(void);

#endif // PRNG_H