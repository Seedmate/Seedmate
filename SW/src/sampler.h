#ifndef SAMPLER_H
#define SAMPLER_H

#include <stdint.h>

// Increase this if you expect PSBTs with more than 50 parts, 
// but 50 is usually plenty for hardware wallets.
#define MAX_UR_TOTAL_PARTS 50 

// Calculates the mathematical recipe for a given frame.
// out_degree: How many original parts are XOR'd in this frame.
// out_fragments: Array filled with the exact indexes (0 to total-1) of those parts.

void get_fountain_parts(uint32_t seq, uint32_t total, uint32_t msg_len, uint32_t checksum, uint32_t *out_degree, uint32_t *out_fragments);

#endif // SAMPLER_H