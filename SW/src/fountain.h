#ifndef FOUNTAIN_H
#define FOUNTAIN_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_FOUNTAIN_PARTS 35
#define MAX_MIXED_FRAMES 8
#define MAX_PAYLOAD_LEN 250 // Adjust based on your max expected fragment size

// Initialize or reset the decoder state
void fountain_init(void);

// Process an incoming frame. Returns true if the entire dataset is now 100% complete.
bool fountain_process_frame(uint32_t seq, uint32_t total, uint32_t msg_len, uint32_t checksum, const uint8_t *payload, uint32_t payload_len);

// Check if all parts are recovered
bool fountain_is_complete(void);

// Retrieve a resolved part (0-indexed)
uint8_t* fountain_get_part(uint32_t index);
uint32_t fountain_get_part_length(uint32_t index);
uint32_t fountain_get_total_parts(void);
uint32_t fountain_get_pure_count(void);
uint32_t fountain_get_mixed_count(void);

// Joins all recovered parts into one contiguous message of msg_len bytes,
// in place inside the part buffer (no extra RAM). Returns NULL if decoding
// is not complete or msg_len does not fit. Afterwards the individual parts
// are no longer valid: call fountain_init() before decoding again.
uint8_t* fountain_assemble_message(uint32_t msg_len);

#endif // FOUNTAIN_H