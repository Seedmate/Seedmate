#include "fountain.h"
#include "sampler.h"
#include <string.h>

typedef struct {
    uint32_t degree;
    uint32_t fragments[MAX_FOUNTAIN_PARTS];
    uint32_t payload_len;
    uint8_t payload[MAX_PAYLOAD_LEN];
} MixedFrame;

static uint8_t pure_parts[MAX_FOUNTAIN_PARTS][MAX_PAYLOAD_LEN];
static uint32_t pure_lengths[MAX_FOUNTAIN_PARTS];
static bool has_pure[MAX_FOUNTAIN_PARTS];

static MixedFrame mixed_frames[MAX_MIXED_FRAMES];
static uint32_t mixed_count = 0;

static uint32_t total_expected = 0;
static uint32_t pure_count = 0;

void fountain_init(void) {
    memset(has_pure, 0, sizeof(has_pure));
    memset(pure_lengths, 0, sizeof(pure_lengths));
    mixed_count = 0;
    total_expected = 0;
    pure_count = 0;
}

static void xor_payloads(uint8_t *dest, const uint8_t *src, uint32_t len) {
    for (uint32_t i = 0; i < len; i++) {
        dest[i] ^= src[i];
    }
}

// Removes a pure part from a mixed frame using XOR
static void reduce_mixed_frame(MixedFrame *mixed, uint32_t pure_idx) {
    if (mixed->degree == 0) return;

    for (uint32_t i = 0; i < mixed->degree; i++) {
        if (mixed->fragments[i] == pure_idx) {
            xor_payloads(mixed->payload, pure_parts[pure_idx], mixed->payload_len);
            
            // Safe shift without unsigned underflow
            for (uint32_t j = i; j + 1 < mixed->degree; j++) {
                mixed->fragments[j] = mixed->fragments[j + 1];
            }
            mixed->degree--;
            break;
        }
    }
}

// Helper to remove a mixed frame at index idx safely
static void remove_mixed_at(uint32_t idx) {
    if (idx >= mixed_count || mixed_count == 0) return;
    for (uint32_t k = idx; k + 1 < mixed_count; k++) {
        mixed_frames[k] = mixed_frames[k + 1];
    }
    mixed_count--;
}

// Cascades newly found pure parts against all mixed frames
static void process_cascade(void) {
    bool newly_resolved = true;
    
    while (newly_resolved) {
        newly_resolved = false;
        
        uint32_t i = 0;
        while (i < mixed_count) {
            if (mixed_frames[i].degree == 0) {
                remove_mixed_at(i);
                continue; // Do not increment i, next element shifted into i
            }
            
            if (mixed_frames[i].degree == 1) {
                uint32_t part_idx = mixed_frames[i].fragments[0];
                
                if (part_idx < total_expected && !has_pure[part_idx]) {
                    has_pure[part_idx] = true;
                    pure_lengths[part_idx] = mixed_frames[i].payload_len;
                    memcpy(pure_parts[part_idx], mixed_frames[i].payload, mixed_frames[i].payload_len);
                    pure_count++;
                    
                    // Reduce all other mixed frames with this new pure part
                    for (uint32_t j = 0; j < mixed_count; j++) {
                        if (j != i) {
                            reduce_mixed_frame(&mixed_frames[j], part_idx);
                        }
                    }
                    newly_resolved = true;
                }
                
                remove_mixed_at(i);
                continue; // Restart or check newly shifted element at i
            }
            
            i++;
        }
    }
}

bool fountain_process_frame(uint32_t seq, uint32_t total, uint32_t msg_len, uint32_t checksum, const uint8_t *payload, uint32_t payload_len) {
    if (total == 0 || total > MAX_FOUNTAIN_PARTS) return false;
    if (payload_len == 0 || payload_len > MAX_PAYLOAD_LEN) return false;
    
    if (total_expected == 0) {
        total_expected = total;
    } else if (total != total_expected) {
        return false;
    }
    
    if (fountain_is_complete()) return true;

    uint32_t degree = 0;
    uint32_t fragments[MAX_FOUNTAIN_PARTS];
    
    get_fountain_parts(seq, total, msg_len, checksum, &degree, fragments);
    if (degree == 0 || degree > total) return false;

    MixedFrame new_frame;
    new_frame.degree = degree;
    new_frame.payload_len = payload_len;
    memcpy(new_frame.fragments, fragments, degree * sizeof(uint32_t));
    memcpy(new_frame.payload, payload, payload_len);

    // 1. Reduce against already known pure parts
    for (uint32_t i = 0; i < total; i++) {
        if (has_pure[i]) {
            reduce_mixed_frame(&new_frame, i);
        }
    }

    // 2. If reduced to degree 1, save as pure and cascade
    if (new_frame.degree == 1) {
        uint32_t part_idx = new_frame.fragments[0];
        if (part_idx < total && !has_pure[part_idx]) {
            has_pure[part_idx] = true;
            pure_lengths[part_idx] = new_frame.payload_len;
            memcpy(pure_parts[part_idx], new_frame.payload, new_frame.payload_len);
            pure_count++;
            
            for (uint32_t i = 0; i < mixed_count; i++) {
                reduce_mixed_frame(&mixed_frames[i], part_idx);
            }
            process_cascade();
        }
    } 
    // 3. If still mixed (degree > 1), store if not a duplicate
    else if (new_frame.degree > 1) {
        if (mixed_count < MAX_MIXED_FRAMES) {
            mixed_frames[mixed_count++] = new_frame;
        }
    }

    return fountain_is_complete();
}

bool fountain_is_complete(void) {
    return (total_expected > 0 && pure_count == total_expected);
}

uint8_t* fountain_get_part(uint32_t index) {
    if (index >= MAX_FOUNTAIN_PARTS || !has_pure[index]) return NULL;
    return pure_parts[index];
}

uint32_t fountain_get_part_length(uint32_t index) {
    if (index >= MAX_FOUNTAIN_PARTS || !has_pure[index]) return 0;
    return pure_lengths[index];
}

uint32_t fountain_get_total_parts(void) {
    return total_expected;
}

uint32_t fountain_get_pure_count(void) {
    return pure_count;
}

uint8_t* fountain_assemble_message(uint32_t msg_len) {
    if (!fountain_is_complete() || msg_len > sizeof(pure_parts)) return NULL;

    // Part i lives at offset i * MAX_PAYLOAD_LEN and is moved to dst <= that
    // offset, so moving parts in order never overwrites unread data.
    uint8_t *base = &pure_parts[0][0];
    uint32_t dst = 0;
    for (uint32_t i = 0; i < total_expected && dst < msg_len; i++) {
        uint32_t len = pure_lengths[i];
        if (len > msg_len - dst) len = msg_len - dst;   // Drop final padding
        memmove(base + dst, pure_parts[i], len);
        dst += len;
    }
    if (dst != msg_len) return NULL;

    memset(has_pure, 0, sizeof(has_pure));   // Parts are no longer valid
    return base;
}

uint8_t* fountain_scratch_buffer(uint32_t *size) {
    memset(has_pure, 0, sizeof(has_pure));   // Parts are no longer valid
    *size = sizeof(pure_parts);
    return &pure_parts[0][0];
}

uint32_t fountain_get_mixed_count(void) {
    return mixed_count;
}