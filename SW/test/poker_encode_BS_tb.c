#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

// You can tweak this value. 
// BEAM_WIDTH 12 uses ~4.5 KB of RAM. 
// BEAM_WIDTH 8 uses ~3.0 KB of RAM.
#define BEAM_WIDTH 8

// Highly compact state structure to fit inside PIC RAM limits
typedef struct {
    uint16_t bit_offset;
    uint16_t score;
    uint8_t  usage[52];
    uint8_t  seq[130];
    uint8_t  seq_len;
    uint8_t  max_usage;
} BeamState;

// Define the two state buffers globally or statically to avoid Stack Overflow
static BeamState current_beams[BEAM_WIDTH];
static BeamState next_beams[BEAM_WIDTH];

// --- DEVICE CONSTANTS & VARIABLES ---
#define cSIZE_12 12
#define cSIZE_24 24

int size_pointer = cSIZE_12;
uint8_t data_array_256b[32]; // Original input bit array
int card_sequence[150];      
int card_sequence_len = 0;
int card_decks_needed = 0;
int card_view_page = 0;

// Lookup arrays provided by the user
const char card_rank_chars[13] = { 'a', '2', '3', '4', '5', '6', '7', '8', '9', 't', 'j', 'q', 'k' };
const char card_suit_chars[4]  = { 'c', 'd', 'h', 's' };

const char * const card_entropy_map[52] = {
    "00000", "00001", "00010", "00011", "00100", "00101", "00110", "00111", "01000", "01001", "01010", "01011", "01100",
    "01101", "01110", "01111", "10000", "10001", "10010", "10011", "10100", "10101", "10110", "10111", "11000", "11001",
    "11010", "11011", "11100", "11101", "11110", "11111", "0000",  "0001",  "0010",  "0011",  "0100",  "0101",  "0110",
    "0111",  "1000",  "1001",  "1010",  "1011",  "1100",  "1101",  "1110",  "1111",  "00",    "01",    "10",    "11"
};

// --- HELPER: READ BITS FROM ARRAY ---
unsigned int read_bits(uint8_t *array, int offset, int len) {
    unsigned int result = 0;
    for (int i = 0; i < len; i++) {
        int bit_idx = offset + i;
        int byte_idx = bit_idx / 8;
        int bit_in_byte = 7 - (bit_idx % 8); // MSB first
        int bit = (array[byte_idx] >> bit_in_byte) & 1;
        result = (result << 1) | bit;
    }
    return result;
}
#include <stdint.h>
#include <stdint.h>
// --- HELPER: GET CARD VALUE ---
static int get_card(int offset, int len) {
    if (len == 5) return read_bits(data_array_256b, offset, 5);
    if (len == 4) return 32 + read_bits(data_array_256b, offset, 4);
    return 48 + read_bits(data_array_256b, offset, 2);
}

// --- MAIN FUNCTION: BEAM SEARCH ENCODING ---
void calculate_card_encoding(void) {
    int total_bits = (size_pointer == cSIZE_12) ? 128 : 256;
    
    // Initialize the root state
    memset(&current_beams[0], 0, sizeof(BeamState));
    int num_current_beams = 1;
    
    bool all_paths_done = false;

    while (!all_paths_done) {
        all_paths_done = true;
        int max_inserted = 0; // Tracks how many candidates we have in next_beams
        
        for (int i = 0; i < num_current_beams; i++) {
            BeamState *curr = &current_beams[i];
            
            // If this specific path has already reached the target, 
            // just pass it forward to the next generation without expanding.
            if (curr->bit_offset >= total_bits) {
                // Top-N Insertion logic for finished paths
                if (max_inserted < BEAM_WIDTH || curr->score < next_beams[BEAM_WIDTH - 1].score) {
                    int pos = (max_inserted < BEAM_WIDTH) ? max_inserted++ : (BEAM_WIDTH - 1);
                    while (pos > 0 && curr->score < next_beams[pos - 1].score) {
                        next_beams[pos] = next_beams[pos - 1];
                        pos--;
                    }
                    next_beams[pos] = *curr;
                }
                continue;
            }
            
            // If at least one path is still growing, we are not done
            all_paths_done = false; 
            int rem = total_bits - curr->bit_offset;
            int lengths[] = {5, 4, 2};
            
            // Branch out this path into 3 new possible futures
            for (int j = 0; j < 3; j++) {
                int len = lengths[j];
                
                if (rem >= len && (rem - len != 1) && (rem - len != 3)) {
                    // Create a candidate state based on the current path
                    BeamState cand = *curr;
                    
                    int card = get_card(cand.bit_offset, len);
                    cand.usage[card]++;
                    
                    if (cand.usage[card] > cand.max_usage) {
                        cand.max_usage = cand.usage[card];
                    }
                    
                    cand.seq[cand.seq_len++] = card;
                    cand.bit_offset += len;
                    
                    // Unified Heuristic Score:
                    // Primary metric: Deck usage (shifted by 8 to make it dominant)
                    // Secondary metric: Sequence length (rewards paths that use 5-bit jumps)
                    cand.score = ((uint16_t)cand.max_usage << 8) + cand.seq_len;
                    
                    // TOP-N INSERTION: Keep only the absolute best BEAM_WIDTH paths
                    if (max_inserted < BEAM_WIDTH || cand.score < next_beams[BEAM_WIDTH - 1].score) {
                        int pos = (max_inserted < BEAM_WIDTH) ? max_inserted++ : (BEAM_WIDTH - 1);
                        
                        // Shift worse candidates down
                        while (pos > 0 && cand.score < next_beams[pos - 1].score) {
                            next_beams[pos] = next_beams[pos - 1];
                            pos--;
                        }
                        // Insert new candidate in its sorted position
                        next_beams[pos] = cand;
                    }
                }
            }
        }
        
        if (all_paths_done) break;
        
        // Prepare current_beams for the next depth level
        num_current_beams = max_inserted;
        for (int i = 0; i < num_current_beams; i++) {
            current_beams[i] = next_beams[i];
        }
    }
    
    // The very best path will naturally sit at index 0
    BeamState *best_path = &current_beams[0];
    
    // Copy the winning path back to the global device variables
    card_sequence_len = best_path->seq_len;
    for (int i = 0; i < card_sequence_len; i++) {
        card_sequence[i] = best_path->seq[i];
    }
    
    card_decks_needed = best_path->max_usage;
    card_view_page = 0;
}

// --- STEP 2: DECODE CARDS BACK TO BITS ---
void decode_cards_to_bits(uint8_t *out_array, int total_bits) {
    memset(out_array, 0, 32);
    int bit_offset = 0;
    
    for (int i = 0; i < card_sequence_len; i++) {
        int card_idx = card_sequence[i];
        const char *bin_str = card_entropy_map[card_idx];
        int len = strlen(bin_str); 
        
        for (int b = 0; b < len; b++) {
            if (bit_offset >= total_bits) break; 
            
            int bit_val = bin_str[b] - '0'; 
            
            int byte_idx = bit_offset / 8;
            int bit_in_byte = 7 - (bit_offset % 8);
            
            if (bit_val == 1) {
                out_array[byte_idx] |= (1 << bit_in_byte);
            }
            bit_offset++;
        }
    }
}

// --- HELPER: PRINT DECK STATISTICS ---
void print_deck_stats(int *stats, int num_tests) {
    printf("----------------------------------------\n");
    printf("DECK USAGE STATISTICS (Out of %d runs)\n", num_tests);
    printf("----------------------------------------\n");
    for (int i = 1; i <= 8; i++) {
        double percentage = (stats[i] / (double)num_tests) * 100.0;
        printf("%d Decks needed: %6d runs (%5.2f%%)\n", i, stats[i], percentage);
    }
    if (stats[9] > 0) {
        printf(">8 Decks needed: %6d runs\n", stats[9]);
    }
    printf("----------------------------------------\n\n");
}

// --- MAIN TEST BENCH ---
int main() {
    srand((unsigned int)time(NULL));
    uint8_t decoded_array[32]; 
    
    int num_tests_128 = 30000;
    int num_tests_256 = 30000;
    
    // Arrays to track how many runs required X decks (index 1 to 8, index 9 is for >8)
    int deck_stats_128[10] = {0};
    int deck_stats_256[10] = {0};
    
    printf("Starting round-trip bit equivalence test with deck statistics...\n\n");

    // ----------------------------------------------------
    // TEST 1: 128-BIT ROUND-TRIP
    // ----------------------------------------------------
    printf("Testing 128-bit encoding/decoding (%d iterations)...\n", num_tests_128);
    size_pointer = cSIZE_12;
    int num_bytes_128 = 128 / 8; 
    
    for (int t = 0; t < num_tests_128; t++) {
        // 1. Generate random bits
        for (int i = 0; i < num_bytes_128; i++) {
            data_array_256b[i] = rand() % 256;
        }
        
        // 2. Encode to cards
        calculate_card_encoding();
        
        // Track deck usage
        if (card_decks_needed >= 1 && card_decks_needed <= 8) {
            deck_stats_128[card_decks_needed]++;
        } else if (card_decks_needed > 8) {
            deck_stats_128[9]++;
        }
        
        // 3. Decode & Verify
        decode_cards_to_bits(decoded_array, 128);
        for (int i = 0; i < num_bytes_128; i++) {
            if (data_array_256b[i] != decoded_array[i]) {
                printf("FAIL at 128-bit mode (Iteration %d)!\n", t);
                return 1;
            }
        }
    }
    printf("SUCCESS: All %d iterations matched perfectly in 128-bit mode!\n", num_tests_128);
    print_deck_stats(deck_stats_128, num_tests_128);


    // ----------------------------------------------------
    // TEST 2: 256-BIT ROUND-TRIP
    // ----------------------------------------------------
    printf("Testing 256-bit encoding/decoding (%d iterations)...\n", num_tests_256);
    size_pointer = cSIZE_24;
    int num_bytes_256 = 256 / 8; 
    
    for (int t = 0; t < num_tests_256; t++) {
        // 1. Generate random bits
        for (int i = 0; i < num_bytes_256; i++) {
            data_array_256b[i] = rand() % 256;
        }
        
        // 2. Encode to cards
        calculate_card_encoding();
        
        // Track deck usage
        if (card_decks_needed >= 1 && card_decks_needed <= 8) {
            deck_stats_256[card_decks_needed]++;
        } else if (card_decks_needed > 8) {
            deck_stats_256[9]++;
        }
        
        // 3. Decode & Verify
        decode_cards_to_bits(decoded_array, 256);
        for (int i = 0; i < num_bytes_256; i++) {
            if (data_array_256b[i] != decoded_array[i]) {
                printf("FAIL at 256-bit mode (Iteration %d)!\n", t);
                return 1;
            }
        }
    }
    printf("SUCCESS: All %d iterations matched perfectly in 256-bit mode!\n", num_tests_256);
    print_deck_stats(deck_stats_256, num_tests_256);

    printf("ALL TESTS PASSED!\n");
    return 0;
}