#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h> // Required for memset and strlen
#include <time.h>
#include <stdbool.h>

// --- DEVICE CONSTANTS & VARIABLES ---
#define cSIZE_12 12
#define cSIZE_24 24

int size_pointer = cSIZE_12;
uint8_t data_array_256b[32]; // Original input bit array
int card_sequence[150];      
int card_sequence_len = 0;
int card_decks_needed = 0;
int card_view_page = 0;

// Lookup arrays for printing and decoding the cards
const char card_rank_chars[13] = { 'a', '2', '3', '4', '5', '6', '7', '8', '9', 't', 'j', 'q', 'k' };
const char card_suit_chars[4]  = { 'c', 'd', 'h', 's' };

const char * const card_entropy_map[52] = {
    "00000", "00001", "00010", "00011", "00100", "00101", "00110", "00111", "01000", "01001", "01010", "01011", "01100",
    "01101", "01110", "01111", "10000", "10001", "10010", "10011", "10100", "10101", "10110", "10111", "11000", "11001",
    "11010", "11011", "11100", "11101", "11110", "11111", "0000",  "0001",  "0010",  "0011",  "0100",  "0101",  "0110",
    "0111",  "1000",  "1001",  "1010",  "1011",  "1100",  "1101",  "1110",  "1111",  "00",    "01",    "10",    "11"
};

// --- BEAM SEARCH STRUCTURES ---
#define BEAM_WIDTH 8 

typedef struct {
    uint16_t bit_offset;
    uint16_t score;
    uint8_t  usage[52];
    uint8_t  seq[130];
    uint8_t  seq_len;
    uint8_t  max_usage;
} BeamState;

static BeamState current_beams[BEAM_WIDTH];
static BeamState next_beams[BEAM_WIDTH];

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

// --- HELPER: GET CARD VALUE ---
static int get_card(int offset, int len) {
    if (len == 5) return read_bits(data_array_256b, offset, 5);
    if (len == 4) return 32 + read_bits(data_array_256b, offset, 4);
    return 48 + read_bits(data_array_256b, offset, 2);
}

// --- MAIN ENCODING FUNCTION: BEAM SEARCH ---
void calculate_card_encoding(void) {
    int total_bits = (size_pointer == cSIZE_12) ? 128 : 256;
    
    // Initialize the root state
    memset(&current_beams[0], 0, sizeof(BeamState));
    int num_current_beams = 1;
    
    bool all_paths_done = false;

    while (!all_paths_done) {
        all_paths_done = true;
        int max_inserted = 0; 
        
        for (int i = 0; i < num_current_beams; i++) {
            BeamState *curr = &current_beams[i];
            
            if (curr->bit_offset >= total_bits) {
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
            
            all_paths_done = false; 
            int rem = total_bits - curr->bit_offset;
            int lengths[] = {5, 4, 2};
            
            for (int j = 0; j < 3; j++) {
                int len = lengths[j];
                
                if (rem >= len && (rem - len != 1) && (rem - len != 3)) {
                    BeamState cand = *curr;
                    
                    int card = get_card(cand.bit_offset, len);
                    cand.usage[card]++;
                    
                    if (cand.usage[card] > cand.max_usage) {
                        cand.max_usage = cand.usage[card];
                    }
                    
                    cand.seq[cand.seq_len++] = card;
                    cand.bit_offset += len;
                    
                    // Unified Heuristic Score
                    cand.score = ((uint16_t)cand.max_usage << 8) + cand.seq_len;
                    
                    if (max_inserted < BEAM_WIDTH || cand.score < next_beams[BEAM_WIDTH - 1].score) {
                        int pos = (max_inserted < BEAM_WIDTH) ? max_inserted++ : (BEAM_WIDTH - 1);
                        
                        while (pos > 0 && cand.score < next_beams[pos - 1].score) {
                            next_beams[pos] = next_beams[pos - 1];
                            pos--;
                        }
                        next_beams[pos] = cand;
                    }
                }
            }
        }
        
        if (all_paths_done) break;
        
        num_current_beams = max_inserted;
        for (int i = 0; i < num_current_beams; i++) {
            current_beams[i] = next_beams[i];
        }
    }
    
    BeamState *best_path = &current_beams[0];
    
    card_sequence_len = best_path->seq_len;
    for (int i = 0; i < card_sequence_len; i++) {
        card_sequence[i] = best_path->seq[i];
    }
    
    card_decks_needed = best_path->max_usage;
    card_view_page = 0;
}

// --- HELPER: PRINT ARRAY IN HEXADECIMAL ---
void print_hex(uint8_t *data, int num_bytes) {
    for (int i = 0; i < num_bytes; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

// --- HELPER: PRINT CARD SEQUENCE ---
void print_cards() {
    for (int i = 0; i < card_sequence_len; i++) {
        int card_idx = card_sequence[i];
        char rank = card_rank_chars[card_idx % 13];
        char suit = card_suit_chars[card_idx / 13];
        printf("%c%c ", rank, suit);
    }
    printf("\n");
}

// --- HELPER: DECODE CARDS BACK TO BITS ---
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

// --- MAIN TEST BENCH FOR MANUAL VERIFICATION ---
int main() {
    srand((unsigned int)time(NULL));
    uint8_t decoded_array[32];
    
    printf("========================================================\n");
    printf("   BEAM SEARCH MANUAL VERIFICATION: 128-BIT (10 RUNS)   \n");
    printf("========================================================\n");
    
    size_pointer = cSIZE_12;
    int num_bytes_128 = 128 / 8;
    
    for (int t = 1; t <= 10; t++) {
        for (int i = 0; i < num_bytes_128; i++) {
            data_array_256b[i] = rand() % 256;
        }
        
        calculate_card_encoding();
        decode_cards_to_bits(decoded_array, 128);
        
        printf("[Test %2d] \n", t);
        printf("Entropy (HEX): ");
        print_hex(data_array_256b, num_bytes_128);
        printf("Cards (%d):    ", card_sequence_len);
        print_cards();
        printf("Decks needed:  %d\n", card_decks_needed);
        
        // Verify mismatch
        for (int i = 0; i < num_bytes_128; i++) {
            if (data_array_256b[i] != decoded_array[i]) {
                printf(">> ERROR: Decode mismatch at byte %d!\n", i);
            }
        }
        printf("--------------------------------------------------------\n");
    }

    printf("\n\n");
    printf("========================================================\n");
    printf("   BEAM SEARCH MANUAL VERIFICATION: 256-BIT (10 RUNS)   \n");
    printf("========================================================\n");
    
    size_pointer = cSIZE_24;
    int num_bytes_256 = 256 / 8;
    
    for (int t = 1; t <= 10; t++) {
        for (int i = 0; i < num_bytes_256; i++) {
            data_array_256b[i] = rand() % 256;
        }
        
        calculate_card_encoding();
        decode_cards_to_bits(decoded_array, 256);
        
        printf("[Test %2d] \n", t);
        printf("Entropy (HEX): ");
        print_hex(data_array_256b, num_bytes_256);
        printf("Cards (%d):    ", card_sequence_len);
        print_cards();
        printf("Decks needed:  %d\n", card_decks_needed);
        
        // Verify mismatch
        for (int i = 0; i < num_bytes_256; i++) {
            if (data_array_256b[i] != decoded_array[i]) {
                printf(">> ERROR: Decode mismatch at byte %d!\n", i);
            }
        }
        printf("--------------------------------------------------------\n");
    }

    return 0;
}