/*******************************************************************************
 * Project:     SeedMate
 * File:        app_state.h
 *
 * Summary:
 *   Application state variables defined in main.c and read by screens.c.
 *   Including this header in main.c lets the compiler check each declaration
 *   against its definition.
 ******************************************************************************/

#ifndef APP_STATE_H
#define APP_STATE_H

#include <stdint.h>
#include <stdbool.h>
#include "app_defs.h"
#include "sha256.h"            // BYTE

// Menu / navigation
extern int main_pointer;
extern int obfuscation_pointer;
extern bool seedqr_enabled;
extern bool SD_ready;
extern int SD_page;

// Entropy buffer, seed size and entropy progress
extern BYTE data_array_256b[36];
extern int last_input_len;
extern int size_pointer;
extern int bit_count_dice;
extern char dice_string_buf[char_hash_limit];

// SD card sector scratch buffer
extern uint8_t buffer[512];

// BIP85 child seed configuration
extern int bip85_size;
extern int bip85_index;
extern int bip85_cursor;

// Obfuscation configuration
extern int obfus_cursor;
extern int obfus_dir_op;
extern int obfus_amount;

// XOR merge
extern bool capturing_xor_word;
extern int xor_merge_words_available;

// Mnemonic to cards
extern int card_rank_pointer;
extern int card_suit_pointer;
extern int card_field_pointer;
extern uint8_t card_sequence[132];
extern int card_sequence_len;
extern int card_decks_needed;
extern int card_view_page;
extern const char card_rank_chars[13];
extern const char card_suit_chars[4];
extern const char * const card_entropy_map[52];

// Helpers still defined in main.c (candidates for mnemonic.c / sd_card.c)
int read_entropy_bit(const BYTE data_array[36], int bit_index);
int read_11bit_value(const BYTE data_array[36], int index);
const char* get_confirmed_word_from_entropy(const BYTE data_array[36], int index);
bool sd_init(void);
bool sd_read_block(uint32_t sector, uint8_t *buffer);

#endif // APP_STATE_H
