/*******************************************************************************
 * Project:     SeedMate
 * File:        main.c
 *
 * Summary:
 *   Main application entry point for the SeedMate firmware.
 *
 * Description:
 *   This firmware runs on a PIC32MM-based platform with TFT display, buttons,
 *   SD card support, QR generation, and entropy capture features. It provides
 *   an offline workflow to create, load, transform, split, merge, display,
 *   and export BIP39-compatible seed data.
 *
 * Main responsibilities:
 *   - Initialize hardware and application services
 *   - Handle user input and screen navigation
 *   - Capture entropy from supported input sources
 *   - Manage seed generation and validation
 *   - Support XOR and Shamir-based operations
 *   - Export data through QR and SD card features
 *
 * Notes:
 *   - This project is intended for offline use
 *   - Security-sensitive data should be handled carefully at all times
 *
 * Author:      Seedmate
 * Date:        01/10/2026
 * Version:     v1.8                               
 * License
 * 
 * This project is licensed under the MIT License.
 * 
 * MIT License
 * 
 * Copyright (c) 2026 Seedmate
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 ******************************************************************************/

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************

#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include "definitions.h"                // SYS function prototypes
#include "SPI.h"                        // SPI functions
#include "TFT.h"                        // TFT functions
#include "sha256.h"
#include "sha512.h"
//#include "screens.h"
#include "words_opt.h"
#include <string.h>
#include "SSS/shamir.h"
#include "QRCode-master/src/qrcode.h"
#include "memzero.h"
#include "bytewords.h"
#include "prng.h"
#include "sampler.h"
#include "fountain.h"
#include "app_defs.h"
#include "app_state.h"
#include "screens.h"
#include "psbt.h"
#include "sd_files.h"
#include "ur_encode.h"
#include "ur_test_psbt.h"




    #include "crypto/ripemd160.h"
    #include "crypto/bignum.h"
    #include "crypto/bip32.h"
    #include "crypto/secp256k1.h"       
    #include "crypto/segwit_addr.h"     
    
    typedef struct {
        char address[90];
        char fingerprint[9]; 
        char xpub[112];
        char zpub[112];
    } BitcoinBip84Result;

    //SD
    #define SD_CS     PORTBbits.RB5

    // Pin mapping
    #define LED       PORTAbits.RA2   // CPU activity led

    // LCD
    #define LED_LCD   PORTBbits.RB10  // TFT backlight control

    // Buttons
    #define BT1       PORTBbits.RB2   // Button 1
    #define BT2       PORTCbits.RC0  // Button 2
    #define BT_OK     PORTCbits.RC1  // Button 3
    #define BT4       PORTBbits.RB3   // Button 4
    #define BT5       PORTCbits.RC2  // Button 5
    #define BT6       PORTAbits.RA4   // Button 6

    // ============================================================================
    // Bootloader Shared Memory Flags
    // ============================================================================
    #define UPDATE_FLAG_ADDR ((volatile uint32_t *)0x80007F00)
    #define MAGIC_WORD_UPDATE 0x55AA1234

    




bool seedqr_enabled = false;
int settings_pointer = 0;
















// SSS limits

// Set to 1 to enable SSS coefficient debugging screen. Set to 0 for production.
#define SSS_DEBUG 0


#define SHA512_SIZE 64          // SHA512 output size
#define BLOCK_SIZE 128 // SHA512 block size


char bip84_passphrase[200] = {0}; // Holds the optional BIP39 passphrase


//Text editor
#define KBD_LETTER_SPACING 8

#define LAYER_ABC 0
#define LAYER_ABC_UPPER 1
#define LAYER_NUM 2
#define LAYER_SYM 3
const char kbd_abc[27] = "abcdefghijklmnopqrstuvwxyz";
const char kbd_ABC[27] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
// Fixed: Padded with a trailing space to reach 26 slots, preventing ghost chars
const char kbd_num[27] = "0123456789.,!?+-*/=()@#$%&"; // Exactly 26 chars
const char kbd_sym[27] = "<>[]{}~^|_\\\"';:.,!?+-*/=@#"; // Exactly 26 chars

#define PASSPHRASE_MODE false
#define NOTE_MODE true


int erase_pointer = 0;
int main_pointer = 0;
int obfuscation_pointer =0;
int sss_pointer = 0;
int resource_pointer = 0;
uint8_t  selected_share_id = 1;
int shares_loaded = 0;

int bip85_size = cSIZE_12;
int bip85_index = 0;
int bip85_cursor = 0;

int bip84_menu_pointer = 0;
static int sign_menu_pointer = 0;
uint32_t bip84_address_index = 0;
int bip84_extended_key_page = 0;
bool bip84_qr_return_to_menu = false;
bool bip84_qr_return_to_info = false;

bool bip84_account_cached = false;
char bip84_cached_xpub[115] = {0}; 
char bip84_cached_zpub[115] = {0}; 

HDNode bip84_receive_node_cache;
HDNode bip84_change_node_cache;

HDNode bip84_account_node;
uint32_t bip84_master_fingerprint = 0;
uint32_t bip84_account_parent_fingerprint = 0;

// XOR Globals moved from main()
int xor_pointer = 0;
BYTE xor_merge_word1[32] = {0};
BYTE xor_merge_word2[32] = {0};
BYTE xor_merge_word3[32] = {0};
int xor_merge_words_available = 0;

int extract_word_offset = 0;
int triple_view_state = 0;
BYTE triple_backup_256b[36] = {0};

int dice_x_pointer = 0;
int dice_y_pointer = 25;

int dice_mode_pointer = 0;
int hash_mode_pointer = 0;

char dice_string_buf[char_hash_limit] = {0};
int dice_input_idx = 0; // 0-5 for '1'-'6', 6 for DONE

BYTE data_array_256b[36] = {0}; // Increased buffer size to handle excess bits tracking
int size_pointer = 0;
int bit_count_dice = 0;
int entropy_bits = 0;
int last_input_len = 0; // Tracks the length of the most recent entropy input

bool capturing_xor_word = false; // Flag to hijack WRITE_WORD behavior
int obfus_xor_word_idx = 0;

int seed_pointer = 0;
int card_rank_pointer = 0;
int card_suit_pointer = 0;
int card_field_pointer = 0;
int card_history_count = 0;
uint16_t card_history_start_bits[cCARD_MAX_HISTORY] = {0};
uint8_t card_history_bit_len[cCARD_MAX_HISTORY] = {0};


const char card_rank_chars[13] = { 'a', '2', '3', '4', '5', '6', '7', '8', '9', 't', 'j', 'q', 'k' };
const char card_suit_chars[4] = { 'c', 'd', 'h', 's' };
const char * const card_entropy_map[52] = {
    "00000", "00001", "00010", "00011", "00100", "00101", "00110", "00111", "01000", "01001", "01010", "01011", "01100",
    "01101", "01110", "01111", "10000", "10001", "10010", "10011", "10100", "10101", "10110", "10111", "11000", "11001",
    "11010", "11011", "11100", "11101", "11110", "11111", "0000",  "0001",  "0010",  "0011",  "0100",  "0101",  "0110",
    "0111",  "1000",  "1001",  "1010",  "1011",  "1100",  "1101",  "1110",  "1111",  "00",    "01",    "10",    "11"
};

#define NCOEFF 5
#define BYTES_PER_COEFF 32 // Same as LEN
#define TOTAL_BYTES (NCOEFF * BYTES_PER_COEFF)

uint8_t c0[BYTES_PER_COEFF] = { 0 };  // len = 1
uint8_t c1[BYTES_PER_COEFF] = { 0 };
uint8_t c2[BYTES_PER_COEFF] = { 0 };
uint8_t c3[BYTES_PER_COEFF] = { 0 };
uint8_t c4[BYTES_PER_COEFF] = { 0 };

// Circular buffer to accumulate entropy from button presses
static uint8_t sss_entropy_pool[32] = {0};
static uint8_t sss_pool_idx = 0;

// Pointer table to avoid a switch
uint8_t * const coefficient_buffers[5] = { c0, c1, c2, c3, c4 };
static void clear_string(char *text);
static void remove_last_char(char *text);
static char *add_char(char *text, int letter_index, size_t capacity);
static char *add_char_dice(char *text, int num, size_t capacity);
static const char *search_unique_prefix(const char *prefix, char *result, size_t result_size);
static BYTE *append_checksum(BYTE *data_array, int N);
static void write_11bit_value(BYTE *buffer, int index, int value);
static bool matches_last_word_checksum(BYTE *data_array, char *word_user, int sel_size);

static void shift_left(BYTE *data, int N);
static void shift_right(BYTE *data, int N);
static void not_operator(BYTE *data, int N);
void set_bit(BYTE data_array[36], int bit_index, int value);
const char* get_confirmed_word_from_entropy(const BYTE data_array[36], int index);
int read_11bit_value(const BYTE data_array[36], int index);
void print_checksum_screen(void);
void print_triple_checksum(int word_target);
const char* get_word(int index);
int get_next_valid_key(int current_idx, int step, const char *current_word, bool ok_is_valid);
int get_nearest_valid_key(int current_idx, const char *current_word, bool ok_is_valid);

// Advanced screen redraw logic to seal memory leak and handle navigation states natively
void redraw_show_seed_with_offset(void);
void refresh_triple_view(void);
void extract_11bit_groups(BYTE *data, size_t size);

// Prototypes for smart keyboard prediction
static void get_valid_next_letters(const char *prefix, bool *valid_letters);
void print_keyboard_with_validation(int index, bool word_found, const char *current_word);

int find_word_index(const char *word);


// Mnemonic to Cards Globals
uint8_t card_sequence[132];
int card_sequence_len = 0;
int card_decks_needed = 0;
int card_view_page = 0;

// --- UR ANIMATED QR (SPARROW PSBT) GLOBALS ---
//#define MAX_UR_TOTAL_PARTS   30
#define MAX_UR_PAYLOAD_LEN   400


// ============================================================================
// BIP85 Derivation Engine
// ============================================================================
// -------------------- HMAC-SHA512 --------------------

void HmacSha512(const BYTE *key, size_t keyLen,
                const BYTE *data, size_t dataLen,
                BYTE *out) {
    BYTE k_ipad[BLOCK_SIZE];
    BYTE k_opad[BLOCK_SIZE];
    SHA512_HASH innerHash;
    SHA512_HASH outerHash;
    Sha512Context ctx;

    if (keyLen > BLOCK_SIZE) {
        Sha512Initialise(&ctx);
        Sha512Update(&ctx, key, keyLen);
        Sha512Finalise(&ctx, &innerHash);
        key = innerHash.bytes;
        keyLen = SHA512_SIZE;
    }

    memset(k_ipad, 0x36, BLOCK_SIZE);
    memset(k_opad, 0x5c, BLOCK_SIZE);

    for (size_t i = 0; i < keyLen; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    // Inner hash
    Sha512Initialise(&ctx);
    Sha512Update(&ctx, k_ipad, BLOCK_SIZE);
    Sha512Update(&ctx, data, dataLen);
    Sha512Finalise(&ctx, &innerHash);

    // Outer hash
    Sha512Initialise(&ctx);
    Sha512Update(&ctx, k_opad, BLOCK_SIZE);
    Sha512Update(&ctx, innerHash.bytes, SHA512_SIZE);
    Sha512Finalise(&ctx, &outerHash);

    memcpy(out, outerHash.bytes, SHA512_SIZE);
}
// -------------------- PBKDF2-HMAC-SHA512 --------------------
void PBKDF2_HMAC_SHA512(const char *password, const char *salt,
                        uint32_t iterations, BYTE *output, size_t dkLen) {
    uint32_t blockCount = (dkLen + SHA512_SIZE - 1) / SHA512_SIZE;
    BYTE U[SHA512_SIZE];
    BYTE T[SHA512_SIZE];
    BYTE saltBlock[32]; 
    size_t saltLen = strlen(salt);

    for (uint32_t i = 1; i <= blockCount; i++) {
        memcpy(saltBlock, salt, saltLen);
        saltBlock[saltLen + 0] = (i >> 24) & 0xFF;
        saltBlock[saltLen + 1] = (i >> 16) & 0xFF;
        saltBlock[saltLen + 2] = (i >> 8) & 0xFF;
        saltBlock[saltLen + 3] = i & 0xFF;

        HmacSha512((const BYTE *)password, strlen(password),
                   saltBlock, saltLen + 4, U);
        memcpy(T, U, SHA512_SIZE);

        for (uint32_t j = 2; j <= iterations; j++) {
            HmacSha512((const BYTE *)password, strlen(password),
                       U, SHA512_SIZE, U);
            for (int k = 0; k < SHA512_SIZE; k++) {
                T[k] ^= U[k];
            }
            
            // Keep the system and watchdog happy during the heavy hash loop
            if (j % 16 == 0) {
                SYS_Tasks(); 
            }
            
            // Simple UI Progress Bar at the bottom of the screen
            if (j % 102 == 0) {
                int chunk = j / 102; // Yields 1 through 20
                // Draw progress bar from x=10 to x=150 at y=115
                rectan(10 + ((chunk - 1) * 7), 121, 10 + (chunk * 7), 124, ST7735_GREEN);
            }
        }

        size_t offset = (i - 1) * SHA512_SIZE;
        size_t toCopy = (dkLen - offset < SHA512_SIZE) ? (dkLen - offset) : SHA512_SIZE;
        memcpy(output + offset, T, toCopy);
    }
}


static void get_mnemonic_string(char *out_str) {
    int target_words = (size_pointer == cSIZE_12) ? 12 : 24;
    int entropy_bytes = (size_pointer == cSIZE_12) ? 16 : 32;
    
    // Generate full seed data including the 4/8-bit SHA256 checksum
    BYTE *c_buf = append_checksum(data_array_256b, entropy_bytes);
    
    int pos = 0;
    out_str[0] = '\0';
    if (c_buf == NULL) return;
    

    unsigned int group = 0;
    int bit_index = 0;
    int words_extracted = 0;
    
    for (size_t i = 0; i < (entropy_bytes + 1) * 8; i++) {
        int byte_idx = i / 8;
        int bit_pos = 7 - (i % 8);
        int bit = (c_buf[byte_idx] >> bit_pos) & 1;

        group = (group << 1) | bit;
        bit_index++;

        // Once 11 bits are collected, append the word
        if (bit_index == 11) {
            const char *w = get_word(group);
        if (words_extracted > 0) {
            out_str[pos++] = ' ';
        }
        if (w != NULL) {
            while (*w != '\0') {
                out_str[pos++] = *w++;
            }
        }
        out_str[pos] = '\0';
            words_extracted++;
            group = 0;
            bit_index = 0;
            
            // Break early to ignore trailing bits in the checksum byte
            if (words_extracted == target_words) break;
        }
    }
}

static void add_256_mod_n(uint8_t *out, const uint8_t *a, const uint8_t *b) {
    // SECP256K1 curve order (n)
    const uint8_t n[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
        0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
        0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
    };
    uint16_t carry = 0;
    uint8_t res[32];
    
    // 256-bit addition
    for (int i = 31; i >= 0; i--) {
        carry += a[i] + b[i];
        res[i] = carry & 0xFF;
        carry >>= 8;
    }
    
    // Check if result >= n
    bool over = false;
    if (carry > 0) {
        over = true;
    } else {
        for (int i = 0; i < 32; i++) {
            if (res[i] > n[i]) { over = true; break; }
            if (res[i] < n[i]) { break; }
        }
    }
    
    // Subtract n if overflowed (Strict portable wrapping)
    if (over) {
        int borrow = 0;
        for (int i = 31; i >= 0; i--) {
            int diff = (int)res[i] - (int)n[i] - borrow;
            if (diff < 0) {
                diff += 256;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out[i] = (uint8_t)diff;
        }
    } else {
        for (int i = 0; i < 32; i++) {
            out[i] = res[i];
        }
    }
}


static void process_bip85_derivation(void) {
    char mnemonic_str[250]; 
    get_mnemonic_string(mnemonic_str);
   
    uint8_t seed[64];
    PBKDF2_HMAC_SHA512(mnemonic_str, "mnemonic", 2048, seed, 64);
    
    uint8_t I[64];
    HmacSha512((uint8_t *)"Bitcoin seed", 12, seed, 64, I);
    
    uint8_t k[32];
    uint8_t c[32];
    
    // Initialize k and c from master seed
    memcpy(k, I, 32);
    memcpy(c, I + 32, 32);
    
    uint32_t path[5] = {
        0x80000000 | 83696968,
        0x80000000 | 39,
        0x80000000 | 0,
        0x80000000 | ((bip85_size == cSIZE_12) ? 12 : 24),
        0x80000000 | bip85_index
    };
    
    for (int i = 0; i < 5; i++) {
        uint8_t data[37];
        data[0] = 0x00;
        memcpy(data + 1, k, 32);
        data[33] = (path[i] >> 24) & 0xFF;
        data[34] = (path[i] >> 16) & 0xFF;
        data[35] = (path[i] >> 8) & 0xFF;
        data[36] = path[i] & 0xFF;
        
        HmacSha512(c, 32, data, 37, I);
        
        // Proper BIP32 child key addition mod n
        add_256_mod_n(k, I, k); // k_i = (I_L + k_par) % n
        memcpy(c, I + 32, 32);  // c_i = I_R
    }
    
    // BIP85 explicitly requires HMAC-SHA512 step here using "bip-entropy-from-k"
    uint8_t bip85_hmac_out[64];
    HmacSha512((uint8_t *)"bip-entropy-from-k", 18, k, 32, bip85_hmac_out);
    
    memset(data_array_256b, 0, 36);
    int target_bytes = (bip85_size == cSIZE_12) ? 16 : 32;
    for (int i = 0; i < target_bytes; i++) {
        data_array_256b[i] = bip85_hmac_out[i];
    }
    
    size_pointer = bip85_size;
}
// ============================================================================


// Writes byte 'val' at linear position 'i' (0..159)
 inline void write_coefficient_byte(unsigned i, uint8_t val){
    unsigned coef = i / BYTES_PER_COEFF;  // 0..4
    unsigned off  = i % BYTES_PER_COEFF;  // 0..31
    coefficient_buffers[coef][off] = val;
}


void update_entropy_coefficients(void) {
    uint16_t t = TMR1; // Read timer jitter
    
    // Circularly overwrite the pool by XORing with the jitter
    sss_entropy_pool[sss_pool_idx] ^= (uint8_t)t;
    sss_pool_idx = (sss_pool_idx + 1) % 32;
    sss_entropy_pool[sss_pool_idx] ^= (uint8_t)(t >> 8);
    sss_pool_idx = (sss_pool_idx + 1) % 32;
}


#if SSS_DEBUG
void debug_print_sss_state(void) {
    int page = 0;
    bool redraw = true;
    
    while(1) {
        SYS_Tasks(); // Keep hardware watchdog and background tasks happy
        
        if (redraw) {
            black_screen();
            
            // Draw title with pagination info (e.g., "DEBUG SSS - PAGE 1/4")
            char title[25];
            strcpy(title, "DEBUG SSS - PAGE ");
            char page_str[2] = {'1' + page, '\0'};
            strcat(title, page_str);
            strcat(title, "/4");
            drawtext(5, 5, title, ST7735_YELLOW, ST7735_BLACK, 1);
            
            char line[30];
            int y = 25;
            int offset = page * 8; // Each page shows 8 bytes (16 hex chars)
            
            // 1. Print 8 bytes of the Entropy Pool
            strcpy(line, "POOL: ");
            for (int j = 0; j < 4; j++) {
                // Combine 2 bytes into a 16-bit word and format to hex
                u16_to_hex4(((uint16_t)sss_entropy_pool[offset + j*2] << 8) | sss_entropy_pool[offset + j*2 + 1], &line[6 + j*4]);
            }
            drawtext(5, y, line, ST7735_WHITE, ST7735_BLACK, 1);
            y += 14;

            // 2. Print 8 bytes of C0 through C4
            for (int i = 0; i < 5; i++) {
                line[0] = 'C';
                line[1] = '0' + i;
                line[2] = ':';
                line[3] = ' ';
                line[4] = ' ';
                line[5] = '\0';
                
                for (int j = 0; j < 4; j++) {
                    u16_to_hex4(((uint16_t)coefficient_buffers[i][offset + j*2] << 8) | coefficient_buffers[i][offset + j*2 + 1], &line[5 + j*4]);
                }
                
                drawtext(5, y, line, ST7735_CYAN, ST7735_BLACK, 1);
                y += 12;
            }
            
            drawtext(5, 105, "LEFT/RIGHT: PAGE", ST7735_WHITE, ST7735_BLACK, 1);
            drawtext(5, 117, "OK: CONTINUE", ST7735_GREEN, ST7735_BLACK, 1);
            
            redraw = false;
            delay_ms(150); // Small delay to avoid visual flickering
        }
        
        // Button handling (Active LOW: 0 = pressed)
        if (BT6 == 0) { // Right button
            page = (page + 1) % 4;
            redraw = true;
            while(BT6 == 0) { SYS_Tasks(); } // Wait for release
        }
        
        if (BT2 == 0) { // Left button
            page = (page + 3) % 4; // Equivalent to (page - 1) wrapping around
            redraw = true;
            while(BT2 == 0) { SYS_Tasks(); } // Wait for release
        }
        
        if (BT_OK == 0) { // OK button
            while(BT_OK == 0) { SYS_Tasks(); } // Wait for release
            break; // Exit debug screen and continue execution
        }
    }
    
    black_screen(); // Clear the debug info before returning to standard flow
}
#endif

void expand_sss_coefficients(void) {
    SHA256_CTX ctx;
    for (uint8_t i = 0; i < 5; i++) {
        uint8_t index_byte = i + 1; // Indices 1, 2, 3, 4, 5
        sha256_init(&ctx);
        // Feed with the pool collected during button presses
        sha256_update(&ctx, sss_entropy_pool, 32);  
        // Add the index (1..5) to derive a different coefficient each time
        sha256_update(&ctx, &index_byte, 1);
        sha256_final(&ctx, coefficient_buffers[i]);
    }
    
    // --- DEBUG INJECTION POINT ---
    // Print the state before wiping the buffers
    #if SSS_DEBUG
        debug_print_sss_state();
    #endif
    
    // Secure wipe of the SHA256 context in RAM
    volatile uint8_t *p = (volatile uint8_t *)&ctx;
    for(size_t j = 0; j < sizeof(SHA256_CTX); j++) p[j] = 0;
    
    // Clear the pool so future splits do not reuse the same entropy
    for(int j = 0; j < 32; j++) sss_entropy_pool[j] = 0;
}

// State definitions
typedef enum
{
    INIT,
    MAIN,
    CHILD_CONFIG,
    CREATE_SEED,
    SEL_SIZE,
    SEL_XOR,
    SEL_OBFUS,
    OBFUS_CONFIG,
    ROLL_DICE1,
    SHOW_CHECKSUM_DETAILS,
    PRECOMPUTE_BIP84,
    SHOW_SEED,
    SHOW_QRSEED,
    WRITE_WORD,
    CHECK_RESULT,
    SEL_SD_BLOCK,
    SEL_SD_BLOCK_WR,
    SEL_SD_BLOCK_XOR,
    SEL_SD_BLOCK_MERGE,
    SEL_SSS,
    SEL_KN,
    SEL_K,
    SEL_INPUT,
    QR_TUTORIAL,
    RESOURCE_MENU,
    RESOURCE_QR_VIEW,
    WORD_LIST_ERROR,
    SEL_SHARE,
    TMR_INPUT,
    CARD_INPUT,
    PROCESS_TRIPLE,
    SHOW_TRIPLE_CHKSUM_12,
    SHOW_TRIPLE_CHKSUM_24,
    PROCESS_BIP85,
    SEL_DICE_MODE,
    SEL_HASH_MODE,
    DICE_STRING_INPUT,
    OBFUS_QR_VIEW,
    SEL_SETTINGS,
    WARNING_SEEDQR,
    SHOW_CARD_ENCODING,
        QR_SCANNING,
        SHOW_MCU_SERIAL,
        WARNING_UPDATE_FW,
        SHOW_SEED_MENU,
        SHOW_BIP84_INFO,
        SIGN_MENU,
    SEL_ERASE_MODE,
    CONFIRM_WIPE_SD,
    PROCESS_WIPE_SD,
    END_MODE // Final
} state_t;

state_t estado = INIT;

// Button enum
typedef enum
{
    NONE,
    OK_BT,
    BACK_BT,
    UP_BT,
    DOWN_BT,
    LEFT_BT,
    RIGHT_BT,
} PULSED_BT_t;

// ============================================================================
// QR Parsing & Validation Logic
// ============================================================================
bool validate_and_load_qr(uint8_t *buffer, int length) {
    
    // --- PRO FIX: Handle CompactQR FIRST, treating it as strictly binary data ---
    // CompactQR payload is exactly 16 or 32 bytes. Hardware scanners may append \r, \n, or \0, 
    // making the total received length 17-20 or 33-36 bytes.
    // Since the shortest possible Text SeedQR is 47 characters and Numeric is 48, 
    // any length in these ranges is guaranteed to be a CompactQR.
    if ((length >= 16 && length <= 20) || (length >= 32 && length <= 36)) {
        
        int compact_len = (length < 32) ? 16 : 32;
        size_pointer = (compact_len == 16) ? cSIZE_12 : cSIZE_24;
        
        // Clear target array
        for (int i = 0; i < 36; i++) {
            data_array_256b[i] = 0;
        }
        
        // Blindly copy exactly 16 or 32 bytes of raw entropy. 
        // We completely ignore scanner suffixes (bytes at index 16+ or 32+)
        for (int i = 0; i < compact_len; i++) {
            data_array_256b[i] = buffer[i];
        }
        
        return true;
    }
    
    // --- Now it is safe to trim string artifacts for Text and Numeric QR ---
    // At this point we know the buffer is text, so if a byte matches '\r' or ' ', 
    // it is genuinely a scanner artifact, not valid binary entropy.
    while (length > 0 && (buffer[length - 1] == '\r' || 
                          buffer[length - 1] == '\n' || 
                          buffer[length - 1] == ' '  || 
                          buffer[length - 1] == '\0')) {
        length--;
    }
    
    buffer[length] = '\0'; // Properly terminate the string for string processing
    
    // 2. Check if standard SeedQR (48 or 96 numeric digits)
    bool is_numeric = true;
    for (int i = 0; i < length; i++) {
        if (buffer[i] < '0' || buffer[i] > '9') { 
            is_numeric = false; 
            break; 
        }
    }
    
    if (is_numeric && (length == 48 || length == 96)) {
        int words = length / 4;
        size_pointer = (words == 12) ? cSIZE_12 : cSIZE_24;
        for (int i = 0; i < 36; i++) data_array_256b[i] = 0;
        
        int last_val = 0; 
        
        for (int w = 0; w < words; w++) {
            int val = (buffer[w*4]-'0')*1000 + (buffer[w*4+1]-'0')*100 + (buffer[w*4+2]-'0')*10 + (buffer[w*4+3]-'0');
            if (val > 2047) return false;
            
            write_11bit_value(data_array_256b, w+1, val);
            
            if (w == words - 1) {
                last_val = val;
            }
        }
        
        const char *last_word = get_word(last_val); 
        return matches_last_word_checksum(data_array_256b, (char *)last_word, size_pointer);
    }
    
    // 3. Check pure text sequence (Space/Newline separated)
    int word_count = 0;
    int last_val = 0; 
    for (int i = 0; i < 36; i++) data_array_256b[i] = 0;
    
    char tmp_word[16];
    int char_idx = 0;
    for (int i = 0; i <= length; i++) {
        if (buffer[i] == ' ' || buffer[i] == '\r' || buffer[i] == '\n' || buffer[i] == '\0') {
            if (char_idx > 0) {
                tmp_word[char_idx] = '\0';
                int idx = find_word_index(tmp_word);
                if (idx == -1) return false; // Not in BIP39 dictionary
                word_count++;
                if (word_count > 24) return false;
                
                write_11bit_value(data_array_256b, word_count, idx);
                last_val = idx; 
                
                char_idx = 0;
            }
        } else {
            if (char_idx < 15) {
                char c = buffer[i];
                // FIX: Convert uppercase letters to lowercase to match the UI dictionary
                if (c >= 'A' && c <= 'Z') c = c - ('a' - 'A'); 
                tmp_word[char_idx++] = c;
            } else {
                return false; // Word is suspiciously long
            }
        }
    }
    
    if (word_count == 12 || word_count == 24) {
        size_pointer = (word_count == 12) ? cSIZE_12 : cSIZE_24;
        
        const char *last_word = get_word(last_val); 
        return matches_last_word_checksum(data_array_256b, (char *)last_word, size_pointer);
    }
    
    return false;
}


void spi_send(uint8_t data) {
    // --- V2: Hardware SPI3 ---
    SPI3BUF = data;                  // 1. Write output buffer
    while (!SPI3STATbits.SPIRBF);    // 2. Wait TX ends
    (void)SPI3BUF;                   // 3. Fake read to avoid overflow of the RX buffer

}



bool SD_ready = false;

int SD_page = 0;


// --- Helper: Draw Single Character in Text Box (For Delta Rendering) ---
static void draw_single_text_char(const char* text, int len, int target_idx, int text_cursor, int scroll_y) {
    int pos_x = 5, pos_y = 15;
    
    // Calculate coordinates for the target index
    for(int i = 0; i < target_idx; i++) {
         if (text[i] == '\n') { 
             pos_x = 5; pos_y += 10; 
         } else { 
             pos_x += 6; 
             if (pos_x > 150) { pos_x = 5; pos_y += 10; } 
         }
    }
    
    // Only draw if within visible vertical scrolling window (60px height)
    if (pos_y >= scroll_y && pos_y < scroll_y + 60) {
        int draw_y = 15 + (pos_y - scroll_y);
        char c = (target_idx < len) ? text[target_idx] : ' ';
        if (c == '\n') c = ' '; // Newlines are rendered as blank spaces visually
        
        char s[2] = {c, '\0'};
        
        if (target_idx == text_cursor) {
            // Block Cursor: Orange Background, Black Text
            drawtext(pos_x, draw_y, s, ST7735_BLACK, ST7735_ORANGE, 1);
        } else {
            // Standard Text: White Text, Black Background
            drawtext(pos_x, draw_y, s, ST7735_WHITE, ST7735_BLACK, 1);
        }
    }
}

// --- Helper: Draw Full Editor Text Box (Delta Optimized - No Flicker) ---
static void draw_editor_textbox_full(const char* text, int len, int text_cursor, int scroll_y) {
    int pos_x = 5, pos_y = 15;
    
    for(int i = 0; i <= len; i++) {
        int draw_y = 15 + (pos_y - scroll_y);
        bool in_viewport = (pos_y >= scroll_y && pos_y < scroll_y + 60);
        
        char c = (i < len) ? text[i] : ' ';
        bool is_newline = (c == '\n');
        
        // 1. Draw the character
        if (in_viewport) {
            char s[2] = {is_newline ? ' ' : c, '\0'};
            
            if (i == text_cursor) {
                drawtext(pos_x, draw_y, s, ST7735_BLACK, ST7735_ORANGE, 1);
            } else if (i < len && !is_newline) {
                drawtext(pos_x, draw_y, s, ST7735_WHITE, ST7735_BLACK, 1);
            }
        }
        
        // 2. Advance the cursor and clear remaining pixels on the line if wrapping or newline
        if (i < len) {
            if (is_newline) {
                if (in_viewport && pos_x <= 150) {
                    int erase_x = pos_x + (i == text_cursor ? 6 : 0);
                    // Clear only the remainder of the empty line
                    rectan(erase_x, draw_y, 157, draw_y + 9, ST7735_BLACK);
                }
                pos_x = 5; 
                pos_y += 10; 
            } else { 
                pos_x += 6; 
                if (pos_x > 150) { 
                    if (in_viewport) {
                        // Clear the right margin
                        rectan(pos_x, draw_y, 157, draw_y + 9, ST7735_BLACK);
                    }
                    pos_x = 5; 
                    pos_y += 10; 
                } 
            }
        }
    } // <-- End of the for loop
    
    // 3. Final cleanup (Erase trailing artifacts at the end of the text)
    if (pos_y >= scroll_y && pos_y < scroll_y + 60) {
        int draw_y = 15 + (pos_y - scroll_y);
        
        // Offset the cleanup if the block cursor is sitting at the very end of the text
        int erase_x = pos_x;
        if (text_cursor == len) {
            erase_x += 6; // Protect the 6 pixels of the cursor we just drew
        }
        
        if (erase_x <= 150) {
            // Clear the remainder of the last line
            rectan(erase_x, draw_y, 157, draw_y + 9, ST7735_BLACK);
        }
        // Clear any lower lines that have been left empty
        if (draw_y + 10 < 75) {
            rectan(2, draw_y + 10, 157, 75, ST7735_BLACK);
        }
    }
}

// --- Helper: Find Closest Text Index (Used for UP/DOWN text navigation) ---
static int get_closest_text_idx(const char* text, int len, int target_x, int target_y) {
    int pos_x = 5, pos_y = 15;
    int best_idx = -1;
    int min_dist = 9999;
    
    for (int i = 0; i <= len; i++) {
        if (pos_y == target_y) {
            int dist = (pos_x > target_x) ? (pos_x - target_x) : (target_x - pos_x);
            if (dist < min_dist) { min_dist = dist; best_idx = i; }
        }
        if (i < len) {
            if (text[i] == '\n') { pos_x = 5; pos_y += 10; }
            else { pos_x += 6; if (pos_x > 150) { pos_x = 5; pos_y += 10; } }
        }
    }
    return best_idx;
}

// --- Helper: Delta Renderer for a Single Key ---
static void draw_keyboard_key(int idx, int active_layer, bool is_selected, bool allow_newlines) {
    uint16_t color = is_selected ? ST7735_ORANGE : ST7735_WHITE;
    uint16_t bg = ST7735_BLACK;
    
    if (idx >= 0 && idx <= 25) { 
        const char* charset = (active_layer == LAYER_ABC) ? kbd_abc : 
                              (active_layer == LAYER_ABC_UPPER) ? kbd_ABC : 
                              (active_layer == LAYER_NUM) ? kbd_num : kbd_sym;
        
        char single_char[2] = { charset[idx], '\0' };
        int row = (idx <= 12) ? 0 : 1;
        int col = (idx <= 12) ? idx : (idx - 13);
        
        int kx = 5 + (col * KBD_LETTER_SPACING);
        int ky = 81 + (row * 12);
        
        drawtext(kx, ky, single_char, color, bg, 1);
        
    } else if (idx == 26) { // Space ?
        int sx = 5 + 13 * KBD_LETTER_SPACING;
        int sy = 81; 
        
        rectan(sx, sy, sx + 6, sy + 7, ST7735_BLACK);
        drawFastHLine(sx, sy + 6, 6, color);
        drawFastVLine(sx, sy + 4, 3, color);
        drawFastVLine(sx + 5, sy + 4, 3, color);
        
    } else if (idx == 27) { // Return ?
        int sx = 5 + 13 * KBD_LETTER_SPACING;
        int sy = 93;
        uint16_t c = is_selected ? ST7735_ORANGE : (allow_newlines ? ST7735_WHITE : 0x8410); // 0x8410 is Dark Gray
        
        // Clear the background
        rectan(sx, sy, sx + 6, sy + 7, ST7735_BLACK);
        
        // 1. Vertical drop line on the right side of the cell
        // Drops down from the top (sy) with a length of 5 pixels
        drawFastVLine(sx + 5, sy, 5, c); 
        
        // 2. Left arrow pointing from the elbow
        // (sy + 2) lowers it slightly to align with the bottom of the vertical line
        print_left_arrow(sx, sy + 8, c);
        
    } else if (idx == 28) { // CANCEL
        drawtext(118, 81, "CANCEL", color, bg, 1);
    } else if (idx == 29) { // SAVE
        uint16_t save_color = is_selected ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(118, 93, "SAVE  ", save_color, bg, 1); 
        
    } else if (idx >= 30 && idx <= 35) { // 2x3 Control Grid (Bottom Left)
        if (idx == 30) {
            uint16_t c = is_selected ? ST7735_ORANGE : ((active_layer == LAYER_ABC || active_layer == LAYER_ABC_UPPER) ? ST7735_CYAN : ST7735_WHITE);
            drawtext(5, 105, "aA ", c, bg, 1);
        } else if (idx == 31) {            
            print_up_arrow(27,110,color);
        } else if (idx == 32) {
            uint16_t c = is_selected ? ST7735_ORANGE : ((active_layer == LAYER_NUM || active_layer == LAYER_SYM) ? ST7735_CYAN : ST7735_WHITE);
            drawtext(43, 105, "#@ ", c, bg, 1);
        } else if (idx == 33) {            
            print_left_arrow(8,122,color);
        } else if (idx == 34) {            
            print_down_arrow(27,122,color);
        } else if (idx == 35) {            
            print_rigth_arrow(46,122,color);
        }
    }
}


// --- Helper: Draw Title Line (Delta Optimized - No Flicker) ---
static void draw_editor_title_full(char* title, int len, int t_cursor, bool is_editing, bool allow_newlines) {
    int pos_x = 2; 
    
    for (int i = 0; i <= len; i++) {
        char c = (i < len) ? title[i] : ' ';
        char s[2] = {c, '\0'};
        
        if (is_editing && i == t_cursor) {
            // Block Cursor: Orange Background, Black Text
            drawtext(pos_x, 2, s, ST7735_BLACK, ST7735_ORANGE, 1);
        } else if (i < len) {
            // Standard Text
            drawtext(pos_x, 2, s, ST7735_WHITE, ST7735_BLACK, 1);
        } else {
            // Overwrite trailing characters with empty black spaces
            drawtext(pos_x, 2, " ", ST7735_WHITE, ST7735_BLACK, 1);
        }
        
        pos_x += 6;
        // Prevent text from overwriting the UI hint on the right side
        if (pos_x > 130) break; 
    }
    
    // Clear remaining pixels up to the hint area boundary
    if (pos_x <= 135) {
        rectan(pos_x, 2, 135, 10, ST7735_BLACK);
    }
    
    // Draw the UI hints ONLY if we are in Note Mode (newlines allowed)
    if (allow_newlines) {
        if (is_editing) {
            // Active state: Orange hint
            //drawtext(138, 2, "[^]", ST7735_ORANGE, ST7735_BLACK, 1);
            print_up_arrow(138,8,ST7735_ORANGE);
        } else {
            // Inactive state: Cyan hint to attract attention
            print_up_arrow(138,8,ST7735_CYAN);
        }
        
        // Draw a subtle bottom border to make it look like an input box
        // 0x8410 is Dark Gray in RGB565
        drawFastHLine(0, 12, 160, 0x8410); 
    }
}


// --- Main Modal Function ---
bool full_text_editor(char* title, int max_title_len, char* buffer, int max_len, bool allow_newlines) {
    int cursor_idx = 0; // Keyboard focus
    int prev_cursor = -1;
    int active_layer = LAYER_ABC;
    
    int text_len = strlen(buffer); 
    int text_cursor = text_len; 
    int prev_text_cursor = text_cursor;
    
    // Title State Variables
    int title_len = strlen(title);
    int title_cursor = title_len;
    int prev_title_cursor = title_cursor;
    bool editing_title = false;
    bool prev_editing_title = false;
    bool title_changed = true;
    
    int scroll_y = 15;
    int prev_scroll_y = 15;
    
    bool full_redraw = true;
    bool text_changed = true;
    
    while(BT_OK == 0 || BT1 == 0) SYS_Tasks();

    black_screen();

    while (1) {
        SYS_Tasks();

        if (full_redraw) {
            drawFastHLine(0, 77, 160, ST7735_WHITE); 
            grid_keyboard(); 
            
            for (int i = 0; i <= 35; i++) {
                draw_keyboard_key(i, active_layer, (i == cursor_idx), allow_newlines);
            }
            
            full_redraw = false;
            title_changed = true;
            text_changed = true; 
            prev_cursor = cursor_idx;
        } else if (prev_cursor != cursor_idx) {
            draw_keyboard_key(prev_cursor, active_layer, false, allow_newlines);
            draw_keyboard_key(cursor_idx, active_layer, true, allow_newlines);
            prev_cursor = cursor_idx;
        }

        // --- Calculate Text Viewport Scrolling ---
        int cursor_x = 5, cursor_y = 15;
        for(int i = 0; i < text_cursor; i++) {
             if (buffer[i] == '\n') { cursor_x = 5; cursor_y += 10; }
             else { cursor_x += 6; if (cursor_x > 150) { cursor_x = 5; cursor_y += 10; } }
        }
        
        bool scrolled = false;
        if (cursor_y < scroll_y) {
            scroll_y = cursor_y;
            scrolled = true;
        } else if (cursor_y >= scroll_y + 60) {
            scroll_y = cursor_y - 50;
            scrolled = true;
        }
        
        // --- Render Title ---
        // Check if editing state changed OR text changed
        if (title_changed || (editing_title != prev_editing_title) || (editing_title && prev_title_cursor != title_cursor)) {
            draw_editor_title_full(title, title_len, title_cursor, editing_title, allow_newlines);
            title_changed = false;
            prev_title_cursor = title_cursor;
            prev_editing_title = editing_title; // <-- Update previous state tracker
        }

        // --- Render Text Body ---
        if (text_changed || scrolled || scroll_y != prev_scroll_y) {
            // Pass -1 to hide the body cursor if we are currently editing the title
            draw_editor_textbox_full(buffer, text_len, editing_title ? -1 : text_cursor, scroll_y);
            text_changed = false;
            prev_text_cursor = text_cursor;
            prev_scroll_y = scroll_y;
        } else if (!editing_title && prev_text_cursor != text_cursor) {
            draw_single_text_char(buffer, text_len, prev_text_cursor, text_cursor, scroll_y);
            draw_single_text_char(buffer, text_len, text_cursor, text_cursor, scroll_y);
            prev_text_cursor = text_cursor;
        }

        if (BT_OK == 0) { 
            delay_ms(30); 
            if (BT_OK == 0) { 
                update_entropy_coefficients();
                LED = 1;
                
                char char_to_insert = '\0';
                
                if (cursor_idx >= 0 && cursor_idx <= 25) { 
                    char_to_insert = (active_layer == LAYER_ABC) ? kbd_abc[cursor_idx] : 
                                     (active_layer == LAYER_ABC_UPPER) ? kbd_ABC[cursor_idx] : 
                                     (active_layer == LAYER_NUM) ? kbd_num[cursor_idx] : kbd_sym[cursor_idx];
                } else if (cursor_idx == 26) { char_to_insert = ' '; } 
                  else if (cursor_idx == 27 && allow_newlines) { char_to_insert = '\n'; }
                
                // Insertion Mode
                if (char_to_insert != '\0') {
                    if (editing_title) {
                        // Title insertion (Do not allow newlines in title)
                        if (char_to_insert != '\n' && title_len < max_title_len - 1) {
                            memmove(&title[title_cursor + 1], &title[title_cursor], title_len - title_cursor + 1);
                            title[title_cursor] = char_to_insert;
                            title_len++;
                            title_cursor++;
                            title_changed = true;
                        }
                    } else {
                        // Body insertion
                        if (text_len < max_len - 1) {
                            memmove(&buffer[text_cursor + 1], &buffer[text_cursor], text_len - text_cursor + 1);
                            buffer[text_cursor] = char_to_insert;
                            text_len++;
                            text_cursor++;
                            text_changed = true;
                        }
                    }
                } 
                else if (cursor_idx == 28) { // CANCEL
                    while(BT_OK == 0) SYS_Tasks();
                    delay_ms(30);
                    black_screen();
                    LED = 0;
                    return false; 
                } 
                else if (cursor_idx == 29) { // SAVE
                    while(BT_OK == 0) SYS_Tasks();
                    delay_ms(30);
                    black_screen();
                    LED = 0;
                    return true; 
                } 
                else if (cursor_idx == 30) { // Toggle aA
                    if (active_layer == LAYER_ABC) active_layer = LAYER_ABC_UPPER;
                    else if (active_layer == LAYER_ABC_UPPER) active_layer = LAYER_ABC;
                    else active_layer = LAYER_ABC; 
                    full_redraw = true; 
                    rectan(0, 78, 159, 103, ST7735_BLACK);
                } 
                else if (cursor_idx == 32) { // Toggle #@
                    if (active_layer == LAYER_NUM) active_layer = LAYER_SYM;
                    else if (active_layer == LAYER_SYM) active_layer = LAYER_NUM;
                    else active_layer = LAYER_NUM; 
                    full_redraw = true; 
                    rectan(0, 78, 159, 103, ST7735_BLACK);
                }
                else if (cursor_idx == 33) { // LEFT (Text Navigation)
                    if (editing_title) {
                        if (title_cursor > 0) title_cursor--;
                    } else {
                        if (text_cursor > 0) text_cursor--;
                    }
                }
                else if (cursor_idx == 35) { // RIGHT (Text Navigation)
                    if (editing_title) {
                        if (title_cursor < title_len) title_cursor++;
                    } else {
                        if (text_cursor < text_len) text_cursor++;
                    }
                }
                else if (cursor_idx == 31) { // UP (Text Navigation)
                    if (!editing_title) {
                        // Jump to title if we are on the top line and in NOTE_MODE
                        if (allow_newlines && cursor_y == 15 && scroll_y == 15) {
                            editing_title = true;
                            title_changed = true; // Force title redraw
                            text_changed = true;  // Force redraw to hide body cursor
                        } else {
                            int target_idx = get_closest_text_idx(buffer, text_len, cursor_x, cursor_y - 10);
                            text_cursor = (target_idx != -1) ? target_idx : 0;
                        }
                    }
                }
                else if (cursor_idx == 34) { // DOWN (Text Navigation)
                    if (editing_title) {
                        // Jump back down to body text
                        editing_title = false;
                        title_changed = true; // Force title redraw to clear cursor block
                        text_changed = true;
                    } else {
                        int target_idx = get_closest_text_idx(buffer, text_len, cursor_x, cursor_y + 10);
                        text_cursor = (target_idx != -1) ? target_idx : text_len;
                    }
                }
                
                while(BT_OK == 0) SYS_Tasks(); 
                delay_ms(30); 
                LED = 0;
            }
        }
        
        if (BT1 == 0) { // BACK / DELETE
            delay_ms(30);
            if (BT1 == 0) {
                update_entropy_coefficients();
                LED = 1;
                
                if (editing_title) {
                    if (title_cursor > 0) {
                        memmove(&title[title_cursor - 1], &title[title_cursor], title_len - title_cursor + 1);
                        title_len--;
                        title_cursor--;
                        title_changed = true;
                    }
                } else {
                    if (text_cursor > 0) {
                        memmove(&buffer[text_cursor - 1], &buffer[text_cursor], text_len - text_cursor + 1);
                        text_len--;
                        text_cursor--;
                        text_changed = true;
                    }
                }
                
                while(BT1 == 0) SYS_Tasks();
                delay_ms(30);
                LED = 0;
            }
        }

        if (BT6 == 0) { // RIGHT D-Pad
            delay_ms(30);
            if (BT6 == 0) {
                update_entropy_coefficients();
                if (cursor_idx <= 11) cursor_idx++;
                else if (cursor_idx == 12) cursor_idx = 26; 
                else if (cursor_idx == 26) cursor_idx = 28; 
                else if (cursor_idx == 28) cursor_idx = 0;  
                else if (cursor_idx >= 13 && cursor_idx <= 24) cursor_idx++;
                else if (cursor_idx == 25) cursor_idx = 27; 
                else if (cursor_idx == 27) cursor_idx = 29; 
                else if (cursor_idx == 29) cursor_idx = 13; 
                else if (cursor_idx == 30) cursor_idx = 31; 
                else if (cursor_idx == 31) cursor_idx = 32; 
                else if (cursor_idx == 32) cursor_idx = 30; 
                else if (cursor_idx == 33) cursor_idx = 34; 
                else if (cursor_idx == 34) cursor_idx = 35; 
                else if (cursor_idx == 35) cursor_idx = 33; 
                
                while(BT6 == 0) SYS_Tasks();
                delay_ms(30);
            }
        }

        if (BT2 == 0) { // LEFT D-Pad
            delay_ms(30);
            if (BT2 == 0) {
                update_entropy_coefficients();
                if (cursor_idx == 0) cursor_idx = 28;       
                else if (cursor_idx >= 1 && cursor_idx <= 12) cursor_idx--;
                else if (cursor_idx == 26) cursor_idx = 12; 
                else if (cursor_idx == 28) cursor_idx = 26; 
                else if (cursor_idx == 13) cursor_idx = 29; 
                else if (cursor_idx >= 14 && cursor_idx <= 25) cursor_idx--;
                else if (cursor_idx == 27) cursor_idx = 25; 
                else if (cursor_idx == 29) cursor_idx = 27; 
                else if (cursor_idx == 30) cursor_idx = 32; 
                else if (cursor_idx == 31) cursor_idx = 30; 
                else if (cursor_idx == 32) cursor_idx = 31; 
                else if (cursor_idx == 33) cursor_idx = 35; 
                else if (cursor_idx == 34) cursor_idx = 33; 
                else if (cursor_idx == 35) cursor_idx = 34; 
                
                while(BT2 == 0) SYS_Tasks();
                delay_ms(30);
            }
        }

        if (BT4 == 0) { // DOWN D-Pad
            delay_ms(30);
            if (BT4 == 0) {
                update_entropy_coefficients();
                if (cursor_idx >= 0 && cursor_idx <= 12) cursor_idx += 13; 
                else if (cursor_idx >= 13 && cursor_idx <= 15) cursor_idx = 30; 
                else if (cursor_idx >= 16 && cursor_idx <= 18) cursor_idx = 31; 
                else if (cursor_idx >= 19 && cursor_idx <= 25) cursor_idx = 32; 
                else if (cursor_idx == 26) cursor_idx = 27; 
                else if (cursor_idx == 27) cursor_idx = 32; 
                else if (cursor_idx == 28) cursor_idx = 29; 
                else if (cursor_idx == 29) cursor_idx = 32; 
                else if (cursor_idx == 30) cursor_idx = 33; 
                else if (cursor_idx == 31) cursor_idx = 34; 
                else if (cursor_idx == 32) cursor_idx = 35; 
                else if (cursor_idx == 33) cursor_idx = 0;  
                else if (cursor_idx == 34) cursor_idx = 4;  
                else if (cursor_idx == 35) cursor_idx = 9;  
                
                while(BT4 == 0) SYS_Tasks();
                delay_ms(30);
            }
        }

        if (BT5 == 0) { // UP D-Pad
            delay_ms(30);
            if (BT5 == 0) {
                update_entropy_coefficients();
                if (cursor_idx >= 13 && cursor_idx <= 25) cursor_idx -= 13; 
                else if (cursor_idx == 27) cursor_idx = 26; 
                else if (cursor_idx == 29) cursor_idx = 28; 
                else if (cursor_idx == 30) cursor_idx = 14; 
                else if (cursor_idx == 31) cursor_idx = 17; 
                else if (cursor_idx == 32) cursor_idx = 21; 
                else if (cursor_idx == 33) cursor_idx = 30; 
                else if (cursor_idx == 34) cursor_idx = 31; 
                else if (cursor_idx == 35) cursor_idx = 32; 
                else if (cursor_idx >= 0 && cursor_idx <= 3) cursor_idx = 33; 
                else if (cursor_idx >= 4 && cursor_idx <= 8) cursor_idx = 34;
                else if (cursor_idx >= 9 && cursor_idx <= 12) cursor_idx = 35;
                else if (cursor_idx == 26) cursor_idx = 35; 
                else if (cursor_idx == 28) cursor_idx = 35; 
                
                while(BT5 == 0) SYS_Tasks();
                delay_ms(30);
            }
        }
    }
}


// ============================================================================
// Base58Check Functions (No external dependencies, using custom memzero)
// ============================================================================

const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

bool b58enc(char *b58, size_t *b58sz, const void *data, size_t binsz) {
    const uint8_t *bin = (const uint8_t *)data;
    int carry = 0;
    size_t i = 0, j = 0, high = 0, zcount = 0;
    size_t size = 0;

    // 1. Count leading null bytes (zeros)
    while (zcount < binsz && !bin[zcount]) ++zcount;

    // 2. Allocate maximum size needed for base58 conversion
    size = (binsz - zcount) * 138 / 100 + 1;
    uint8_t buf[size];
    memzero(buf, size);

    // 3. Process the binary array and convert it
    for (i = zcount, high = size - 1; i < binsz; ++i, high = j) {
        for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
            carry += 256 * buf[j];
            buf[j] = carry % 58;
            carry /= 58;
            if (!j) {
                break;
            }
        }
    }

    // 4. Find the first useful digit (non-null)
    for (j = 0; j < size && !buf[j]; ++j);

    // 5. Check if the output buffer size is sufficient
    if (*b58sz <= zcount + size - j) {
        *b58sz = zcount + size - j + 1;
        return false;
    }

    // 6. Write '1's (representing leading zeros in Base58)
    if (zcount) memset(b58, '1', zcount);
    
    // 7. Write the remaining encoded characters
    for (i = zcount; j < size; ++i, ++j) b58[i] = b58digits_ordered[buf[j]];
    b58[i] = '\0';
    *b58sz = i + 1;

    return true;
}

size_t base58_encode_check(const uint8_t *data, size_t datalen, char *str, size_t strsize) {
    if (datalen > 128) {
        return 0;
    }
    
    // Buffer for original data + 4 bytes of checksum
    uint8_t buf[128 + 4]; 
    memzero(buf, sizeof(buf));
    memcpy(buf, data, datalen);

    // Double SHA-256 hash to get the checksum
    uint8_t hash1[32];
    uint8_t hash2[32];
    SHA256_CTX ctx;
    
    sha256_init(&ctx);
    sha256_update(&ctx, data, datalen);
    sha256_final(&ctx, hash1);
    
    sha256_init(&ctx);
    sha256_update(&ctx, hash1, 32);
    sha256_final(&ctx, hash2);

    // Copy the first 4 bytes of the second hash to the end of the payload (checksum)
    memcpy(buf + datalen, hash2, 4);

    size_t res = strsize;
    bool success = b58enc(str, &res, buf, datalen + 4);
    
    memzero(buf, sizeof(buf));
    return success ? res : 0;
}

// Curve definition for the seed
#ifndef SECP256K1_NAME
#define SECP256K1_NAME "secp256k1"
#endif

// 1. Native Fingerprint calculation using your local sha256 and ripemd160
static uint32_t hdnode_fingerprint(HDNode *node) {
    uint8_t sha256_pub[32];
    uint8_t hash160[20];
    SHA256_CTX ctx; // Fixed: Using your original context name
    
    hdnode_fill_public_key(node);
    
    sha256_init(&ctx);
    sha256_update(&ctx, node->public_key, 33);
    sha256_final(&ctx, sha256_pub);
    
    ripemd160(sha256_pub, 32, hash160);
    
    return ((uint32_t)hash160[0] << 24) | (hash160[1] << 16) | (hash160[2] << 8) | hash160[3];
}

// ============================================================================
// BIP32 Packaging and Base58 Encoding
// ============================================================================

static void hdnode_serialize_public(const HDNode *node, uint32_t fingerprint, uint32_t version, char *str, size_t strsize) {
    uint8_t payload[78];
    
    // 1. Key version (4 bytes, Big-Endian) (e.g., 0x0488B21E for xpub)
    payload[0] = (version >> 24) & 0xFF;
    payload[1] = (version >> 16) & 0xFF;
    payload[2] = (version >> 8) & 0xFF;
    payload[3] = version & 0xFF;

    // 2. Depth of the node in the tree (1 byte)
    payload[4] = node->depth;

    // 3. Parent fingerprint (4 bytes, Big-Endian)
    payload[5] = (fingerprint >> 24) & 0xFF;
    payload[6] = (fingerprint >> 16) & 0xFF;
    payload[7] = (fingerprint >> 8) & 0xFF;
    payload[8] = fingerprint & 0xFF;

    // 4. Child number (4 bytes, Big-Endian)
    payload[9] = (node->child_num >> 24) & 0xFF;
    payload[10] = (node->child_num >> 16) & 0xFF;
    payload[11] = (node->child_num >> 8) & 0xFF;
    payload[12] = node->child_num & 0xFF;

    // 5. Chain code (32 bytes)
    memcpy(payload + 13, node->chain_code, 32);

    // 6. Compressed public key (33 bytes) 
    // The Ledger library already stores this with the 0x02 or 0x03 prefix in node->public_key
    memcpy(payload + 45, node->public_key, 33);

    // 7. Encode the 78 bytes using Base58Check
    base58_encode_check(payload, 78, str, strsize);
}

// Background calculation function
void precompute_bip84_account(void) {
    if (bip84_account_cached) return;

    char mnemonic_str[250];
    get_mnemonic_string(mnemonic_str);


    // Draw initial outline for progress bar over the footer area
    rectan(0, 110, 159, 127, BLACK);
    //drawtext(10, 105, "COMPUTING KEYS...", ST7735_YELLOW, ST7735_BLACK, 1);
    rectan(9, 120, 151, 125, WHITE);

    // Generate the master seed (This loop triggers the green progress bar)
    uint8_t seed[64];
    char bip39_salt[250] = "mnemonic"; 
    strcat(bip39_salt, bip84_passphrase); 
    
    PBKDF2_HMAC_SHA512(mnemonic_str, bip39_salt, 2048, seed, 64);

    HDNode root;
    if (!hdnode_from_seed(seed, 64, SECP256K1_NAME, &root)) return;

    // Store Master Fingerprint
    bip84_master_fingerprint = hdnode_fingerprint(&root);

    // Derive path m/84'/0'
    bip84_account_node = root;
    hdnode_private_ckd(&bip84_account_node, 84 | 0x80000000); 
    hdnode_private_ckd(&bip84_account_node, 0  | 0x80000000); 

    // Store parent fingerprint for account-level xpub/zpub
    bip84_account_parent_fingerprint = hdnode_fingerprint(&bip84_account_node);

    // Derive Account path: m/84'/0'/0'
    hdnode_private_ckd(&bip84_account_node, 0  | 0x80000000); 
    
    // Precompute public key and Base58 strings under the loading bar ---
    // Fill the public key for the account node so it can be serialized
    hdnode_fill_public_key(&bip84_account_node);

    // Serialize and cache the XPUB and ZPUB strings globally
    hdnode_serialize_public(&bip84_account_node, bip84_account_parent_fingerprint, 0x0488B21E, bip84_cached_xpub, sizeof(bip84_cached_xpub));
    hdnode_serialize_public(&bip84_account_node, bip84_account_parent_fingerprint, 0x04B24746, bip84_cached_zpub, sizeof(bip84_cached_zpub));
    // --------------------------------------------------------------------------------

    // This saves one heavy HMAC-SHA512 derivation per address request
    bip84_receive_node_cache = bip84_account_node;
    hdnode_private_ckd(&bip84_receive_node_cache, 0);

    bip84_change_node_cache = bip84_account_node;
    hdnode_private_ckd(&bip84_change_node_cache, 1);
    
    // Mark as successfully cached
    bip84_account_cached = true;
}

static bool get_current_bip84_result(uint32_t chain, uint32_t address_index, BitcoinBip84Result *result)
{
    // 1. LAZY EVALUATION FALLBACK
    if (!bip84_account_cached) {
        precompute_bip84_account();
    }

    // 2. FILL RESULT FROM CACHE
    u16_to_hex4((bip84_master_fingerprint >> 16) & 0xFFFF, result->fingerprint);
    u16_to_hex4(bip84_master_fingerprint & 0xFFFF, result->fingerprint + 4);

    strcpy(result->xpub, bip84_cached_xpub);
    strcpy(result->zpub, bip84_cached_zpub);

    // --- NEW CODE: Start directly from the precomputed branch cache ---
    HDNode node = (chain == 0) ? bip84_receive_node_cache : bip84_change_node_cache;

    // FAST DERIVATION: Derive only the final specific address index
    if (!hdnode_private_ckd(&node, address_index)) return false; 
    // ------------------------------------------------------------------

    // HEAVY MATH: Secp256k1 Elliptic Curve Scalar Multiplication
    // This is computationally intensive but unavoidable for each new address
    hdnode_fill_public_key(&node);

    // 4. HASHING & ENCODING
    uint8_t sha256_pub[32];
    uint8_t hash160[20];
    
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, node.public_key, 33);
    sha256_final(&ctx, sha256_pub);
    
    ripemd160(sha256_pub, 32, hash160);

    // Encode as a Native SegWit Bech32 address ("bc1q...")
    if (!segwit_addr_encode(result->address, "bc", 0, hash160, 20)) return false;

    return true;
}


static void print_bip84_menu(void)
{
    print_generic_menu(menu_bip84, cBIP84_n_opt, bip84_menu_pointer);
    // --- ADDED: Display master fingerprint at the bottom left ---
    // Convert the 32-bit fingerprint into an 8-character hex string
    char fgp_str[9];
    u16_to_hex4((bip84_master_fingerprint >> 16) & 0xFFFF, fgp_str);
    u16_to_hex4(bip84_master_fingerprint & 0xFFFF, fgp_str + 4);
    fgp_str[8] = '\0';
    
    // Draw the fingerprint string in Cyan color at x=5, y=117 (bottom left corner)
    drawtext(5, 117, fgp_str, ST7735_CYAN, ST7735_BLACK, 1);
    
    estado = SHOW_SEED_MENU;
    estado = SHOW_SEED_MENU;
}

static void print_sign_menu(void)
{
    print_generic_menu(menu_sign, cSIGN_n_opt, sign_menu_pointer);
    estado = SIGN_MENU;
}

static void print_bip84_info_screen(void)
{
    BitcoinBip84Result result;
    const char *title;
    const char *value;
    char index_text[12];

    black_screen();

    if (bip84_menu_pointer == cBIP84_RECEIVE ||
        bip84_menu_pointer == cBIP84_CHANGE) {
        
        // Only run the heavy elliptic curve derivation when we actually need an address
        uint32_t chain = (bip84_menu_pointer == cBIP84_RECEIVE) ? 0u : 1u;
        bool derived = get_current_bip84_result(chain, bip84_address_index, &result);
        
        title = (chain == 0u) ? "RECEIVE ADDRESS" : "CHANGE ADDRESS";
        drawtext(1, 5, (char *)title, ST7735_ORANGE, ST7735_BLACK, 1);
        drawtext(1, 15, "INDEX:", ST7735_WHITE, ST7735_BLACK, 1);
        
        u16_to_str((unsigned int)bip84_address_index, index_text);
        drawtext(45, 15, index_text, ST7735_CYAN, ST7735_BLACK, 1);
        
        if (derived) {
            draw_bip84_wrapped_text(result.address, 1, 30, 25, 6);
        } else {
            drawtext(1, 30, "DERIVATION ERROR", ST7735_RED, ST7735_BLACK, 1);
        }
        
    } else if (bip84_menu_pointer == cBIP84_FINGERPRINT) {
        // FAST PATH: Read directly from the cached global variable
        char fgp_str[9];
        u16_to_hex4((bip84_master_fingerprint >> 16) & 0xFFFF, fgp_str);
        u16_to_hex4(bip84_master_fingerprint & 0xFFFF, fgp_str + 4);
        fgp_str[8] = '\0';
        
        drawtext(1, 5, "MASTER FINGERPRINT", ST7735_ORANGE, ST7735_BLACK, 1);
        drawtext(1, 30, fgp_str, ST7735_CYAN, ST7735_BLACK, 2);
        
    } else {
        // FAST PATH: Read the XPUB/ZPUB directly from the cached global buffers
        value = (bip84_extended_key_page == 0) ? bip84_cached_xpub : bip84_cached_zpub;
        title = (bip84_extended_key_page == 0) ? "XPUB" : "ZPUB";
        
        drawtext(1, 5, (char *)title, ST7735_ORANGE, ST7735_BLACK, 1);
        draw_bip84_wrapped_text(value, 1, 18, 25, 7);
    }

    grid_menu2();
    estado = SHOW_BIP84_INFO;
}


static void reset_card_entropy_mode(void) {
    for (int i = 0; i < 32; i++) {
        data_array_256b[i] = 0;
    }
    bit_count_dice = 0;
    last_input_len = 0;
    card_rank_pointer = 0;
    card_suit_pointer = 0;
    card_field_pointer = 0;
    card_history_count = 0;
    for (int i = 0; i < cCARD_MAX_HISTORY; i++) {
        card_history_start_bits[i] = 0;
        card_history_bit_len[i] = 0;        
    }
}


// Unified visual helper for building entropy for cards, dice, and coins
int read_entropy_bit(const BYTE data_array[36], int bit_index) {
    if (bit_index < 0 || bit_index >= 288) { // Updated bounds
        return 0;
    }

    int byte_index = bit_index / 8;
    int bit_position = 7 - (bit_index % 8);
    return (data_array[byte_index] >> bit_position) & 1;
}


// Accepts excess bits without truncation to allow proper red-bit display in checksum screen
static void append_entropy_bits(const char *bits, size_t len) {
    last_input_len = len; // Track length for purple highlight
    for (size_t i = 0; i < len; i++) {
        set_bit(data_array_256b, bit_count_dice, (bits[i] == '1') ? 1 : 0);
        bit_count_dice++;
    }
}

static bool append_selected_card_entropy(void) {
    uint8_t card_index = get_selected_card_index();
    const char *bits = card_entropy_map[card_index];
    size_t len = strlen(bits);
    int target_bits = (size_pointer == cSIZE_12) ? 128 : 256;

    if (card_history_count >= cCARD_MAX_HISTORY) {
        return false;
    }

    if (bit_count_dice >= target_bits) {
        return false;
    }

    card_history_start_bits[card_history_count] = (uint16_t)bit_count_dice;
    card_history_bit_len[card_history_count] = (uint8_t)len;
    card_history_count++;

    append_entropy_bits(bits, len);

    return true;
}

static void remove_last_card_entropy(void) {
    if (card_history_count <= 0) {
        return;
    }

    card_history_count--;
    uint16_t start_bit = card_history_start_bits[card_history_count];
    uint8_t len = card_history_bit_len[card_history_count];

    for (uint8_t i = 0; i < len; i++) {
        set_bit(data_array_256b, start_bit + i, 0);
    }

    bit_count_dice = start_bit;
    last_input_len = 0; // Clear highlight on delete
}


void print_checksum_screen(void) {
    int target_bits = (size_pointer == cSIZE_12) ? 128 : 256;
    int b_len = (size_pointer == cSIZE_12) ? 7 : 3;
    int c_len = (size_pointer == cSIZE_12) ? 4 : 8;
    int b_start = target_bits - b_len;
    
    // Calculate final checksum Hash 
    BYTE hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data_array_256b, (size_t)(target_bits / 8));
    sha256_final(&ctx, hash);
    
    // Extract 'b' bits (from true entropy input)
    char b_str[8] = {0};
    unsigned int b_val = 0;
    for (int i = 0; i < b_len; i++) {
        int bit = read_entropy_bit(data_array_256b, b_start + i);
        b_str[i] = bit ? '1' : '0';
        b_val = (b_val << 1) | bit;
    }
    
    // Extract 'c' bits (from mathematical hash)
    char c_str[9] = {0};
    unsigned int c_val = 0;
    for (int i = 0; i < c_len; i++) {
        int bit = (hash[0] >> (7 - i)) & 1;
        c_str[i] = bit ? '1' : '0';
        c_val = (c_val << 1) | bit;
    }
    
    // Derived values mapping
    unsigned int correct_group = (b_val << c_len) | c_val;
    const char* correct_word = get_word(correct_group);
    char correct_dec_str[6];
    u16_to_str_pad(correct_group, correct_dec_str, 4);

    int y_cursor = 5;

    // Handle User input sections (Word Mode vs Raw Bits Mode)
    if (seed_pointer == cSEED_word) {
        int r_len = c_len;
        char r_str[9] = {0};
        unsigned int r_val = 0;
        for (int i = 0; i < r_len; i++) {
            int bit = read_entropy_bit(data_array_256b, target_bits + i);
            r_str[i] = bit ? '1' : '0';
            r_val = (r_val << 1) | bit;
        }
        unsigned int user_group = (b_val << c_len) | r_val;
        char user_dec_str[6];
        u16_to_str_pad(user_group, user_dec_str, 4);
        
        uint16_t r_color = (r_val == c_val) ? ST7735_GREEN : ST7735_RED;

        drawtext(1, y_cursor, "User word:", ST7735_WHITE, ST7735_BLACK, 1);
        y_cursor += 10;
        
        drawtext(1, y_cursor, b_str, ST7735_ORANGE, ST7735_BLACK, 1);
        drawtext(1 + (b_len * 6), y_cursor, r_str, r_color, ST7735_BLACK, 1);
        y_cursor += 10;
        
        drawtext(1, y_cursor, "decimal: ", ST7735_WHITE, ST7735_BLACK, 1);
        drawtext(55, y_cursor, user_dec_str, ST7735_YELLOW, ST7735_BLACK, 1);
        y_cursor += 10;
        
        drawtext(1, y_cursor, "word: ", ST7735_WHITE, ST7735_BLACK, 1);
        drawtext(37, y_cursor, (char*)get_word(user_group), r_color, ST7735_BLACK, 1);
        y_cursor += 15;
    } else if (bit_count_dice > target_bits) {
        // Display excess overrun bits in red
        int r_len = bit_count_dice - target_bits;
        char r_str[16] = {0};
        for (int i = 0; i < r_len && i < 15; i++) {
            r_str[i] = read_entropy_bit(data_array_256b, target_bits + i) ? '1' : '0';
        }
        
        drawtext(1, y_cursor, "Excess bits (discarded):", ST7735_WHITE, ST7735_BLACK, 1);
        y_cursor += 10;
        drawtext(1, y_cursor, b_str, ST7735_ORANGE, ST7735_BLACK, 1);
        drawtext(1 + (b_len * 6), y_cursor, r_str, ST7735_RED, ST7735_BLACK, 1);
        y_cursor += 15;
    }

    // Unified Correct Checksum Section
    drawtext(1, y_cursor, "Checksum word:", ST7735_WHITE, ST7735_BLACK, 1);
    y_cursor += 10;
    drawtext(1, y_cursor, b_str, ST7735_ORANGE, ST7735_BLACK, 1);
    drawtext(1 + (b_len * 6), y_cursor, c_str, ST7735_CYAN, ST7735_BLACK, 1);
    y_cursor += 10;
    
    drawtext(1, y_cursor, "decimal: ", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(55, y_cursor, correct_dec_str, ST7735_YELLOW, ST7735_BLACK, 1);
    y_cursor += 10;
    
    drawtext(1, y_cursor, "word: ", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(37, y_cursor, (char*)correct_word, ST7735_GREEN, ST7735_BLACK, 1);

    grid_OK_only(); 
}

void print_triple_checksum(int word_target) {
    int b_len, c_len, b_start;
    unsigned int b_val = 0, c_val = 0;
    char b_str[8] = {0}, c_str[9] = {0};

    if (word_target == 12) {
        b_len = 7; c_len = 4; b_start = 121;
        drawtext(1, 5, "Word 12 Checksum:", ST7735_WHITE, ST7735_BLACK, 1);
        for(int i=0; i<7; i++) {
            int bit = read_entropy_bit(data_array_256b, b_start + i);
            b_str[i] = bit ? '1' : '0';
            b_val = (b_val << 1) | bit;
        }
        for(int i=0; i<4; i++) {
            int bit = read_entropy_bit(data_array_256b, 128 + i);
            c_str[i] = bit ? '1' : '0';
            c_val = (c_val << 1) | bit;
        }
    } else {
        b_len = 3; c_len = 8; b_start = 253;
        drawtext(1, 5, "Word 24 Checksum:", ST7735_WHITE, ST7735_BLACK, 1);
        for(int i=0; i<3; i++) {
            int bit = read_entropy_bit(data_array_256b, b_start + i);
            b_str[i] = bit ? '1' : '0';
            b_val = (b_val << 1) | bit;
        }
        for(int i=0; i<8; i++) {
            int bit = read_entropy_bit(data_array_256b, 256 + i);
            c_str[i] = bit ? '1' : '0';
            c_val = (c_val << 1) | bit;
        }
    }

    unsigned int correct_group = (b_val << c_len) | c_val;
    const char* correct_word = get_word(correct_group);
    char correct_dec_str[6];
    u16_to_str_pad(correct_group, correct_dec_str, 4);

    int y_cursor = 25;
    drawtext(1, y_cursor, b_str, ST7735_ORANGE, ST7735_BLACK, 1);
    drawtext(1 + (b_len * 6), y_cursor, c_str, ST7735_CYAN, ST7735_BLACK, 1);
    y_cursor += 15;

    drawtext(1, y_cursor, "decimal: ", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(55, y_cursor, correct_dec_str, ST7735_YELLOW, ST7735_BLACK, 1);
    y_cursor += 15;

    drawtext(1, y_cursor, "word: ", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(37, y_cursor, (char*)correct_word, ST7735_GREEN, ST7735_BLACK, 1);
    grid_OK_only(); 
}


// Unified Obfuscation Configuration Screen
int obfus_cursor = 0;
int obfus_dir_op = 0;
int obfus_amount = 1;


int get_nearest_valid_key(int current_idx, const char *current_word, bool ok_is_valid) {
    bool valid_letters[27];
    get_valid_next_letters(current_word, valid_letters);
    valid_letters[26] = ok_is_valid; // Dynamic OK state

    if (current_idx >= 0 && current_idx < 27 && valid_letters[current_idx]) {
        return current_idx;
    }

    int best_idx = current_idx; // Fallback to current position
    int best_dist = 9999;
    
    int cx = current_idx % 9;
    int cy = current_idx / 9;
    
    for (int i = 0; i < 27; i++) {
        if (!valid_letters[i]) {
            continue;
        }
        
        int tx = i % 9;
        int ty = i / 9;
        
        int dx = tx - cx;
        int dy = ty - cy;
        
        int dist = (dx * dx) + (dy * dy);
        
        if (dist < best_dist) {
            best_dist = dist;
            best_idx = i;
        }
    }
    
    return best_idx;
}

int get_next_valid_key(int current_idx, int step, const char *current_word, bool ok_is_valid) {
    bool valid_letters[27];
    get_valid_next_letters(current_word, valid_letters);
    valid_letters[26] = ok_is_valid; // Dynamic OK state
    
    bool has_other_valid = false;
    for (int i = 0; i < 27; i++) {
        if (i != current_idx && valid_letters[i]) {
            has_other_valid = true;
            break;
        }
    }
    
    if (!has_other_valid) {
        return current_idx;
    }
    
    int best_idx = current_idx;
    int best_score = 99999;
    
    int cx = current_idx % 9;
    int cy = current_idx / 9;
    
    for (int i = 0; i < 27; i++) {
        if (i == current_idx || !valid_letters[i]) {
            continue;
        }
        
        int tx = i % 9;
        int ty = i / 9;
        
        int forward_dist = 0;
        int lateral_dist = 0;
        int axis_max = 0;
        
        if (step == 1) { 
            forward_dist = tx - cx;
            int diff = ty - cy;
            lateral_dist = (diff < 0) ? -diff : diff;
            axis_max = 9;
        } else if (step == -1) { 
            forward_dist = cx - tx;
            int diff = ty - cy;
            lateral_dist = (diff < 0) ? -diff : diff;
            axis_max = 9;
        } else if (step == 9) { 
            forward_dist = ty - cy;
            int diff = tx - cx;
            lateral_dist = (diff < 0) ? -diff : diff;
            axis_max = 3;
        } else if (step == -9) { 
            forward_dist = cy - ty;
            int diff = tx - cx;
            lateral_dist = (diff < 0) ? -diff : diff;
            axis_max = 3;
        }
        
        int score = 0;
        
        if (forward_dist > 0) {
            if (lateral_dist == 0) {
                score = forward_dist; 
            } else {
                score = 100 + forward_dist + (lateral_dist * 4); 
            }
        } else {
            int wrapped_forward = forward_dist + axis_max;
            if (lateral_dist == 0) {
                score = 200 + wrapped_forward; 
            } else {
                score = 300 + wrapped_forward + (lateral_dist * 4); 
            }
        }
        
        if (score < best_score) {
            best_score = score;
            best_idx = i;
        }
    }
    
    return best_idx;
}

const char* get_word(int index) {
    if (index < 0 || index >= 2048) {
        return NULL;
    }
    
    const char* ptr = bip39_words; 
    
    
    for (int i = 0; i < index; i++) {
        while (*ptr != '\0') {
            ptr++;
        }
        ptr++; 
    }
    
    return ptr; 
}


int find_word_index(const char *word) {
    if (word == NULL || word[0] == '\0') {
        return -1;
    }

    const char* ptr = bip39_words;
    
    for (int i = 0; i < 2048; ++i) {
        if (strcmp(ptr, word) == 0) {
            return i; // Word found, return its index
        }
        
        // If not, advance pointer to the next word
        while (*ptr != '\0') {
            ptr++;
        }
        ptr++;
    }
    
    return -1; // Word not found
}


int read_11bit_value(const BYTE data_array[36], int index) {
    int bit_pos = (index - 1) * 11;
    int max_bits = (16 + size_pointer * 16) * 8;
    int value = 0;

    if (index < 1 || bit_pos + 11 > max_bits) {
        return -1;
    }

    for (int i = 0; i < 11; i++) {
        value = (value << 1) | read_entropy_bit(data_array, bit_pos + i);
    }

    return value;
}

const char* get_confirmed_word_from_entropy(const BYTE data_array[36], int index) {
    int word_index = read_11bit_value(data_array, index);

    if (word_index < 0) {
        return NULL;
    }

    return get_word(word_index);
}

static void write_11bit_value(BYTE *buffer, int index, int value) {
    int bit_pos;

    if (buffer == NULL || index < 1 || value < 0 || value > 2047) {
        return;
    }

    bit_pos = (index - 1) * 11;
    for (int bit = 0; bit < 11; bit++) {
        int bit_value = (value >> (10 - bit)) & 1;
        set_bit(buffer, bit_pos + bit, bit_value);
    }
}

static void clear_string(char *text) {
    if (text != NULL) {
        text[0] = '\0';
    }
}

static void remove_last_char(char *text) {
    size_t len;

    if (text == NULL) {
        return;
    }

    len = strlen(text);
    if (len > 0) {
        text[len - 1] = '\0';
    }
}

static char *add_char(char *text, int letter_index, size_t capacity) {
    size_t len;

    if (text == NULL || capacity == 0 || letter_index < 0 || letter_index > 25) {
        return text;
    }

    len = strlen(text);
    if (len + 1 >= capacity) {
        return text;
    }
    
    // FIX: Base character is now 'a' instead of 'A'
    text[len] = (char)('a' + letter_index);
    text[len + 1] = '\0';
    return text;
}

static char *add_char_dice(char *text, int num, size_t capacity) {
    size_t len;
    if (text == NULL || capacity == 0 || num < 1 || num > 6) {
        return text;
    }
    len = strlen(text);
    if (len + 1 >= capacity) {
        return text;
    }
    text[len] = (char)('0' + num);
    text[len + 1] = '\0';
    return text;
}

static void get_valid_next_letters(const char *prefix, bool *valid_letters) {
    for (int i = 0; i < 26; i++) {
        valid_letters[i] = false;
    }

    size_t prefix_len = 0;
    if (prefix != NULL) {
        prefix_len = strlen(prefix);
    }

    if (prefix_len == 0) {
        for (int i = 0; i < 26; i++) {
            if (i != ('x' - 'a')) valid_letters[i] = true;
        }
        return;
    }

    const char* ptr = bip39_words;
    for (int i = 0; i < 2048; ++i) {
        int cmp = strncmp(ptr, prefix, prefix_len);
        if (cmp == 0) {
            char next_char = ptr[prefix_len];
            // FIX: Check against lowercase ASCII boundaries
            if (next_char >= 'a' && next_char <= 'z') {
                valid_letters[next_char - 'a'] = true;
            }
        } else if (cmp > 0) {
            break; // Dictionary is sorted, we can stop
        }
        while (*ptr != '\0') ptr++;
        ptr++;
    }
}

static const char *search_unique_prefix(const char *prefix, char *result, size_t result_size) {
    const char *unique_match = NULL;
    size_t prefix_len;
    int match_count = 0;

    if (result == NULL || result_size == 0) return NULL;
    result[0] = '\0';
    if (prefix == NULL) return NULL;

    prefix_len = strlen(prefix);
    if (prefix_len == 0) return NULL;

    const char* ptr = bip39_words;
    
    for (int i = 0; i < 2048; ++i) {
        // Compare prefix with the currently pointed word
        if (strncmp(ptr, prefix, prefix_len) == 0) {
            
            // --- EXACT MATCH CHECK ---
            // If the next character in the dictionary is null, the length is identical
            if (ptr[prefix_len] == '\0') {
                unique_match = ptr;
                match_count = 1;
                break; // Exact match, stop searching
            }

            unique_match = ptr;
            match_count++;
            if (match_count > 1) {
                return NULL; // More than one match
            }
        }
        
        // Advance to the next word
        while (*ptr != '\0') {
            ptr++;
        }
        ptr++;
    }

        // Safe return if no match is found (though the smart keyboard makes this unreachable)
        if (unique_match == NULL) {
            return NULL;
        }

        size_t i = 0;
        while (i < (result_size - 1) && unique_match[i] != '\0') {
            result[i] = unique_match[i];
            i++;
        }
        result[i] = '\0';
        return result;
}


bool check_last_word(BYTE *data, size_t size, char* word_user) {
    int bit_index = 0;
    int unused_tail_bits = 4; // Unused trailing bits for 128-bit entropy
    if (size==33){
        unused_tail_bits = 0; // No unused trailing bits for 256-bit entropy
    }
    unsigned int group = 0;
    for (size_t i = ((size * 8) - 11 - unused_tail_bits); i < size * 8; i++) {
        // Read the current bit.
        int byte_index = i / 8;
        int bit_position = 7 - (i % 8);
        int bit = (data[byte_index] >> bit_position) & 1;

        // Add the current bit to the 11-bit group.
        group = (group << 1) | bit;
        bit_index++;

        // Once 11 bits are collected, validate the last word.
        if (bit_index == 11) {
            const char *word = get_word(group);
            group = 0;
            bit_index = 0;
            if (strcmp(word_user, word) == 0) {
                return true;
            }   else{
                return false;
            }
        }
    }
    return false;
}


void redraw_show_seed_with_offset(void) {
    black_screen();
    if (main_pointer == cMAIN_create && seed_pointer == cSEED_triple) {
         extract_word_offset = (triple_view_state == 2) ? 12 : 0;
    } else {
         extract_word_offset = 0;
         triple_view_state = 0;
    }
    
    BYTE *c_buf = append_checksum(data_array_256b, 16 + size_pointer*16);
    extract_11bit_groups(c_buf, 16  + size_pointer*16 +1);    
    
    // Intercept to compute keys in the background while blocking user input.
    // We skip this if navigating BIP85, as it doesn't need BIP84 keys.
    if (!bip84_account_cached && (main_pointer != cMAIN_BIP85)) {
        estado = PRECOMPUTE_BIP84;
        return; 
    }

    estado = SHOW_SEED;
}

void refresh_triple_view(void) {
    if (triple_view_state == 0) {
        for(int i=0; i<36; i++) data_array_256b[i] = triple_backup_256b[i];
        size_pointer = cSIZE_24;
    } else if (triple_view_state == 1) {
        for(int i=0; i<36; i++) data_array_256b[i] = 0;
        for(int i=0; i<16; i++) data_array_256b[i] = triple_backup_256b[i];
        size_pointer = cSIZE_12;
    } else if (triple_view_state == 2) {
        for(int i=0; i<36; i++) data_array_256b[i] = 0;
        for(int b=0; b<128; b++) {
            int bit = read_entropy_bit(triple_backup_256b, 132 + b);
            set_bit(data_array_256b, b, bit);
        }
        size_pointer = cSIZE_12;
    }
    redraw_show_seed_with_offset();
}

void reset_current_word_list_buffer(void) {
    for (int i = 0; i < 36; i++) {
        data_array_256b[i] = 0;
    }
}


// ============================================================================
// Shared Keyboard Selection Updater
// ============================================================================
void update_keyboard_selection(int *lt_idx, int step, const char *word, bool found_bool, int word_number, char *word_number_text) {
    *lt_idx = get_next_valid_key(*lt_idx, step, word, found_bool);
    print_word_number_top(word_number, word_number_text);
    print_keyboard_with_validation(*lt_idx, found_bool, word);
}


void print_keyboard_with_validation(int index, bool word_found, const char *current_word) {
    bool valid_letters[26];
    get_valid_next_letters(current_word, valid_letters);
    print_keyboard(index, word_found, valid_letters);
}


void set_bit(BYTE data_array[36], int bit_index, int value) {
    if (bit_index < 0 || bit_index >= 288 || (value != 0 && value != 1)) {
        // Index out of range
        return;
    }

    int byte_index = bit_index / 8;
    int bit_position = 7 - (bit_index % 8); // MSB to LSB

    if (value == 1) {
        data_array[byte_index] |= (1 << bit_position);
    } else {
        data_array[byte_index] &= ~(1 << bit_position);
    }
}


void addsub_11bit_groups(size_t size, int amount, int add_sub) {
    const size_t total_bits = size * 8;
    unsigned int group = 0;   // Current 11-bit value (0..2047)
    int bit_index = 0;        // Number of bits accumulated so far (0..11)

    for (size_t i = 0; i < total_bits; i++) {
        // Read the current bit (MSB-first in each byte).
        size_t byte_index = i / 8;
        int bit_position = 7 - (int)(i % 8);
        int bit = (data_array_256b[byte_index] >> bit_position) & 1;

        // Accumulate the bit into the current group.
        group = (group << 1) | (unsigned int)bit;
        bit_index++;

        // Process the group every time 11 bits are collected.
        if (bit_index == 11) {
            // Add or subtract with 11-bit wraparound (mod 2048).
            unsigned int new_group;
            if (add_sub == 0) {
                new_group = (group + (unsigned int)amount) & 0x7FFu;
            } else {
                // Using & 0x7FF keeps the value wrapped to 11 bits.
                new_group = (group - (unsigned int)amount) & 0x7FFu;
            }

            // Write the updated 11 bits back to positions [i-10 .. i].
            for (int j = 0; j < 11; j++) {
                size_t k = (size_t)(i - 10 + j);        // Bit index in the global stream
                size_t bi = k / 8;                      // Target byte
                int bp = 7 - (int)(k % 8);              // Bit position (MSB-first)
                int b = (int)((new_group >> (10 - j)) & 1u);

                if (b) {
                    data_array_256b[bi] |= (uint8_t)(1u << bp);
                } else {
                    data_array_256b[bi] &= (uint8_t)~(1u << bp);
                }
            }

            // Reset accumulators for the next group.
            group = 0;
            bit_index = 0;
        }
    }
}


void extract_11bit_groups(BYTE *data, size_t size) {
    int bit_index = 0;
    int y_index = 1;
    int x_index = 0;
    int word_index = 1 + extract_word_offset;
    unsigned int group = 0;
    int total_words = (size * 8) / 11;
    for (size_t i = 0; i < size * 8; i++) {
        // Read the current bit.
        int byte_index = i / 8;
        int bit_position = 7 - (i % 8);
        int bit = (data[byte_index] >> bit_position) & 1;

        // Add the current bit to the 11-bit group.
        group = (group << 1) | bit;
        bit_index++;

        // Once 11 bits are collected, render the word index.
        if (bit_index == 11) {

            char word_index_text[12]; // 3 digits plus null terminator
            u16_to_str((unsigned int)word_index, word_index_text);
            drawtext(x_index,y_index, word_index_text, ST7735_WHITE, ST7735_BLACK, 1);
            const char *word = get_word(group);
            
            uint16_t color;
            if (main_pointer == cMAIN_create && seed_pointer == cSEED_triple && triple_view_state == 0) {
                color = (word_index == 12 || word_index == 23 || word_index == 24) ? ST7735_GREEN : ST7735_WHITE;
            } else {
                color = (word_index == total_words + extract_word_offset) ? ST7735_GREEN : ST7735_WHITE;
            }

            drawtext(x_index + 15, y_index, (char *)word, color, ST7735_BLACK, 1);
            y_index+=9;
            if (y_index>100){
                x_index= 70;
                y_index= 0;
            }
            group = 0;
            bit_index = 0;
            word_index+=1;
        }
    }
    print_camera(145,20,cNOTSAFE);
    // QR functions moved to the next menu, so we just show a MENU hint
    drawtext(120, 117, "LOAD", ST7735_ORANGE, ST7735_BLACK, 1);
    print_rigth_arrow(150, 123, ST7735_WHITE);
    
    drawtext(7,117, "SAVE TO SD", ST7735_ORANGE, ST7735_BLACK, 1);
    print_left_arrow(0,123, ST7735_WHITE);
    if ((main_pointer==cMAIN_SSS) & (sss_pointer==cSPLIT)){
        char shareid_text[4];
        u16_to_str((unsigned int)selected_share_id, shareid_text);
        drawtext(145,30, "ID", ST7735_CYAN, ST7735_BLACK, 1);
        drawtext(146,40, shareid_text, ST7735_CYAN, ST7735_BLACK, 2);
        if (selected_share_id>1)print_up_arrow(72,123, ST7735_WHITE);
        if (selected_share_id<cN_MAX)print_down_arrow(80,123,ST7735_WHITE);
    }
    if (main_pointer == cMAIN_create && seed_pointer == cSEED_triple) {
         if (triple_view_state > 0) print_up_arrow(72,123, ST7735_WHITE);
         if (triple_view_state < 2) print_down_arrow(80,123, ST7735_WHITE);
    }
}


void print_previous_confirmed_word(int current_word_number, char *word_number_text) {
    if (capturing_xor_word) return; // Do not draw previous word on XOR capture
    
    const char *previous_word;

    clear_write_word_previous_display();

    if (current_word_number <= 1) {
        return;
    }

    previous_word = get_confirmed_word_from_entropy(data_array_256b, current_word_number - 1);
    if (previous_word == NULL) {
        return;
    }

    u16_to_str((unsigned int)(current_word_number - 1), word_number_text);
    drawtext(45,80, word_number_text, ST7735_GREEN, ST7735_BLACK, 1);
    drawtext(60,80, (char *)previous_word, ST7735_GREEN, ST7735_BLACK, 1);
}

static BYTE *append_checksum(BYTE *data_array, int N) {
    BYTE hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    
    // Statically allocated buffer handles up to 32 bytes of entropy + 1 checksum byte
    static BYTE checksum_buffer[33]; 

    sha256_init(&ctx);
    sha256_update(&ctx, data_array, (size_t)N);
    sha256_final(&ctx, hash);

    for (int i = 0; i < N; i++) {
        checksum_buffer[i] = data_array[i];
    }

    if (N == 16) {
        checksum_buffer[16] = hash[0] & 0xF0;
    } else {
        checksum_buffer[32] = hash[0];
    }

    return checksum_buffer;
}

static bool matches_last_word_checksum(BYTE *data_array, char *word_user, int sel_size) {
    BYTE *checksum_buffer = append_checksum(data_array, 16 + 16 * sel_size);
    bool matches;

    if (checksum_buffer == NULL) {
        return false;
    }

    matches = check_last_word(checksum_buffer, (size_t)(17 + 16 * sel_size), word_user);
    
    return matches;
}

static void shift_left(BYTE *data, int N)
{
    uint8_t carry;

    if (!data || N <= 0) {
        return;
    }

    carry = (uint8_t)((data[0] & 0x80) >> 7);

    for (int i = N - 1; i >= 0; --i) {
        uint8_t new_carry = (uint8_t)((data[i] & 0x80) >> 7);
        data[i] = (uint8_t)((data[i] << 1) | carry);
        carry = new_carry;
    }
}

static void not_operator(BYTE *data, int N)
{
    if (!data || N <= 0) {
        return;
    }

    for (int i = 0; i < N; ++i) {
        data[i] = (BYTE)~data[i];
    }
}

static void shift_right(BYTE *data, int N)
{
    BYTE carry;

    if (!data || N <= 0) {
        return;
    }

    carry = (BYTE)(data[N - 1] & 0x01);

    for (int i = 0; i < N; ++i) {
        BYTE new_carry = (BYTE)(data[i] & 0x01);
        data[i] = (BYTE)((data[i] >> 1) | (carry << 7));
        carry = new_carry;
    }
}


const char* refresh_word_input_preview(char *word, char *result, size_t result_size, bool *found_bool) {
    const char *found = search_unique_prefix(word, result, result_size);

    *found_bool = false;
    clear_write_word_current_display();
    drawtext(130, 60, OK_MSG, ST7735_GREY, ST7735_BLACK, 1);

    if (strlen(word) == 0) {
        return found;
    }

    drawtext(60, 10, word, ST7735_WHITE, ST7735_BLACK, 1);

    
    if (found != NULL) {
        clear_write_word_current_display();
        drawtext(60, 10, result, ST7735_GREEN, ST7735_BLACK, 1);
        drawtext(130, 60, OK_MSG, ST7735_GREEN, ST7735_BLACK, 1);
        *found_bool = true;
    }

    return found;
}


//  [cmd|0x40][arg3][arg2][arg1][arg0][crc]
void sd_send_cmd(uint8_t cmd, uint32_t arg, uint8_t crc) {
    spi_send(0x40 | cmd);
    spi_send((arg >> 24) & 0xFF);
    spi_send((arg >> 16) & 0xFF);
    spi_send((arg >> 8)  & 0xFF);
    spi_send(arg & 0xFF);
    spi_send(crc);
}

uint8_t spi_recv(void) {
    // --- V2: Hardware SPI3 ---
    SPI3BUF = 0xFF;                  // Send a dummy byte to generate the clock pulses (SCK)
    while (!SPI3STATbits.SPIRBF);    // Wait until the receive buffer is full
    return SPI3BUF;                  // Read and return the incoming data from the SD card

}

uint8_t sd_get_response(void) {
    uint8_t r;
    uint32_t timeout = 20000; // Adjust for the SPI speed in use.

    while (timeout > 0) {
        r = spi_recv();
        if (r != 0xFF) return r; // Response received
        timeout--;
    }
    return 0xFF; // Timeout

}


// Assumes: SD_CS controls chip select, spi_send()/spi_recv() are implemented,
// sd_get_response() uses the timeout-safe loop, and drawtext() renders on ST7735.

static bool sd_is_sdhc = false;

bool sd_init(void) {
        SPI3BRG = 0x0004;     // SLOW speed for initialization (sd_init)
    // 74+ clocks with CS held high
    SD_CS = 1;
    for (int i = 0; i < 10; i++) spi_send(0xFF); // 80 clocks

    // ---- CMD0: GO_IDLE_STATE ----
    SD_CS = 0;
    sd_send_cmd(0, 0x00000000, 0x95);
    uint8_t r1 = sd_get_response();               // Read R1
    SD_CS = 1; spi_send(0xFF);                    // Release + extra clocks
    if (r1 != 0x01) {                             // Card must be in IDLE
        return false;
    }

    // ---- CMD8: SEND_IF_COND ----
    SD_CS = 0;
    sd_send_cmd(8, 0x000001AA, 0x87);             // Check 2.7-3.6V range + echo 0xAA
    r1 = sd_get_response();
    uint8_t cmd8_extra[4] = {0};
    // Read the 4 extra bytes (echo + voltage).
    cmd8_extra[0] = spi_recv();
    cmd8_extra[1] = spi_recv();
    cmd8_extra[2] = spi_recv();
    cmd8_extra[3] = spi_recv();
    SD_CS = 1; spi_send(0xFF);

    if (r1 == 0x01) {
        if (cmd8_extra[2] == 0x01 && cmd8_extra[3] == 0xAA) {
            // OK
        } else {
            return false;
        }
    }


    bool v2_card = (r1 == 0x01);                  // v2 cards usually answer with 0x01

    // ---- Loop: CMD55 + ACMD41 ----
    // Request HCS=1 for SDHC/SDXC-capable cards.
    uint32_t tries = 10000;
    do {
        // CMD55
        SD_CS = 0;
        sd_send_cmd(55, 0x00000000, 0x65);
        r1 = sd_get_response();
        SD_CS = 1; spi_send(0xFF);

        // ACMD41 (argument carries HCS when the card is v2)
        SD_CS = 0;
        uint32_t arg = v2_card ? 0x40000000 : 0x00000000; // HCS bit31
        sd_send_cmd(41, arg, 0x77);
        r1 = sd_get_response();
        SD_CS = 1; spi_send(0xFF);

        if (r1 == 0x00) break; // Ready: leaves idle state
    } while (--tries);

    if (r1 != 0x00) {
        return false;
    }

    // ---- CMD58: READ_OCR ----
    SD_CS = 0;
    sd_send_cmd(58, 0x00000000, 0xFD);
    r1 = sd_get_response();
    uint8_t ocr[4] = {0};
    ocr[0] = spi_recv(); // MSB
    ocr[1] = spi_recv();
    ocr[2] = spi_recv();
    ocr[3] = spi_recv(); // LSB
    SD_CS = 1; spi_send(0xFF);

    if (r1 != 0x00) {
        return false;
    }

    // Bit CCS (Card Capacity Status) in OCR MSB bit6
    sd_is_sdhc = (ocr[0] & 0x40) != 0;

    // ---- CMD16: SET_BLOCKLEN (only SDSC; SDHC ignores, always 512) ----
    if (!sd_is_sdhc) {
        SD_CS = 0;
        sd_send_cmd(16, 512, 0x15);
        r1 = sd_get_response();
        SD_CS = 1; spi_send(0xFF);
        if (r1 != 0x00) {
            return false;
        }
    }
    
        // Switch SPI3 back to high speed for data transfers
        SPI3BRG = 1; 


    return true;
}


// Read R1 response of SD command (first byte different from 0xFF)
// Returns 0xFF if there is a timeout
uint8_t sd_get_r1(void) {
    uint8_t r;
    uint32_t timeout = 20000; // Wide margin for bit banging
    while (timeout--) {
        r = spi_recv();
        if (r != 0xFF) return r; // Response received
    }
    return 0xFF; // Timeout
}

bool sd_write_block(uint32_t sector, const uint8_t *buffer) {
    uint32_t arg = sd_is_sdhc ? sector : (sector * 512);

    SD_CS = 0;
    sd_send_cmd(24, arg, 0xFF); // CMD24: WRITE_SINGLE_BLOCK
    uint8_t r1 = sd_get_r1();
    if (r1 != 0x00) { SD_CS=1; spi_send(0xFF); return false; }

    // Data start token
    spi_send(0xFE);

    // Write 512 bytes
    for (int i = 0; i < 512; i++) spi_send(buffer[i]);

    // CRC bytes (0xFFFF is acceptable when CRC is not computed)
    spi_send(0xFF);
    spi_send(0xFF);

    // Data response: 0bXXX00101 means accepted
    uint8_t resp = spi_recv();
    if ((resp & 0x1F) != 0x05) { SD_CS=1; spi_send(0xFF); return false; }

    // Wait for the card to finish (busy = 0x00, until it returns 0xFF)
    uint32_t wait = 100000;
    uint8_t b;
    do {
        b = spi_recv();
        if (b == 0xFF) break;
    } while (--wait);

    SD_CS = 1;
    spi_send(0xFF);
    return (b == 0xFF);
}


// For SDHC, 'sector' is passed as a direct argument.
// For SDSC, the argument is byte address = sector * 512.
bool sd_read_block(uint32_t sector, uint8_t *buffer) {
    return sd_read_partial(sector, 0, 512, buffer);
}

// Reads 'count' bytes at 'offset' inside one sector. The rest of the sector
// is clocked out and dropped, so no 512-byte buffer is needed. dst == NULL
// discards the data too.
bool sd_read_partial(uint32_t sector, uint32_t offset, uint32_t count, uint8_t *dst) {
    if (offset > 512 || count > 512 - offset) return false;
    uint32_t arg = sd_is_sdhc ? sector : (sector * 512);

    SD_CS = 0;
    sd_send_cmd(17, arg, 0xFF); // CMD17: READ_SINGLE_BLOCK
    uint8_t r1 = sd_get_r1();
    if (r1 != 0x00) { SD_CS = 1; spi_send(0xFF); return false; }

    // Wait for data start token 0xFE
    uint32_t wait = 100000;
    uint8_t token;
    do {
        token = spi_recv();
        if (token == 0xFE) break;
    } while (--wait);

    if (token != 0xFE) { SD_CS = 1; spi_send(0xFF); return false; }

    for (uint32_t i = 0; i < 512; i++) {
        uint8_t b = spi_recv();
        if (dst != NULL && i >= offset && i - offset < count) dst[i - offset] = b;
    }

    // Read CRC (two bytes, safe to ignore here)
    spi_recv(); spi_recv();

    SD_CS = 1;
    spi_send(0xFF);
    return true;
}

// Buffer for the SD card
uint8_t buffer[512];


static int load_and_verify_sd_slot(int absolute_slot) {
    if (!sd_read_block(absolute_slot, buffer)) {
        sd_init();
    }
    if (sd_read_block(absolute_slot, buffer)) {
        BYTE checksum_SD = 1;
        BYTE XOR_SD = buffer[cSD_XOR_ADDR];
        for (int i = 0; i < 32; i++) {
            data_array_256b[i] = buffer[i] ^ XOR_SD;
            checksum_SD += buffer[i];
        }
        if (checksum_SD == buffer[cSD_CHECKSUM_ADDR]) {
            return 0; // Success
        }
        return 2; // Checksum Error
    }
    return 1; // SD Error
}


#ifndef BS_LANES
#define BS_LANES 32  // Number of parallel bytes processed per block
#endif


#define POLY_DEGREE_MAX 6

/* Evaluates Y = sum_{k=0..degree} c_k * x^k (GF(256)) for a bitsliced block.
      - c_in[0] = c0 (secret), c_in[1] = c1, ..., c_in[degree] = cN
      - blk_len: bytes in the block (<= BS_LANES)
      - x_val: same x value for all lanes
*/
static void eval_poly_block(uint8_t *y_out,
                            const uint8_t *c_in[],  // c0..cN
                            size_t degree,          // N (<= 6)
                            size_t blk_len,
                            uint8_t x_val)
{
    uint32_t X[8], Y[8], T[8], Ck[8];

    // X = x_val for all lanes
    bitslice_setall(X, x_val);

    // Y = c_N
    bitslice(Y, c_in[degree], blk_len);

    // Horner: Y = (...((c_N * X + c_{N-1}) * X + ...) * X + c_0)
    for (size_t k = degree; k-- > 0; ) {
        gf256_mul(T, Y, X);       // T = Y * X
        bitslice(Ck, c_in[k], blk_len); // Ck = c_k
        for (int i = 0; i < 8; ++i) Y[i] = T[i];
        gf256_add(Y, Ck);         // Y ^= Ck
    }

    unbitslice(y_out, Y, blk_len);
}


/* Generic split:
   - f(x) = c0 + c1*x + ... + cN*x^N  (N <= 6)
   - c0: secret buffer (len bytes)
   - coeffs: array of N pointers to buffers (c1..cN), each len bytes
   - x_vals: array of x's (non-zero, distinct from each other)
   - shares: array of x_count pointers to output buffers (each len bytes)
*/
bool sss_split_polyN(const uint8_t *c0,
                     const uint8_t *coeffs[], size_t degree,  // N
                     size_t len,
                     const uint8_t *x_vals, size_t x_count,
                     uint8_t *shares[])
{
    if (degree > POLY_DEGREE_MAX) return false;
    if (x_count == 0) return false;

    size_t off = 0;
    const uint8_t *c_in_local[POLY_DEGREE_MAX + 1]; // c0..cN

    // Build the coefficient vector expected by eval_poly_block
    c_in_local[0] = c0;
    for (size_t k = 1; k <= degree; ++k) {
        c_in_local[k] = coeffs[k - 1];
    }

    while (off < len) {
        size_t blk = len - off;
        if (blk > BS_LANES) blk = BS_LANES;

        for (size_t j = 0; j < x_count; ++j) {
            uint8_t x = x_vals[j];
            eval_poly_block(shares[j] + off,
                            (const uint8_t **)&c_in_local,
                            degree,
                            blk,
                            x);
        }

        off += blk;
    }
    return true;
}


/* Split (k-of-m) with polynomial degree N=k-1 <= 6
   - secret = c0
   - coeffs[0..k-2] = c1..cN (Non-zero random, len bytes each)
   - shares[0..m-1]: Pointers to output buffers (each len bytes)
*/
bool sss_split_kofm(const uint8_t *secret,
                    const uint8_t *coeffs[], size_t k,  // k >= 1
                    size_t len,
                    size_t m,
                    uint8_t *shares[])
{
    if (k == 0) return false;
    size_t degree = (k > 0) ? (k - 1) : 0;

    if (degree > POLY_DEGREE_MAX) return false;
    if (m == 0) return false;
    if (m > 255) return false; // x are uint8

    uint8_t x_vals[255];
    for (size_t j = 0; j < m; ++j) {
        x_vals[j] = (uint8_t)(j + 1); // x = 1..m (does not include 0)
    }

    return sss_split_polyN(secret, coeffs, degree, len,
                                x_vals, m, shares);
}


/* ===== Entropy extraction: LSB ADC + timer jitter ===== */

static void tmr1_init(void)
{
    T1CONbits.ON    = 0;        // Turn off Timer1 while configuring
    T1CONbits.TCS   = 0;        // 0 = Internal clock (PBCLK)
    T1CONbits.TGATE = 0;        // Gate disabled
    T1CONbits.TCKPS = 0;        // Prescaler
    T1CONbits.SIDL  = 0;        // Do not stop in Idle
    PMD4bits.T1MD   = 0;
    PR1             = 0xFFFF;
    T1CONbits.ON    = 1;        // Start Timer1
}


/* ===== Entropy extraction: LSB ADC + timer jitter ===== */
void dice_xy_pointer_line_adjust(){
    if ((seed_pointer==cSEED_timer) ||  (main_pointer ==cMAIN_SSS)){
         if (dice_x_pointer > cEND_OF_LINE-54){
            dice_x_pointer = 0;
            dice_y_pointer = dice_y_pointer +10;
        } else {
            dice_x_pointer = dice_x_pointer+6*4;
        }
    } else{
        if (dice_x_pointer > cEND_OF_LINE){
            dice_x_pointer = 0;
            dice_y_pointer = dice_y_pointer +10;
        } else {
            dice_x_pointer = dice_x_pointer+7;
        }
    }
}

bool check_dice_count_end(){
    int target_bits = (size_pointer == cSIZE_12) ? 128 : 256;
    if (bit_count_dice >= target_bits){
        if (main_pointer != cMAIN_SSS){
            black_screen();
            if (main_pointer == cMAIN_create) {
                if (seed_pointer == cSEED_triple) {
                    estado = PROCESS_TRIPLE;
                } else {
                    print_checksum_screen();
                    estado = SHOW_CHECKSUM_DETAILS;
                }
            } else {
                redraw_show_seed_with_offset();
            }
        }
        return true;
    } else {
        return false;
    }
}

// ============================================================================
// Shared Entropy Rendering Helper
// ============================================================================
void refresh_entropy_screen(void) {
    if (check_dice_count_end()) return;
    draw_shared_entropy_building();
    update_dice_bit_count_display(bit_count_dice);
}


// ============================================================================
// State Machine Transition Helpers
// ============================================================================

// Helper to transition to the SEL_SD_BLOCK screen
void transition_to_sd_block(int sd_ptr) {
    black_screen();
    sel_sd_block_screen_generic(sd_ptr);
    estado = SEL_SD_BLOCK;
}
// Helper to transition to the MAIN screen
void transition_to_main(void) {
    black_screen();
    // Invalidate the cache when returning to the main menu to prevent stale sessions
    bip84_account_cached = false; 
    main_screen(main_pointer);
    estado = MAIN;
}

// Helper to transition to the SEL_INPUT screen
void transition_to_input(int sel_ptr) {
    black_screen();
    print_generic_menu(menu_input, cSELINPUT_n_opt, sel_ptr);
    estado = SEL_INPUT;
}

// Helper to transition to the SEL_SIZE screen
void transition_to_size(void) {
    black_screen();
    print_generic_menu(menu_size, cSIZE_n_opt, size_pointer);
    estado = SEL_SIZE;
}


// Helper to transition to the CREATE_SEED screen
void transition_to_create_seed(void) {
    black_screen();
    print_generic_menu(menu_create, cSEED_n_opt, seed_pointer);
    estado = CREATE_SEED;
}

// Helper to transition to the SEL_OBFUS screen
void transition_to_obfus(void) {
    black_screen();
    print_generic_menu(menu_obfus, cOBFUS_n_opt, obfuscation_pointer);
    estado = SEL_OBFUS;
}

bool is_share_id_already_loaded(uint8_t id, uint8_t *indices) {
    for (int i = 0; i < shares_loaded; i++) {
        if (indices[i] == id) {
            return true;
        }
    }
    return false;
}


void apply_1word_xor(int word_idx, int size) {
    BYTE xor_mask[36] = {0};
    int total_words = (size == cSIZE_12) ? 12 : 24;

    // Repeat the 11-bit word index across the mask buffer
    for (int i = 1; i <= total_words + 1; i++) {
        write_11bit_value(xor_mask, i, word_idx);
    }

    // Apply bitwise XOR to the main entropy array
    int total_bytes = 16 + size * 16;
    for (int i = 0; i < total_bytes; i++) {
        data_array_256b[i] ^= xor_mask[i];
    }
}
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

// ============================================================================

// Reads the CSD register (CMD9) to determine exact SD card capacity
// Returns total number of sectors (512 bytes each), or 0 if error occurs
uint32_t sd_get_sector_count(void) {
    uint8_t csd[16];
    
    SD_CS = 0;
    sd_send_cmd(9, 0, 0xFF); // CMD9: SEND_CSD
    
    if (sd_get_r1() != 0x00) {
        SD_CS = 1; 
        spi_send(0xFF);
        return 0;
    }
    
    // Wait for the data start token 0xFE
    uint32_t wait = 100000;
    uint8_t token;
    do {
        token = spi_recv();
        if (token == 0xFE) break;
    } while (--wait);

    if (token != 0xFE) { 
        SD_CS = 1; 
        spi_send(0xFF); 
        return 0; 
    }

    // Read the 16 bytes of the CSD register
    for (int i = 0; i < 16; i++) {
        csd[i] = spi_recv();
    }
    
    // Discard CRC
    spi_recv(); 
    spi_recv(); 
    
    SD_CS = 1; 
    spi_send(0xFF);

    uint32_t sectors = 0;
    uint8_t csd_ver = (csd[0] >> 6) & 0x03;

    if (csd_ver == 0x00) {
        // CSD Version 1.0 (Standard Capacity SD, e.g., 32MB cards)
        uint16_t c_size = ((csd[6] & 0x03) << 10) | (csd[7] << 2) | ((csd[8] >> 6) & 0x03);
        uint8_t c_size_mult = ((csd[9] & 0x03) << 1) | ((csd[10] >> 7) & 0x01);
        uint8_t read_bl_len = csd[5] & 0x0F;
        
        uint32_t mult = 1 << (c_size_mult + 2);
        uint32_t block_len = 1 << read_bl_len;
        
        sectors = (c_size + 1) * mult * (block_len / 512);
    } else if (csd_ver == 0x01) {
        // CSD Version 2.0 (High Capacity SDHC/SDXC)
        uint32_t c_size = ((uint32_t)(csd[7] & 0x3F) << 16) | ((uint32_t)csd[8] << 8) | csd[9];
        sectors = (c_size + 1) * 1024;
    }
    
    return sectors;
}


//QR animated scan

// Helper: Fast trigger command via UART
static inline void trigger_gm861_scanner(void) {
    const uint8_t trigger_cmd[] = {0x7E, 0x00, 0x08, 0x01, 0x00, 0x02, 0x01, 0xAB, 0xCD};
    for (int i = 0; i < sizeof(trigger_cmd); i++) {
        while (U2STAbits.UTXBF);
        U2TXREG = trigger_cmd[i];
    }
}

// Helper: safe integer to string conversion
static void fast_itoa(uint32_t val, char* buf) {
    if (val == 0) {
        buf[0] = '0';
        buf[1] = '\0';
        return;
    }
    char temp[12];
    int i = 0;
    while (val > 0) {
        temp[i++] = (val % 10) + '0';
        val /= 10;
    }
    int j = 0;
    while (i > 0) {
        buf[j++] = temp[--i];
    }
    buf[j] = '\0';
}


// Helper to convert byte to a 2-character hex string
static void byte_to_hex(uint8_t val, char *out_str) {
    const char hex_chars[] = "0123456789ABCDEF";
    out_str[0] = hex_chars[(val >> 4) & 0x0F];
    out_str[1] = hex_chars[val & 0x0F];
    out_str[2] = '\0';
}

// Helper to read CBOR integer and advance cursor
static uint32_t read_cbor_int(const uint8_t *buf, uint32_t *idx) {
    uint8_t v = buf[(*idx)++] & 0x1F;
    if (v < 24) return v;
    if (v == 24) return buf[(*idx)++];
    if (v == 25) { uint32_t val = (buf[*idx]<<8) | buf[*idx+1]; *idx += 2; return val; }
    if (v == 26) {
        uint32_t val = (buf[*idx]<<24) | (buf[*idx+1]<<16) | (buf[*idx+2]<<8) | buf[*idx+3];
        *idx += 4;
        return val;
    }
    return 0;
}


// ============================================================================
// PSBT VIEWER (test screen; to be moved to screens.c once the flow is final)
// ============================================================================
#define PSBT_VIEW_LINE_CHARS 26     // 160 px / 6 px per char at text size 1

// Writes the address of an output script, or a short description when the
// script has no address form.
static void psbt_view_address(const uint8_t *script, uint32_t len, char *out) {
    psbt_script_type_t type = psbt_script_type(script, len);
    uint8_t payload[21];

    if (psbt_segwit_address(script, len, "bc", out, PSBT_ADDRESS_MAX_LEN)) return;

    if (type == PSBT_SCRIPT_P2PKH || type == PSBT_SCRIPT_P2SH) {
        payload[0] = (type == PSBT_SCRIPT_P2PKH) ? 0x00 : 0x05;   // Mainnet versions
        memcpy(&payload[1], (type == PSBT_SCRIPT_P2PKH) ? &script[3] : &script[2], 20);
        if (base58_encode_check(payload, sizeof(payload), out, PSBT_ADDRESS_MAX_LEN) > 0) return;
    }
    strcpy(out, (type == PSBT_SCRIPT_OP_RETURN) ? "OP_RETURN DATA" : "NON-STANDARD SCRIPT");
}

static void psbt_view_amount_line(int y, const char *label, bool known, uint64_t sats, uint16_t color) {
    char line[PSBT_BTC_STR_LEN + 12];
    strcpy(line, label);
    if (known) {
        char btc[PSBT_BTC_STR_LEN];
        psbt_format_btc(sats, btc);
        strcat(line, btc);
        strcat(line, " BTC");
    } else {
        strcat(line, "UNKNOWN");
    }
    drawtext(5, y, line, color, ST7735_BLACK, 1);
}

// Who owns an input or output, checked against the loaded seed
typedef enum {
    PSBT_OWNER_NO_INFO,     // No BIP32 derivation in the PSBT
    PSBT_OWNER_OTHER,       // Derivations present, none with our fingerprint
    PSBT_OWNER_FP_ONLY,     // Our fingerprint, but a path outside our BIP84 account
    PSBT_OWNER_VERIFIED,    // Key and script derived from our BIP84 account
    PSBT_OWNER_MISMATCH     // Our fingerprint and path, but a different key or script
} psbt_owner_t;

static bool psbt_fp_is_mine(uint32_t fingerprint) {
    return bip84_account_cached && fingerprint == bip84_master_fingerprint;
}

// m/84'/0'/0'/chain/index with chain 0 (receive) or 1 (change)
static bool psbt_is_bip84_path(const psbt_keypath_t *kp) {
    return kp->path_len == 5 &&
           psbt_path_element(kp, 0) == (84 | PSBT_HARDENED) &&
           psbt_path_element(kp, 1) == PSBT_HARDENED &&
           psbt_path_element(kp, 2) == PSBT_HARDENED &&
           psbt_path_element(kp, 3) <= 1 &&
           psbt_path_element(kp, 4) < PSBT_HARDENED;
}

// Derives the path's key from the cached account and checks that it is the
// key in the PSBT and that the script is the P2WPKH paying to it
static bool psbt_bip84_key_matches(const psbt_keypath_t *kp, const uint8_t *script, uint32_t script_len) {
    if (kp->key_len != 33 || psbt_script_type(script, script_len) != PSBT_SCRIPT_P2WPKH) return false;

    HDNode node = (psbt_path_element(kp, 3) == 0) ? bip84_receive_node_cache : bip84_change_node_cache;
    bool match = hdnode_private_ckd(&node, psbt_path_element(kp, 4)) != 0;
    if (match) {
        hdnode_fill_public_key(&node);
        match = memcmp(node.public_key, kp->key, 33) == 0;
    }
    if (match) {
        uint8_t sha256_pub[32];
        uint8_t hash160[20];
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, node.public_key, 33);
        sha256_final(&ctx, sha256_pub);
        ripemd160(sha256_pub, 32, hash160);
        match = memcmp(hash160, &script[2], 20) == 0;
    }
    memzero(&node, sizeof(node));   // Holds a private key
    return match;
}

// Classifies an input (is_input) or output and returns in 'shown' the
// derivation to display: ours if present, else the first one
static psbt_owner_t psbt_check_owner(const psbt_t *psbt, bool is_input, uint32_t index,
                                     const uint8_t *script, uint32_t script_len, psbt_keypath_t *shown) {
    psbt_keypath_t kp;
    bool any = false;

    for (uint32_t n = 0;
         is_input ? psbt_input_keypath(psbt, index, n, &kp) : psbt_output_keypath(psbt, index, n, &kp);
         n++) {
        if (!any) {
            *shown = kp;
            any = true;
        }
        if (!psbt_fp_is_mine(kp.fingerprint)) continue;

        *shown = kp;
        if (!psbt_is_bip84_path(&kp)) return PSBT_OWNER_FP_ONLY;
        return psbt_bip84_key_matches(&kp, script, script_len) ? PSBT_OWNER_VERIFIED : PSBT_OWNER_MISMATCH;
    }
    return any ? PSBT_OWNER_OTHER : PSBT_OWNER_NO_INFO;
}

// Ownership line at y and, when there is one, the derivation path below it
static void psbt_view_owner(int y, psbt_owner_t owner, const psbt_keypath_t *kp, bool is_output) {
    char text[PSBT_PATH_STR_LEN];

    switch (owner) {
        case PSBT_OWNER_NO_INFO:
            drawtext(5, y, is_output ? "EXTERNAL" : "NO KEY INFO", ST7735_WHITE, ST7735_BLACK, 1);
            return;
        case PSBT_OWNER_OTHER:
            strcpy(text, "OTHER FP ");
            psbt_format_fingerprint(kp->fingerprint, &text[9]);
            drawtext(5, y, text, ST7735_YELLOW, ST7735_BLACK, 1);
            break;
        case PSBT_OWNER_FP_ONLY:
            drawtext(5, y, "MY FP, PATH NOT CHECKED", ST7735_YELLOW, ST7735_BLACK, 1);
            break;
        case PSBT_OWNER_VERIFIED:
            if (!is_output) {
                strcpy(text, "MINE (VERIFIED)");
            } else {
                strcpy(text, (psbt_path_element(kp, 3) == 1) ? "CHANGE (VERIFIED)" : "MINE, RECEIVE (VERIFIED)");
            }
            drawtext(5, y, text, ST7735_GREEN, ST7735_BLACK, 1);
            break;
        default:
            drawtext(5, y, "KEY MISMATCH! NOT YOURS", ST7735_RED, ST7735_BLACK, 1);
            break;
    }
    psbt_format_path(kp, text);
    draw_bip84_wrapped_text(text, 5, y + 10, PSBT_VIEW_LINE_CHARS, 2);
}

// "MULTISIG m-OF-n" at y and up to 6 key fingerprints below, ours in green
static void psbt_view_multisig(int y, const psbt_t *psbt, bool is_input, uint32_t index,
                               const uint8_t *witness_script, uint32_t witness_len,
                               const uint8_t *redeem_script, uint32_t redeem_len) {
    uint8_t m, n;
    char line[24];
    char num[4];
    psbt_keypath_t kp;

    if (!psbt_multisig_info(witness_script, witness_len, &m, &n) &&
        !psbt_multisig_info(redeem_script, redeem_len, &m, &n)) {
        return;
    }
    strcpy(line, "MULTISIG ");
    fast_itoa(m, num);
    strcat(line, num);
    strcat(line, "-OF-");
    fast_itoa(n, num);
    strcat(line, num);
    drawtext(5, y, line, ST7735_CYAN, ST7735_BLACK, 1);

    for (uint32_t k = 0; k < 6; k++) {
        bool found = is_input ? psbt_input_keypath(psbt, index, k, &kp) : psbt_output_keypath(psbt, index, k, &kp);
        if (!found) break;
        psbt_format_fingerprint(kp.fingerprint, line);
        drawtext(1 + (k % 3) * 54, y + 10 + (k / 3) * 10, line,
                 psbt_fp_is_mine(kp.fingerprint) ? ST7735_GREEN : ST7735_WHITE, ST7735_BLACK, 1);
    }
}

// Page 0: totals, fee, our fingerprint, locktime/RBF and warnings
static void psbt_view_summary(const psbt_t *psbt) {
    char line[32];
    char num[12];
    uint64_t sum_in, sum_out, fee;
    bool totals_ok = psbt_get_totals(psbt, &sum_in, &sum_out);
    bool fee_ok = psbt_get_fee(psbt, &fee);
    uint32_t my_inputs = 0, signed_inputs = 0, odd_sighash = 0;
    psbt_input_t in;
    psbt_keypath_t kp;

    for (uint32_t i = 0; i < psbt->input_count; i++) {
        if (!psbt_get_input(psbt, i, &in)) continue;
        if (in.finalized || in.partial_sig_count > 0) signed_inputs++;
        if (in.has_sighash && in.sighash != PSBT_SIGHASH_ALL) odd_sighash++;
        for (uint32_t n = 0; psbt_input_keypath(psbt, i, n, &kp); n++) {
            if (psbt_fp_is_mine(kp.fingerprint)) {
                my_inputs++;
                break;
            }
        }
    }

    drawtext(5, 5, "TRANSACTION SUMMARY", ST7735_YELLOW, ST7735_BLACK, 1);

    strcpy(line, "INPUTS: ");
    fast_itoa(psbt->input_count, num);
    strcat(line, num);
    strcat(line, "  OUTPUTS: ");
    fast_itoa(psbt->output_count, num);
    strcat(line, num);
    drawtext(5, 17, line, ST7735_WHITE, ST7735_BLACK, 1);

    psbt_view_amount_line(29, "IN:  ", totals_ok, sum_in, ST7735_WHITE);
    psbt_view_amount_line(39, "OUT: ", true, sum_out, ST7735_WHITE);
    psbt_view_amount_line(49, "FEE: ", fee_ok, fee, fee_ok ? ST7735_ORANGE : ST7735_RED);

    // Inputs carrying our master fingerprint
    strcpy(line, "MY FP ");
    psbt_format_fingerprint(bip84_master_fingerprint, &line[6]);
    strcat(line, " IN ");
    fast_itoa(my_inputs, num);
    strcat(line, num);
    strcat(line, "/");
    fast_itoa(psbt->input_count, num);
    strcat(line, num);
    drawtext(5, 61, line, (my_inputs == psbt->input_count) ? ST7735_GREEN :
                          (my_inputs > 0) ? ST7735_YELLOW : ST7735_RED, ST7735_BLACK, 1);

    // Locktime: block height or UNIX time, and replace-by-fee signaling
    if (psbt->locktime == 0) {
        strcpy(line, "LOCK: NONE");
    } else {
        strcpy(line, (psbt->locktime < PSBT_LOCKTIME_THRESHOLD) ? "LOCK: BLK " : "LOCK: T ");
        fast_itoa(psbt->locktime, num);
        strcat(line, num);
    }
    if (psbt_signals_rbf(psbt)) strcat(line, " RBF");
    drawtext(5, 71, line, ST7735_WHITE, ST7735_BLACK, 1);

    // Global xpubs (multisig coordinators include all of them)
    uint32_t xpubs = 0;
    bool my_xpub = false;
    while (psbt_global_xpub(psbt, xpubs, &kp)) {
        if (psbt_fp_is_mine(kp.fingerprint)) my_xpub = true;
        xpubs++;
    }
    if (xpubs > 0) {
        strcpy(line, "XPUBS: ");
        fast_itoa(xpubs, num);
        strcat(line, num);
        strcat(line, my_xpub ? " (MINE IN)" : " (NOT MINE)");
        drawtext(5, 81, line, my_xpub ? ST7735_WHITE : ST7735_YELLOW, ST7735_BLACK, 1);
    }

    if (odd_sighash > 0) {
        drawtext(5, 93, "WARNING: SIGHASH NOT ALL", ST7735_RED, ST7735_BLACK, 1);
    }
    if (signed_inputs > 0) {
        strcpy(line, "ALREADY SIGNED: ");
        fast_itoa(signed_inputs, num);
        strcat(line, num);
        drawtext(5, 103, line, ST7735_CYAN, ST7735_BLACK, 1);
    }
}

static void psbt_view_input(const psbt_t *psbt, uint32_t index) {
    psbt_input_t in;
    psbt_keypath_t kp;
    char line[32];
    char num[12];
    char text[PSBT_ADDRESS_MAX_LEN];

    strcpy(line, "INPUT ");
    fast_itoa(index + 1, num);
    strcat(line, num);
    strcat(line, "/");
    fast_itoa(psbt->input_count, num);
    strcat(line, num);
    drawtext(5, 5, line, ST7735_YELLOW, ST7735_BLACK, 1);

    if (!psbt_get_input(psbt, index, &in)) {
        drawtext(5, 22, "READ ERROR", ST7735_RED, ST7735_BLACK, 1);
        return;
    }
    if (in.has_amount) {
        strcpy(line, psbt_script_type_name(psbt_script_type(in.script, in.script_len)));
        drawtext(90, 5, line, ST7735_CYAN, ST7735_BLACK, 1);
    }

    // Shortened outpoint: first and last 8 txid chars, then ":vout"
    psbt_format_txid(in.prev_txid, text);
    memcpy(line, text, 8);
    memcpy(&line[8], "...", 3);
    memcpy(&line[11], &text[56], 8);
    line[19] = ':';
    fast_itoa(in.prev_vout, &line[20]);
    drawtext(5, 15, line, ST7735_CYAN, ST7735_BLACK, 1);

    psbt_view_amount_line(25, "AMT: ", in.has_amount, in.amount, ST7735_WHITE);
    if (in.has_amount) {
        drawtext(5, 35, in.amount_from_witness ? "UTXO: WITNESS ONLY" : "UTXO: FULL PREV TX",
                 ST7735_CYAN, ST7735_BLACK, 1);
    }

    psbt_owner_t owner = psbt_check_owner(psbt, true, index, in.script, in.script_len, &kp);
    psbt_view_owner(45, owner, &kp, false);

    // Signing state and sighash, e.g. "SIGS:1 SIGHASH:ALL" (fits one line)
    if (in.finalized) {
        strcpy(line, "FINAL");
    } else {
        strcpy(line, "SIGS:");
        fast_itoa(in.partial_sig_count > 99 ? 99 : in.partial_sig_count, num);
        strcat(line, num);
    }
    bool odd_sighash = in.has_sighash && in.sighash != PSBT_SIGHASH_ALL;
    strcat(line, " SIGHASH:");
    strcat(line, in.has_sighash ? psbt_sighash_name(in.sighash) : "ALL");
    drawtext(5, 77, line, odd_sighash ? ST7735_RED : ST7735_WHITE, ST7735_BLACK, 1);

    psbt_view_multisig(88, psbt, true, index, in.witness_script, in.witness_script_len,
                       in.redeem_script, in.redeem_script_len);
}

static void psbt_view_output(const psbt_t *psbt, uint32_t index) {
    psbt_output_t out;
    psbt_keypath_t kp;
    char line[32];
    char num[12];
    char addr[PSBT_ADDRESS_MAX_LEN];

    strcpy(line, "OUTPUT ");
    fast_itoa(index + 1, num);
    strcat(line, num);
    strcat(line, "/");
    fast_itoa(psbt->output_count, num);
    strcat(line, num);
    drawtext(5, 5, line, ST7735_YELLOW, ST7735_BLACK, 1);

    if (!psbt_get_output(psbt, index, &out)) {
        drawtext(5, 22, "READ ERROR", ST7735_RED, ST7735_BLACK, 1);
        return;
    }
    strcpy(line, psbt_script_type_name(psbt_script_type(out.script, out.script_len)));
    drawtext(90, 5, line, ST7735_CYAN, ST7735_BLACK, 1);

    psbt_view_amount_line(15, "AMT: ", true, out.amount, ST7735_WHITE);

    psbt_view_address(out.script, out.script_len, addr);
    draw_bip84_wrapped_text(addr, 5, 27, PSBT_VIEW_LINE_CHARS, 3);

    psbt_owner_t owner = psbt_check_owner(psbt, false, index, out.script, out.script_len, &kp);
    psbt_view_owner(59, owner, &kp, true);

    psbt_view_multisig(88, psbt, false, index, out.witness_script, out.witness_script_len,
                       out.redeem_script, out.redeem_script_len);
}

// Parses a PSBT and lets the user page through summary, inputs and outputs.
// OK = next page, UP = previous page, BACK = exit.
static void show_psbt_details(const uint8_t *data, uint32_t len) {
    psbt_t psbt;
    psbt_status_t status = psbt_parse(data, len, &psbt);

    if (status != PSBT_OK) {
        char reason[24];
        strcpy(reason, psbt_status_name(status));   // drawtext() takes a non-const string
        black_screen();
        drawtext(5, 5, "PSBT PARSE ERROR", ST7735_RED, ST7735_BLACK, 1);
        drawtext(5, 20, reason, ST7735_WHITE, ST7735_BLACK, 1);
        drawtext(5, 110, "BACK=EXIT", ST7735_WHITE, ST7735_BLACK, 1);
        while (BT1 == 0) SYS_Tasks();   // Release the key that opened us
        while (BT1 == 1) SYS_Tasks();
        return;
    }

    uint32_t page_count = 1 + psbt.input_count + psbt.output_count;
    uint32_t page = 0;

    while (1) {
        black_screen();
        if (page == 0) {
            psbt_view_summary(&psbt);
        } else if (page <= psbt.input_count) {
            psbt_view_input(&psbt, page - 1);
        } else {
            psbt_view_output(&psbt, page - 1 - psbt.input_count);
        }
        drawtext(5, 118, "OK=NEXT UP=PREV BACK=EXIT", ST7735_WHITE, ST7735_BLACK, 1);

        while (BT_OK == 0 || BT1 == 0 || BT5 == 0) SYS_Tasks();   // Wait for release
        delay_ms(30);
        while (BT_OK == 1 && BT1 == 1 && BT5 == 1) SYS_Tasks();   // Wait for a press
        delay_ms(30);

        if (BT1 == 0) break;
        if (BT_OK == 0) {
            page = (page + 1) % page_count;
        } else if (BT5 == 0) {
            page = (page == 0) ? page_count - 1 : page - 1;
        }
    }
}

// ============================================================================
// PSBT from SD card: file picker and loader (binary .PSB or base64 .TXT)
// ============================================================================

#define PSBT_SD_LIST_ROWS 9
static const char *const psbt_sd_exts[] = {"PSB", "TXT"};

// Waits until no key is held, then for OK, BACK, UP or DOWN
static int psbt_wait_key(void) {
    while (BT_OK == 0 || BT1 == 0 || BT5 == 0 || BT4 == 0) SYS_Tasks();
    delay_ms(30);
    while (BT_OK == 1 && BT1 == 1 && BT5 == 1 && BT4 == 1) SYS_Tasks();
    delay_ms(30);
    if (BT1 == 0) return BACK_BT;
    if (BT_OK == 0) return OK_BT;
    return (BT5 == 0) ? UP_BT : DOWN_BT;
}

static void psbt_sd_message(char *title, char *detail) {
    black_screen();
    drawtext(5, 5, title, ST7735_RED, ST7735_BLACK, 1);
    drawtext(5, 20, detail, ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(5, 118, "PRESS ANY KEY", ST7735_WHITE, ST7735_BLACK, 1);
    psbt_wait_key();
}

// Reads file 'name' (file_size bytes) into buf. Binary PSBTs are copied as
// they are; base64 text is decoded on the fly. Returns the PSBT length, or 0
// with a reason in err (at least 24 chars).
static uint32_t psbt_sd_load(const char *name, uint32_t file_size, uint8_t *buf, uint32_t buf_size, char *err) {
    char chunk[64];
    uint32_t len = 0;
    int32_t got;

    if (!sd_files_open(name)) {
        strcpy(err, "CANNOT OPEN FILE");
        return 0;
    }
    got = sd_files_read(chunk, sizeof(chunk));
    if (got <= 0) {
        strcpy(err, (got < 0) ? "SD READ ERROR" : "EMPTY FILE");
        return 0;
    }

    // Binary: the file is the PSBT itself
    if (got >= 5 && memcmp(chunk, "psbt\xff", 5) == 0) {
        if (file_size > buf_size) {
            strcpy(err, "PSBT TOO BIG");
            return 0;
        }
        memcpy(buf, chunk, (uint32_t)got);
        len = (uint32_t)got;
        while ((got = sd_files_read(&buf[len], buf_size - len)) > 0) len += (uint32_t)got;
        if (got < 0) {
            strcpy(err, "SD READ ERROR");
            return 0;
        }
        return len;
    }

    // Base64 text, possibly after a UTF-8 BOM and whitespace
    uint32_t start = 0;
    if (got >= 3 && (uint8_t)chunk[0] == 0xEF && (uint8_t)chunk[1] == 0xBB && (uint8_t)chunk[2] == 0xBF) start = 3;
    while (start < (uint32_t)got && (chunk[start] == ' ' || chunk[start] == '\r' || chunk[start] == '\n')) start++;
    if ((uint32_t)got - start < 7 || memcmp(&chunk[start], "cHNidP8", 7) != 0) {
        strcpy(err, "NOT A PSBT FILE");
        return 0;
    }

    psbt_base64_t b64;
    psbt_base64_init(&b64);
    bool ok = psbt_base64_feed(&b64, &chunk[start], (uint32_t)got - start, buf, buf_size, &len);
    while (ok && (got = sd_files_read(chunk, sizeof(chunk))) > 0) {
        ok = psbt_base64_feed(&b64, chunk, (uint32_t)got, buf, buf_size, &len);
    }
    if (got < 0) {
        strcpy(err, "SD READ ERROR");
        return 0;
    }
    if (!ok || !psbt_base64_finish(&b64)) {
        strcpy(err, (len >= buf_size) ? "PSBT TOO BIG" : "BAD BASE64 TEXT");
        return 0;
    }
    return len;
}

// Lists .PSB/.TXT files in the SD root and shows the selected PSBT.
// OK = open, UP/DOWN = move, BACK = exit.
static void load_psbt_from_sd(void) {
    char name[SD_FILES_NAME_LEN];
    char line[32];
    char num[12];
    char err[24];
    uint32_t size, count = 0, sel = 0;

    black_screen();
    drawtext(5, 5, "READING SD CARD...", ST7735_YELLOW, ST7735_BLACK, 1);
    if (!sd_files_mount()) {
        psbt_sd_message("SD CARD ERROR", "NO CARD OR NOT FAT16");
        return;
    }
    while (count < 99 && sd_files_find(count, psbt_sd_exts, 2, name, &size)) count++;
    if (count == 0) {
        psbt_sd_message("NO PSBT FILES", "NEED .PSB OR .TXT FILE");
        return;
    }

    while (1) {
        black_screen();
        drawtext(5, 5, "SELECT PSBT FILE", ST7735_YELLOW, ST7735_BLACK, 1);
        uint32_t first = sel - sel % PSBT_SD_LIST_ROWS;
        for (uint32_t i = 0; i < PSBT_SD_LIST_ROWS && first + i < count; i++) {
            if (!sd_files_find(first + i, psbt_sd_exts, 2, name, &size)) break;
            strcpy(line, name);
            strcat(line, " ");
            fast_itoa(size, num);
            strcat(line, num);
            strcat(line, "B");
            drawtext(5, 17 + i * 10, line, (first + i == sel) ? ST7735_ORANGE : ST7735_WHITE, ST7735_BLACK, 1);
        }
        drawtext(5, 118, "OK=OPEN UP/DN BACK=EXIT", ST7735_WHITE, ST7735_BLACK, 1);

        int key = psbt_wait_key();
        if (key == BACK_BT) break;
        if (key == UP_BT) {
            sel = (sel == 0) ? count - 1 : sel - 1;
        } else if (key == DOWN_BT) {
            sel = (sel + 1) % count;
        } else if (sd_files_find(sel, psbt_sd_exts, 2, name, &size)) {
            black_screen();
            drawtext(5, 5, "LOADING PSBT...", ST7735_YELLOW, ST7735_BLACK, 1);
            uint32_t buf_size;
            uint8_t *buf = fountain_scratch_buffer(&buf_size);
            uint32_t len = psbt_sd_load(name, size, buf, buf_size, err);
            if (len == 0) {
                psbt_sd_message("LOAD ERROR", err);
            } else {
                show_psbt_details(buf, len);
            }
        }
    }
    while (BT1 == 0) SYS_Tasks();   // Do not let BACK reach the menu state machine
}

// ============================================================================
// PSBT export as an animated "ur:crypto-psbt" QR code
// ============================================================================

#define UR_QR_VERSION       8       // 49x49 modules: 98 px tall at scale 2
#define UR_QR_SCALE         2
#define UR_QR_MAX_FRAGMENT  100     // Bytes per frame; the text fits version 8, ECC L
#define UR_FRAME_DELAY_MS   150

// Loops over the UR parts of a PSBT until BACK is pressed. The parts are
// built one at a time on the stack, so RAM use does not depend on the PSBT.
static void show_ur_animated_qr(const uint8_t *psbt, uint32_t len) {
    ur_encoder_t ur;
    char part[UR_PART_MAX_CHARS(UR_QR_MAX_FRAGMENT) + 1];
    char label[12];
    char num[6];
    uint32_t seq = 1;

    if (!ur_encoder_init(&ur, psbt, len, UR_QR_MAX_FRAGMENT)) {
        psbt_sd_message("QR EXPORT ERROR", "PSBT TOO BIG OR EMPTY");
        return;
    }

    while (BT1 == 0) SYS_Tasks();   // Release the key that opened us
    white_screen();
    while (1) {
        if (ur_encoder_part(&ur, seq, part, sizeof(part)) == 0 ||
            !draw_qr_frame(part, UR_QR_VERSION, UR_QR_SCALE)) {
            psbt_sd_message("QR EXPORT ERROR", "FRAME DOES NOT FIT");
            return;
        }

        // Part counter in the left margin
        fast_itoa(seq, label);
        strcat(label, "/");
        fast_itoa(ur.seq_len, num);
        strcat(label, num);
        rectan(0, 56, 29, 66, WHITE);
        drawtext(1, 58, label, ST7735_BLACK, ST7735_WHITE, 1);

        for (uint32_t t = 0; t < UR_FRAME_DELAY_MS / 10; t++) {
            if (BT1 == 0) break;
            delay_ms(10);
            SYS_Tasks();
        }
        if (BT1 == 0) break;
        seq = (seq % ur.seq_len) + 1;
    }
    while (BT1 == 0) SYS_Tasks();   // Do not let BACK reach the menu state machine
}

void scan_ur_animated_qr(void) {
    black_screen();
    drawtext(10, 10, "SCANNING PSBT", ST7735_YELLOW, ST7735_BLACK, 1);
    drawtext(10, 105, "PRESS BACK TO CANCEL", ST7735_WHITE, ST7735_BLACK, 1);
    // Same progress bar outline as precompute_bip84_account()
    rectan(9, 120, 151, 125, WHITE);

    init_bytewords_lookup();
    fountain_init();

    uint32_t trigger_timeout = 200000;
    char burst_buffer[MAX_UR_PAYLOAD_LEN * 2 + 50];

    // Clear OERR flag and flush buffer ONLY once at startup
    if (U2STAbits.OERR) U2STAbits.OERR = 0;
    while (U2STAbits.URXDA) (void)U2RXREG;
    trigger_gm861_scanner();

    bool psbt_recovered = false;
    uint32_t expected_msg_len = 0;

    while (BT1 == 1) { 
        SYS_Tasks(); // Keep MCU watchdog alive in the main loop

        // PROBE 1: UART OVERRUN DETECTION
        if (U2STAbits.OERR) {
            U2STAbits.OERR = 0;
            drawtext(10, 20, "UART OERR DETECTED!", ST7735_RED, ST7735_BLACK, 1);
        }

        if (U2STAbits.URXDA) {
            int burst_idx = 0;
            uint32_t byte_timeout = 400000;

            while (byte_timeout > 0 && burst_idx < sizeof(burst_buffer) - 1) {
                SYS_Tasks(); // Keep MCU alive during long UART bursts
                
                if (U2STAbits.OERR) {
                    U2STAbits.OERR = 0;
                    drawtext(10, 20, "UART OERR DETECTED!", ST7735_RED, ST7735_BLACK, 1);
                }
                
                if (U2STAbits.URXDA) {
                    char c = U2RXREG;
                    byte_timeout = 400000; 
                    if (c == '\r' || c == '\n') {
                        if (burst_idx > 0) break;
                    } else {
                        burst_buffer[burst_idx++] = c;
                    }
                } else {
                    byte_timeout--;
                }
            }
            burst_buffer[burst_idx] = '\0';

            // Reset scanner timeout since we just received data
            trigger_timeout = 200000;

            if (burst_idx > 15) {
                const char target[] = "UR:CRYPTO-PSBT/";
                char *header_start = NULL;

                for (int i = 0; i <= burst_idx - 15; i++) {
                    bool match = true;
                    for (int j = 0; j < 15; j++) {
                        char cu = burst_buffer[i + j];
                        if (cu >= 'a' && cu <= 'z') cu -= ('a' - 'A'); 
                        if (cu != target[j]) { match = false; break; }
                    }
                    if (match) { header_start = &burst_buffer[i]; break; }
                }

                if (header_start != NULL) {
                    char *payload_start = header_start + 15;
                    char *payload_clean = NULL;

                    for (int i = 0; payload_start[i] != '\0'; i++) {
                        if (payload_start[i] == '/') {
                            payload_clean = &payload_start[i + 1];
                            break;
                        }
                    }

                    if (payload_clean != NULL) {
                        uint8_t decoded_bytes[512]; 
                        uint32_t decoded_len = 0;
                        bool decode_error = false;

                        int payload_char_len = strlen(payload_clean);
                        if ((payload_char_len % 2 != 0) || (payload_char_len < 10)) {
                            decode_error = true;
                        } else {
                            for (int k = 0; k < payload_char_len; k += 2) {
                                int val = decode_bytewords_pair(payload_clean[k], payload_clean[k+1]);
                                if (val == -1) { decode_error = true; break; }
                                if (decoded_len < sizeof(decoded_bytes)) {
                                    decoded_bytes[decoded_len++] = (uint8_t)val;
                                } else {
                                    decode_error = true; break;
                                }
                            }
                        }

                        // Per-frame Bytewords CRC-32 verification
                        if (!decode_error && decoded_len > 4) {
                            uint32_t bw_data_len = decoded_len - 4;
                            
                            // Extract the 4-byte Big-Endian CRC appended to the Bytewords payload
                            uint32_t expected_bw_crc = ((uint32_t)decoded_bytes[bw_data_len] << 24) |
                                                       ((uint32_t)decoded_bytes[bw_data_len + 1] << 16) |
                                                       ((uint32_t)decoded_bytes[bw_data_len + 2] << 8)  |
                                                       ((uint32_t)decoded_bytes[bw_data_len + 3]);

                            // Compute CRC-32 over the frame CBOR data using ur_crc32_update()
                            uint32_t calc_bw_crc = ur_crc32_update(0xFFFFFFFFU, decoded_bytes, bw_data_len) ^ 0xFFFFFFFFU;

                            if (calc_bw_crc == expected_bw_crc) {
                                decoded_len = bw_data_len;
                            } else {
                                decode_error = true; // Reject corrupted UART frame before it pollutes Fountain XOR
                            }
                        } else {
                            decode_error = true;
                        }

                        if (!decode_error && decoded_len > 0) {
                            if (decoded_bytes[0] == 0x85) { 
                                uint32_t cursor = 1;
                                uint32_t cbor_seq = read_cbor_int(decoded_bytes, &cursor);
                                uint32_t cbor_total = read_cbor_int(decoded_bytes, &cursor);
                                uint32_t cbor_msg_len = read_cbor_int(decoded_bytes, &cursor);
                                uint32_t cbor_checksum = read_cbor_int(decoded_bytes, &cursor);

                                uint8_t str_type = decoded_bytes[cursor++];
                                uint32_t frag_len = 0;
                                if ((str_type & 0xE0) == 0x40) { 
                                    uint8_t v = str_type & 0x1F;
                                    if (v < 24) frag_len = v;
                                    else if (v == 24) frag_len = decoded_bytes[cursor++];
                                    else if (v == 25) { frag_len = ((uint32_t)decoded_bytes[cursor]<<8) | decoded_bytes[cursor+1]; cursor += 2; }
                                }

                                if (frag_len > 0 && (cursor + frag_len) <= decoded_len) {
                                    uint8_t *fragment_data = &decoded_bytes[cursor];
                                    
                                    bool complete = fountain_process_frame(cbor_seq, cbor_total, cbor_msg_len, cbor_checksum, fragment_data, frag_len);
                                    
                                    // Progress = recovered fragments / total fragments
                                    if (cbor_total > 0) {
                                        uint32_t pure = fountain_get_pure_count();
                                        if (pure > cbor_total) pure = cbor_total;
                                        uint32_t fill = (140u * pure) / cbor_total;
                                        if (fill > 0) rectan(10, 121, 10 + fill, 124, ST7735_GREEN);
                                    }

                                    if (complete) {
                                        uint32_t crc = 0xFFFFFFFFU;
                                        uint32_t bytes_checked = 0;
                                        
                                        // Rebuild complete message to check final CRC32
                                        for (uint32_t i = 0; i < cbor_total; i++) {
                                            uint8_t *part_data = fountain_get_part(i);
                                            uint32_t part_len = fountain_get_part_length(i);
                                            
                                            // Truncate trailing XOR padding from the final fragment
                                            if (bytes_checked + part_len > cbor_msg_len) {
                                                part_len = cbor_msg_len - bytes_checked;
                                            }
                                            crc = ur_crc32_update(crc, part_data, part_len);
                                            bytes_checked += part_len;
                                            if (bytes_checked >= cbor_msg_len) break;
                                        }
                                        crc ^= 0xFFFFFFFFU;

                                        if (crc == cbor_checksum) {
                                            psbt_recovered = true;
                                            expected_msg_len = cbor_msg_len; 
                                            break; // Break the URXDA loop
                                        } else {
                                            // HALT ON ERROR SO WE CAN READ THE EXACT VALUES
                                            rectan(5, 62, 159, 112, BLACK);
                                            drawtext(5, 62, "CRC FAIL! (PAUSED)", ST7735_RED, ST7735_BLACK, 1);
                                            
                                            char hex_dbg[24];
                                            drawtext(5, 74, "CALC:", ST7735_WHITE, ST7735_BLACK, 1);
                                            u16_to_hex4((crc >> 16) & 0xFFFF, hex_dbg);
                                            u16_to_hex4(crc & 0xFFFF, &hex_dbg[4]);
                                            drawtext(40, 74, hex_dbg, ST7735_YELLOW, ST7735_BLACK, 1);

                                            drawtext(5, 86, "CBOR:", ST7735_WHITE, ST7735_BLACK, 1);
                                            u16_to_hex4((cbor_checksum >> 16) & 0xFFFF, hex_dbg);
                                            u16_to_hex4(cbor_checksum & 0xFFFF, &hex_dbg[4]);
                                            drawtext(40, 86, hex_dbg, ST7735_CYAN, ST7735_BLACK, 1);

                                            // Extract and display the first byte of up to 6 parts (P0-P5) to check for XOR corruption
                                            drawtext(5, 98, "P0-P5:", ST7735_WHITE, ST7735_BLACK, 1);
                                            memset(hex_dbg, 0, sizeof(hex_dbg));
                                            for (int i = 0; i < cbor_total && i < 6; i++) {
                                                uint8_t *p = fountain_get_part(i);
                                                if (p) {
                                                    char b_hex[3];
                                                    byte_to_hex(p[0], b_hex);
                                                    strcat(hex_dbg, b_hex);
                                                } else {
                                                    strcat(hex_dbg, "--");
                                                }
                                            }
                                            drawtext(45, 98, hex_dbg, ST7735_ORANGE, ST7735_BLACK, 1);
                                            
                                            // Force override option
                                            drawtext(5, 110, "OK=FORCE  BACK=EXIT", ST7735_WHITE, ST7735_BLACK, 1);

                                            // Wait for button press
                                            while (BT1 == 1 && BT_OK == 1) SYS_Tasks();
                                            
                                            if (BT_OK == 0) {
                                                psbt_recovered = true;
                                                expected_msg_len = cbor_msg_len;
                                                while (BT_OK == 0) SYS_Tasks(); // Wait for release
                                                break; 
                                            }

                                            if (BT1 == 0) break;
                                            rectan(5, 62, 159, 112, BLACK);
                                            drawtext(10, 105, "PRESS BACK TO CANCEL", ST7735_WHITE, ST7735_BLACK, 1);
                                            rectan(10, 121, 150, 124, BLACK); // Restart the progress bar
                                            fountain_init();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // NO buffer flushing here. Let the scanner stream uninterrupted.

        } else {
            // Trigger scanner ONLY if there is actual UART inactivity
            if (trigger_timeout > 0) {
                trigger_timeout--;
                if (trigger_timeout == 0) {
                    trigger_gm861_scanner();
                    trigger_timeout = 200000;
                }
            }
        }
        
        if (psbt_recovered) break; 
    }

    if (psbt_recovered) {
        // The part buffer becomes one contiguous message (no extra RAM)
        uint8_t *psbt_msg = fountain_assemble_message(expected_msg_len);
        show_psbt_details(psbt_msg, expected_msg_len);
    }
    
    while (BT1 == 0) SYS_Tasks(); // Wait for button release
}


// Helper to print 64-bit integers on screen
static void uint64_to_hex(uint64_t val, char *out_str) {
    const char hex_chars[] = "0123456789ABCDEF";
    for (int i = 15; i >= 0; i--) {
        out_str[i] = hex_chars[val & 0x0F];
        val >>= 4;
    }
    out_str[16] = '\0';
}


void test_prng_to_screen(void) {
    black_screen();
    drawtext(10, 10, "XOSHIRO256** TEST", ST7735_YELLOW, ST7735_BLACK, 1);
    
    // Seed with seq, total, msg_len, and checksum
    prng_seed(369, 5, 446, 0);
    
    char hex_str[17];
    int cursor_y = 30;
    
    for (int i = 0; i < 3; i++) {
        uint64_t rand_val = prng_next();
        uint64_to_hex(rand_val, hex_str);
        
        drawtext(10, cursor_y, hex_str, ST7735_GREEN, ST7735_BLACK, 1);
        cursor_y += 15;
    }
    
    delay_ms(5000);
}


void test_sampler_to_screen(void) {
    black_screen();
    drawtext(10, 10, "FOUNTAIN SAMPLER", ST7735_YELLOW, ST7735_BLACK, 1);
    
    uint32_t degree = 0;
    uint32_t fragments[MAX_UR_TOTAL_PARTS];
    
    // Pass seq, total, msg_len, checksum, &degree, fragments
    get_fountain_parts(369, 5, 446, 0, &degree, fragments);
    
    char debug_str[32];
    char num_str[6];
    
    strcpy(debug_str, "DEGREE: ");
    fast_itoa(degree, num_str);
    strcat(debug_str, num_str);
    drawtext(10, 30, debug_str, ST7735_GREEN, ST7735_BLACK, 1);
    
    strcpy(debug_str, "PARTS: ");
    for (uint32_t i = 0; i < degree; i++) {
        fast_itoa(fragments[i] + 1, num_str); 
        strcat(debug_str, num_str);
        if (i < degree - 1) strcat(debug_str, ", ");
    }
    
    drawtext(10, 45, debug_str, ST7735_CYAN, ST7735_BLACK, 1);
    
    delay_ms(5000);
}


int main ( void ){
    /* Initialize all modules */
    SYS_Initialize ( NULL );
    R_LCD=1;
    LED_LCD =1;
    A0_LCD=0;
    LED = 0;
        // --- SPI1 Configuration (TFT LCD) ---
        SPI1CON = 0x10000120; // Off, Master Mode, 8-bit
        SPI1CON = 0x10008120; // On (ON = 1)
        SPI1BRG = 1;          // Fast speed for the display

        // --- SPI3 Configuration (SD Card) ---
        SPI3CON = 0x10000120; // Off, Master Mode, 8-bit
        SPI3CON = 0x10008120; // On (ON = 1)
        SPI3BRG = 0x0004;     // SLOW speed for initialization (sd_init)
    LED_LCD =1;
    SD_CS =1;


    LCDinit1();
    black_screen();
    LCDinit2();
    black_screen();

    print_logo();
    drawtext(1,40, "KEEP YOUR SEEDS OFFLINE", ST7735_GREEN, ST7735_BLACK, 1);
    drawtext(1,51, "NO PHONE PHOTOS/QR", ST7735_RED, ST7735_BLACK, 1);
    drawtext(1,62, "SD AWAY FROM A COMPUTER", ST7735_RED, ST7735_BLACK, 1);
    print_camera(5,95,cSAFE);
    drawtext(23,87, "=QR Safe for phone", ST7735_GREEN, ST7735_BLACK, 1);
    print_camera(5,110,cNOTSAFE);
    drawtext(23,102, "=QR NOT Safe for phone", ST7735_RED, ST7735_BLACK, 1);
    drawtext(5,119, "(Press any button)", ST7735_WHITE, ST7735_BLACK, 1);
    version_display();

    PULSED_BT_t pulsed_bt = NONE;

    // Initialize the SD card only once at startup.
    SD_ready = sd_init();


    tmr1_init();


    /*// --- RIPEMD160 TEST ---
    const uint8_t test_msg[] = "hello";
    
    // Expected strict mathematical result for "hello"
    //uint8_t expected_hash[20] = {
    //    0x10, 0x8f, 0x07, 0xb8, 0x38, 0x24, 0x12, 0x61, 0x2c, 0x04,
    //    0x8d, 0x07, 0xd1, 0x3f, 0x81, 0x41, 0x18, 0x44, 0x5a, 0xcd
    //};
    uint8_t test_hash[20];

    // Execute the algorithm
    ripemd160(test_msg, 5, test_hash);

    // Verify if the MCU calculated exactly the same hash
    //if (memcmp(test_hash, expected_hash, 20) == 0) {
    //    drawtext(10, 50, "RIPEMD160 OK!", ST7735_GREEN, ST7735_BLACK, 2);
    //} else {
    //    drawtext(10, 50, "RIPEMD FAIL!", ST7735_RED, ST7735_BLACK, 2);
    //}
    
    // Wait 3 seconds to read the screen before loading the main menu
    //delay_ms(3000); 
    //black_screen();
    // --- END TEST ---*/
    
    
    // ==========================================
    // --- UART2 FRAME CONFIGURATION ---
    // ==========================================
    U2MODE = 0x0000; // Clear register first

    // 1. Data bits and Parity (PDSEL)
    // 0 = 8-bit data, no parity
    U2MODEbits.PDSEL = 0; 

    // 2. Stop bits (STSEL)
    // 0 = 1 Stop bit
    U2MODEbits.STSEL = 0; 

    // 3. Flow Control (UEN)
    // 0 = TX and RX pins are enabled and used; CTS and RTS pins are controlled by port latches (Flow control disabled)
    U2MODEbits.UEN = 0;

    // 4. Baud rate
    //U2BRG = 155; // 9600 bps at 24 MHz (Change to 51 if your clock is 8 MHz)
    //U2BRG = 77; // 19200 bps at 24 MHz (Standard mode BRGH=0)
    U2BRG = 12; // 115200 bps at 24 MHz (Standard mode BRGH=0)

    // 5. Enable module and pins
    U2STAbits.UTXEN = 1; // Enable TX
    U2STAbits.URXEN = 1; // Enable RX
    U2MODEbits.ON = 1;   // Turn on UART2

    //test QR XPUB
    //black_screen();
    //draw_xpub_qr("[89aa9c70/84h/0h/0h]xpub6C1WhE68AB95vTj1iM3Bpsu6jwuuKN8D2Z3mGaKNE8xxMHS2ehyN65V6md1KzaDREgcuRDs7AmfvNKFZ6sSykKyxHZDFFWXqVkKL8iss6SD");
    //delay_ms(3000);
 

    int BT1_ST= 1;
    int BT2_ST= 1;
    int BT_OK_ST = 1;
    int BT4_ST= 1;
    int BT5_ST= 1;
    int BT6_ST= 1;

    int SSS_K = 2;
    int SSS_N = 9;
    int sel_K_N = 0;
    int SDblock_pointer = 0;
    int selinput_pointer = 0;
    
    uint32_t wipe_total_sectors = 0;
    uint32_t wipe_mb_total = 0;

    uint16_t time_now ;

    //BYTE checksum_SD =0;
    BYTE XOR_SD =0;

    int lt_idx = 0; // Letter index

    char word[32] = {0};
    char result[32]; // Search result preview
    const char* found = NULL;
    bool found_bool = false;

    word[0] = '\0';

    int word_number = 1; // Tracks the word being entered
    char word_number_text[12];

    const size_t LEN = 32;

    uint8_t SSS_result[LEN];

    const uint8_t *coeffs[cK_MAX-1] = { c0, c1, c2, c3, c4 }; // Maximum polynomial degree 6
    uint8_t sh1[LEN], sh2[LEN], sh3[LEN], sh4[LEN], sh5[LEN], sh6[LEN], sh7[LEN], sh8[LEN], sh9[LEN];
    uint8_t *shares[cN_MAX] = {sh1, sh2, sh3, sh4, sh5, sh6, sh7, sh8, sh9};

    // Buffers used while reconstructing shares.
    uint8_t *shares_input[cN_MAX] = {sh1, sh2, sh3, sh4, sh5, sh6, sh7, sh8, sh9};
    uint8_t share_indices[cK_MAX] = { 1, 2,0,0,0,0 };

    while ( true )
    {
        /* Maintain state machines of all polled MPLAB Harmony modules. */
        SYS_Tasks ( );

        // Button pressing logic
        if ((BT_OK ==0) & (BT_OK_ST==1)) {
            LED = 1;
            update_entropy_coefficients(); // Capture fresh coefficient bytes on each press
            delay_ms(30);
            LED = 0;
            if (BT_OK ==0) {
                BT_OK_ST=0;
                pulsed_bt = OK_BT;
                }
         }  else if ((BT1 ==0) & (BT1_ST==1)) {
            LED = 1;
            update_entropy_coefficients();
            delay_ms(30);
            LED = 0;
            if (BT1 ==0) {
                BT1_ST=0;
                pulsed_bt = BACK_BT;
                }
         }  else if ((BT2 ==0) & (BT2_ST==1)) {
            LED = 1;
            update_entropy_coefficients();
            delay_ms(30);
            LED = 0;
            if (BT2 ==0) {
                BT2_ST=0;
                pulsed_bt = LEFT_BT;
                }
         }  else if ((BT4 ==0) & (BT4_ST==1)) {
            LED = 1;
            update_entropy_coefficients();
            delay_ms(30);
            LED = 0;
            if (BT4 ==0) {
                BT4_ST=0;
                pulsed_bt = DOWN_BT;
                }
         }  else if ((BT5 ==0) & (BT5_ST==1)) {
            LED = 1;
            update_entropy_coefficients();
            delay_ms(30);
            LED = 0;
            if (BT5 ==0) {
                BT5_ST=0;
                pulsed_bt = UP_BT;
                }
         }  else if ((BT6 ==0) & (BT6_ST==1)) {
            LED = 1;
            update_entropy_coefficients();
            delay_ms(30);
            LED = 0;
            if (BT6 ==0) {
                BT6_ST=0;
                pulsed_bt = RIGHT_BT;
                }
        } else {
            if (BT_OK ==1){
            BT_OK_ST=1;
            }
            if (BT1 ==1){
            BT1_ST=1;
            }
            if (BT2 ==1){
            BT2_ST=1;
            }
            if (BT4 ==1){
            BT4_ST=1;
            }
            if (BT5 ==1){
            BT5_ST=1;
            }
            if (BT6 ==1){
            BT6_ST=1;
            }
        }
        // End button pressing logic


        // STATE MACHINE
        switch (estado) {

            case INIT:
                switch (pulsed_bt) {
                    case OK_BT:
                    case BACK_BT:
                    case UP_BT:
                    case DOWN_BT:
                    case LEFT_BT:
                    case RIGHT_BT:
                        /*char pass_title[25] = "SEED:";
                        if (full_text_editor(pass_title, 25, (char*)buffer, 400, PASSPHRASE_MODE)) {
                            black_screen();

                            drawtext(5, 5, "TEXT SAVED:", ST7735_GREEN, ST7735_BLACK, 1);

                            // Pass false for show_cursor, and -1 for prev_len to force a full clean draw
                            draw_editor_textbox_full((char*)buffer, strlen((char*)buffer), -1, 15);
                            delay_ms(5000); 
                            memset(buffer, 0, 400);
                            
                            char note_title[25] = "NEW LOGIN:";
                            full_text_editor(note_title, 25, (char*)buffer, 400, NOTE_MODE);
                            
                            black_screen();
                            draw_editor_textbox_full((char*)note_title, strlen((char*)note_title), -1, 5);
                            draw_editor_textbox_full((char*)buffer, strlen((char*)buffer), -1, 15);
                            delay_ms(5000); 
                            memset(buffer, 0, 400);
                            
                            transition_to_main(); 
                        } else {
                            transition_to_main();
                        }*/

                        // TEST: animated UR export of a PSBT signed on the PC
                        // (test/psbt/sign_abandon.py). Scan it with Sparrow.
                        show_ur_animated_qr(ur_test_signed_psbt, sizeof(ur_test_signed_psbt));

                        //test_bytewords_to_screen();
                        
                        //test_prng_to_screen();
                        
                        //test_sampler_to_screen();
                        
                        
                        transition_to_main();
                        break;
                    default:
                        break;
                }
                break;

            case MAIN:
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        if (main_pointer==cMAIN_create){// Create new seed
                            transition_to_create_seed();
                        } else if (main_pointer==cMAIN_LOAD ){// Load seed words
                            transition_to_input(selinput_pointer);
                        } else if (main_pointer == cMAIN_BIP85) { // BIP85 child seed
                            
                            print_child_config_screen();
                            estado = CHILD_CONFIG;
                        } else if (main_pointer==cMAIN_XOR){// XOR
                            
                            print_generic_menu(menu_xor, cXOR_n_opt, xor_pointer);
                            estado = SEL_XOR;
                        } else if (main_pointer==cMAIN_OBFUS){// Obfuscation
                            transition_to_obfus();
                        } else if (main_pointer==cMAIN_MNEM2CARD){// Convert to Cards
                            transition_to_input(selinput_pointer);
                        } else if (main_pointer==cMAIN_SSS){// Shamir
                           
                            print_generic_menu(menu_sss, cSSS_n_opt, sss_pointer);
                            estado = SEL_SSS;
                        } else if (main_pointer==cMAIN_ERASESD){// Erase SD
                            print_generic_menu(menu_erase, cERASE_n_opt, erase_pointer);
                            estado = SEL_ERASE_MODE;
                        } else if (main_pointer==cMAIN_QR){// Resources menu
                           
                            print_generic_menu(menu_resource, cRESOURCE_n_opt, resource_pointer);
                            estado = RESOURCE_MENU;
                        } else if (main_pointer == cMAIN_SETTINGS) {
                           
                            print_settings_screen(settings_pointer);
                            estado = SEL_SETTINGS;                        
                        }
                        break;
                    case BACK_BT:
                        break;
                    case UP_BT:                        
                        if (main_pointer > 0) {
                            main_pointer--;
                        }
                        main_screen(main_pointer); // <--- Updated
                        break;
                    case DOWN_BT:                        
                        if (main_pointer < (cMAIN_n_opt-1)) {
                            main_pointer++;
                        }
                        main_screen(main_pointer); // <--- Updated
                        break;

                    case LEFT_BT:
                        break;
                    case RIGHT_BT:
                        break;
                    default:
                        break;
                }
                break;
            case CHILD_CONFIG:
                switch (pulsed_bt) {
                    case OK_BT:
                        transition_to_input(selinput_pointer);
                        break;
                    case BACK_BT:
                        transition_to_main();
                        break;
                    case UP_BT:
                        if (bip85_cursor == 0) {
                            bip85_size = cSIZE_12;
                        } else {
                            bip85_index++;
                        }
                        print_child_config_screen();
                        break;
                    case DOWN_BT:
                        if (bip85_cursor == 0) {
                            bip85_size = cSIZE_24;
                        } else {
                            if (bip85_index > 0) {
                                bip85_index--;
                            }
                        }
                        print_child_config_screen();
                        break;
                    case LEFT_BT:
                        bip85_cursor = 0;
                        print_child_config_screen();
                        break;
                    case RIGHT_BT:
                        bip85_cursor = 1;
                        print_child_config_screen();
                        break;
                    default:
                        break;
                }
                break;
            case RESOURCE_MENU:
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        white_screen();
                        if (resource_pointer == cRESOURCE_tutorial) {
                            draw_url_qr("youtu.be/8vy5LIxT1ls");
                        } else if (resource_pointer == cRESOURCE_backup) {
                            draw_url_qr("seedmate.github.io/Seedmate_HTML_backup/");
                        } else if (resource_pointer == cRESOURCE_dice_test) {
                            draw_url_qr("seedmate.github.io/Dice_tester/");
                        } else if (resource_pointer == cRESOURCE_wordlist) {
                            draw_url_qr("seedmate.net/Printable%20BIP39%20wordlist.pdf");   
                        } else if (resource_pointer == cRESOURCE_BINlist) {
                            draw_url_qr("https://www.seedmate.net/Binary_BIP39_wordlist.pdf"); 
                        }
                        print_camera(2, 65, cSAFE);
                        estado = RESOURCE_QR_VIEW;
                        print_left_arrow_black(5, 123);
                        break;
                    case BACK_BT:
                        transition_to_main();
                        break;
                    case UP_BT:
                        if (resource_pointer > 0) {
                            resource_pointer--;
                        }
                        print_generic_menu(menu_resource, cRESOURCE_n_opt, resource_pointer);
                        break;
                    case DOWN_BT:
                        if (resource_pointer < (cRESOURCE_n_opt - 1)) {
                            resource_pointer++;
                        }
                        print_generic_menu(menu_resource, cRESOURCE_n_opt, resource_pointer);
                        break;
                    default:
                        break;
                }
                break;
            case RESOURCE_QR_VIEW:
                switch (pulsed_bt) {
                    case OK_BT:
                        break;
                    case BACK_BT:
                        black_screen();
                        print_generic_menu(menu_resource, cRESOURCE_n_opt, resource_pointer);
                        estado = RESOURCE_MENU;
                        break;
                    default:
                        break;
                }
                break;
            case CREATE_SEED:        /////  SCREEN     2   /////////////
                switch (pulsed_bt) {
                    case OK_BT:
                        if (seed_pointer == cSEED_triple) {
                            transition_to_input(selinput_pointer);
                            size_pointer = cSIZE_24;
                            entropy_bits = cENTROPY_BITS24W;
                        } else if (seed_pointer == cSEED_dice) {
                            black_screen();
                            print_generic_menu(menu_dice, cDICE_MODE_n_opt, dice_mode_pointer);
                            estado = SEL_DICE_MODE;
                        } else {
                            transition_to_size();
                        }
                        break;
                    case BACK_BT:
                        transition_to_main();
                        break;
                    case UP_BT:
                        if (seed_pointer > 0) {
                            seed_pointer--;
                        }
                        print_generic_menu(menu_create, cSEED_n_opt, seed_pointer);
                        break;
                    case DOWN_BT:
                        if (seed_pointer < (cSEED_n_opt-1)) {
                            seed_pointer++;
                        }
                        print_generic_menu(menu_create, cSEED_n_opt, seed_pointer);
                        break;
                    case LEFT_BT:
                        break;
                    case RIGHT_BT:
                        break;
                    default:
                        break;
                }
                break;
            case SEL_DICE_MODE:
                switch (pulsed_bt) {
                    case OK_BT:
                        if (dice_mode_pointer == 0) { // Raw entropy bits
                            transition_to_size();
                        } else { // String hash
                            black_screen();
                            print_generic_menu(menu_hash, cHASH_MODE_n_opt, hash_mode_pointer);
                            estado = SEL_HASH_MODE;
                        }
                        break;
                    case BACK_BT:
                        transition_to_create_seed();
                        break;
                    case UP_BT:
                        if (dice_mode_pointer > 0) dice_mode_pointer--;
                        print_generic_menu(menu_dice, cDICE_MODE_n_opt, dice_mode_pointer);
                        break;
                    case DOWN_BT:
                        if (dice_mode_pointer < (cDICE_MODE_n_opt - 1)) dice_mode_pointer++;
                        print_generic_menu(menu_dice, cDICE_MODE_n_opt, dice_mode_pointer);
                        break;
                    default:
                        break;
                }
                break;
            case SEL_HASH_MODE:
                switch (pulsed_bt) {
                    case OK_BT:
                        transition_to_size();                        
                        break;
                    case BACK_BT:
                        black_screen();
                        print_generic_menu(menu_dice, cDICE_MODE_n_opt, dice_mode_pointer);
                        estado = SEL_DICE_MODE;
                        break;
                    case UP_BT:
                        if (hash_mode_pointer > 0) hash_mode_pointer--;
                        print_generic_menu(menu_hash, cHASH_MODE_n_opt, hash_mode_pointer);
                        break;
                    case DOWN_BT:
                        if (hash_mode_pointer < (cHASH_MODE_n_opt - 1)) hash_mode_pointer++;
                        print_generic_menu(menu_hash, cHASH_MODE_n_opt, hash_mode_pointer);
                        break;
                    default:
                        break;
                }
                break;
            case SEL_OBFUS:
                switch (pulsed_bt) {
                    case OK_BT:
                        if (obfuscation_pointer == cOBFUS_HOWTO) {
                            black_screen();
                            white_screen();
                            draw_url_qr("seedmate.net/obfuscation.html"); 
                            print_camera(2, 65, cSAFE);
                            print_left_arrow_black(5, 123);
                            estado = OBFUS_QR_VIEW;
                        } else if (obfuscation_pointer == cOBFUS_NOT) { // Negate seed words
                            transition_to_input(selinput_pointer);
                        } else if (obfuscation_pointer == cOBFUS_1WORD_XOR) {
                            black_screen();
                            capturing_xor_word = true; // Hijack WRITE_WORD mode
                            estado = WRITE_WORD;
                            word_number = 1;
                            lt_idx = 0;
                            clear_string(word);
                            found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                            print_word_number_top(word_number, word_number_text);
                            print_previous_confirmed_word(word_number, word_number_text);
                            print_keyboard_with_validation(lt_idx, found_bool, word);
                        } else { // Shift or Add/Sub
                            black_screen();
                            obfus_cursor = 0;
                            print_obfus_config_screen();
                            estado = OBFUS_CONFIG;
                        }
                        break;
                    case BACK_BT:
                        transition_to_main();
                        break;
                    case UP_BT:
                        if (obfuscation_pointer > 0) {
                            obfuscation_pointer--;
                        }
                        print_generic_menu(menu_obfus, cOBFUS_n_opt, obfuscation_pointer);
                        break;
                    case DOWN_BT:
                        if (obfuscation_pointer < (cOBFUS_n_opt-1)) {
                            obfuscation_pointer++;
                        }
                        print_generic_menu(menu_obfus, cOBFUS_n_opt, obfuscation_pointer);
                        break;
                    case LEFT_BT:
                    case RIGHT_BT:
                        break;
                    default:
                        break;
                }
                break;
            case OBFUS_CONFIG:
                switch (pulsed_bt) {
                    case OK_BT:
                        transition_to_input(selinput_pointer);
                        break;
                    case BACK_BT:
                        transition_to_obfus();
                        break;
                    case LEFT_BT:
                        obfus_cursor = 0;
                        print_obfus_config_screen();
                        break;
                    case RIGHT_BT:
                        obfus_cursor = 1;
                        print_obfus_config_screen();
                        break;
                    case UP_BT:
                        if (obfus_cursor == 0) {
                            obfus_dir_op = !obfus_dir_op;
                        } else {
                            obfus_amount++;
                        }
                        print_obfus_config_screen();
                        break;
                    case DOWN_BT:
                        if (obfus_cursor == 0) {
                            obfus_dir_op = !obfus_dir_op;
                        } else {
                            if (obfus_amount > 1) {
                                obfus_amount--;
                            }
                        }
                        print_obfus_config_screen();
                        break;
                    default:
                        break;
                }
                break;
            case SEL_ERASE_MODE:
                switch (pulsed_bt) {
                    case OK_BT:
                        if (erase_pointer == 0) { // ERASE SECTOR
                            transition_to_sd_block(SDblock_pointer);
                        } else { // WIPE ALL CARD
                            black_screen();
                            
                            // Initialize SD and get capacity before confirming
                            wipe_total_sectors = 0;
                            for (int retries = 0; retries < 3; retries++) {
                                if (!SD_ready) SD_ready = sd_init();
                                if (SD_ready) wipe_total_sectors = sd_get_sector_count();
                                if (wipe_total_sectors > 0) break;
                                SD_ready = false; 
                                delay_ms(100);    
                            }
                            
                            if (wipe_total_sectors == 0) {
                                drawtext(10, 90, "SD CAPACITY ERROR", ST7735_RED, ST7735_BLACK, 1);
                                print_cursor_grid();
                                print_ok();
                                estado = END_MODE;
                            } else {
                                wipe_mb_total = wipe_total_sectors / 2048;
                                
                                char msg_buf[32] = "Card size: ";
                                char mb_str[10];
                                size_t len = u16_to_str((unsigned int)wipe_mb_total, mb_str);
                                int pos = 11; // "Card size: " length
                                
                                for(size_t i = 0; i < len; i++) {
                                    msg_buf[pos++] = mb_str[i];
                                }
                                msg_buf[pos++] = ' ';
                                msg_buf[pos++] = 'M';
                                msg_buf[pos++] = 'B';
                                msg_buf[pos++] = 's';
                                msg_buf[pos] = '\0';
                                
                                drawtext(10, 30, msg_buf, ST7735_WHITE, ST7735_BLACK, 1);
                                drawtext(10, 50, "Confirm wipe?", ST7735_ORANGE, ST7735_BLACK, 1);
                                
                                // Render OK and BACK grid manually for universal support
                                print_cursor_grid();
                                print_ok();
                                print_back();
                                
                                estado = CONFIRM_WIPE_SD;
                            }
                        }
                        break;
                    case BACK_BT:
                        transition_to_main();
                        break;
                    case UP_BT:
                        if (erase_pointer > 0) erase_pointer--;
                        print_generic_menu(menu_erase, cERASE_n_opt, erase_pointer);
                        break;
                    case DOWN_BT:
                        if (erase_pointer < (cERASE_n_opt - 1)) erase_pointer++;
                        print_generic_menu(menu_erase, cERASE_n_opt, erase_pointer);
                        break;
                    default:
                        break;
                }
                break;

            case CONFIRM_WIPE_SD:
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        drawtext(10, 30, "WIPING ENTIRE SD...", ST7735_RED, ST7735_BLACK, 1);
                        drawtext(10, 50, "PLEASE WAIT", ST7735_WHITE, ST7735_BLACK, 1);
                        estado = PROCESS_WIPE_SD;
                        break;
                    case BACK_BT:
                        // Cancel and return to erase menu
                        black_screen();
                        print_generic_menu(menu_erase, cERASE_n_opt, erase_pointer);
                        estado = SEL_ERASE_MODE;
                        break;
                    default:
                        break;
                }
                break;

            case PROCESS_WIPE_SD: {
                uint8_t secure_wipe_buf[512]; 
                
                // Use alternating bit pattern (10101010) to prevent FTL compression 
                for (int i = 0; i < 512; i++) {
                    secure_wipe_buf[i] = 0xAA; 
                }
                
                for (uint32_t current_sector = 0; current_sector < wipe_total_sectors; current_sector++) {
                    SYS_Tasks(); // Keep MCU watchdog and tasks running
                    
                    if ((current_sector % 256) == 0) {
                        LED = 1 - LED; 
                    }

                    if (!sd_write_block(current_sector, secure_wipe_buf)) {
                        drawtext(10, 90, "PHYSICAL WRITE ERROR", ST7735_RED, ST7735_BLACK, 1);
                        LED = 0;
                        print_cursor_grid();
                        print_ok();
                        estado = END_MODE;
                        goto wipe_end; 
                    }
                    
                    // Update UI every 1000 sectors (~0.5 MB)
                    if ((current_sector % 1000) == 0) {
                        char progress_txt[32];
                        uint32_t mb_erased = current_sector / 2048;
                        
                        size_t len1 = u16_to_str((unsigned int)mb_erased, progress_txt);
                        progress_txt[len1] = ' ';
                        progress_txt[len1 + 1] = '/';
                        progress_txt[len1 + 2] = ' ';
                        
                        size_t len2 = u16_to_str((unsigned int)wipe_mb_total, &progress_txt[len1 + 3]);
                        int pos = len1 + 3 + len2;
                        
                        progress_txt[pos++] = ' ';
                        progress_txt[pos++] = 'M';
                        progress_txt[pos++] = 'B';
                        progress_txt[pos] = '\0';
                        
                        rectan(10, 70, 159, 78, BLACK); 
                        drawtext(10, 70, progress_txt, ST7735_CYAN, ST7735_BLACK, 1);
                    }
                }
                
                drawtext(10, 90, "SECURE WIPE FINISHED", ST7735_GREEN, ST7735_BLACK, 1);

            wipe_end:
                LED = 0; 
                print_cursor_grid();
                print_ok(); 
                estado = END_MODE; 
                break;
            }

            case SEL_SIZE:        /////  SCREEN     2   /////////////
                switch (pulsed_bt) {
                    case OK_BT:
                        if (size_pointer==cSIZE_12){// 12 words
                            entropy_bits = cENTROPY_BITS12W;
                        }   else {
                            entropy_bits = cENTROPY_BITS24W;
                        }
                        if (main_pointer==cMAIN_XOR) { // XOR stuff
                            xor_merge_words_available=0; // Reset
                            for (int i = 0; i < 32; i++){
                                xor_merge_word1[i] = 0;
                                xor_merge_word2[i] = 0;
                                xor_merge_word3[i] = 0;
                            }

                            if (selinput_pointer==cKEYBOARD)	{
                                black_screen();
                                estado = WRITE_WORD;
                                word_number=1;
                                clear_string(word);
                                found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                                print_word_number_top(word_number, word_number_text);
                                print_previous_confirmed_word(word_number, word_number_text);
                                print_keyboard_with_validation(lt_idx, found_bool, word);
                            }else{// SD
                                black_screen();
                                estado = SEL_SD_BLOCK_XOR;
                                sel_sd_block_screen_generic(SDblock_pointer);
                            }
                        }else if ((main_pointer==cMAIN_SSS) & (sss_pointer==cMERGE)){
                            shares_loaded = 0;
                            black_screen();
                            print_sel_share_screen(selected_share_id);
                            estado = SEL_SHARE;
                            break;

                        } else if (main_pointer==cMAIN_LOAD || main_pointer==cMAIN_OBFUS || main_pointer==cMAIN_SSS || main_pointer==cMAIN_BIP85 || main_pointer==cMAIN_MNEM2CARD){// Check seed or obfuscate/SSS
                            black_screen();
                            estado = WRITE_WORD;
                            word_number=1;
                            clear_string(word);
                            found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                            print_word_number_top(word_number, word_number_text);
                            print_previous_confirmed_word(word_number, word_number_text);
                            print_keyboard_with_validation(lt_idx, found_bool, word);
                        } else if (seed_pointer==cSEED_dice && dice_mode_pointer == 1){ // String hash
                            black_screen();
                            dice_string_buf[0] = '\0';
                            dice_input_idx = 0;
                            estado = DICE_STRING_INPUT;
                            int target = (size_pointer == cSIZE_12) ? c12_rolls : c24_rolls;
                            init_dice_string_input_screen(dice_input_idx, dice_string_buf, target);
                        } else if (seed_pointer==cSEED_dice || seed_pointer==cSEED_coin){// Roll dice or coins
                            black_screen();
                            print_diceroll_screen(size_pointer, seed_pointer);
                            estado = ROLL_DICE1;
                            bit_count_dice = 0;
                        } else if (seed_pointer==cSEED_word){// Word pick
                            black_screen();
                            estado = WRITE_WORD;
                            word_number=1;
                            clear_string(word);
                            found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                            print_word_number_top(word_number, word_number_text);
                            print_previous_confirmed_word(word_number, word_number_text);
                            print_keyboard_with_validation(lt_idx, found_bool, word);
                        }   else if (seed_pointer==cSEED_timer){// Stopwatch test only
                            black_screen();
                            estado = TMR_INPUT;
                            dice_x_pointer = 0;
                            dice_y_pointer = 25;
                            bit_count_dice = 0;
                            print_TMR_screen(size_pointer);
                        }   else if (seed_pointer==cSEED_cards){
                            reset_card_entropy_mode();
                            estado = CARD_INPUT;
							black_screen();
                            print_card_input_screen();
                        }
                        break;
                    case BACK_BT:
                        if (main_pointer==cMAIN_OBFUS) {
                            transition_to_obfus();
                        } else if (main_pointer==cMAIN_XOR || main_pointer==cMAIN_LOAD || main_pointer==cMAIN_SSS || main_pointer==cMAIN_BIP85 || main_pointer==cMAIN_MNEM2CARD){
                            transition_to_input(selinput_pointer);
                        } else {
                            if (seed_pointer == cSEED_dice) {
                                if (dice_mode_pointer == 1) { // String Hash back
                                    black_screen();
                                    print_generic_menu(menu_hash, cHASH_MODE_n_opt, hash_mode_pointer);
                                    estado = SEL_HASH_MODE;
                                } else { // Raw back
                                    black_screen();
                                    print_generic_menu(menu_dice, cDICE_MODE_n_opt, dice_mode_pointer);
                                    estado = SEL_DICE_MODE;
                                }
                            } else {
                                transition_to_create_seed();
                            }
                        }
                        break;
                    case UP_BT:
                        if (size_pointer > 0) {
                            size_pointer--;
                        }
                        print_generic_menu(menu_size, cSIZE_n_opt, size_pointer);
                        break;
                    case DOWN_BT:
                        if (size_pointer < (cSIZE_n_opt-1)) {
                            size_pointer++;
                        }
                        print_generic_menu(menu_size, cSIZE_n_opt, size_pointer);
                        break;
                    case LEFT_BT:
                        break;
                    case RIGHT_BT:
                        break;
                    default:
                        break;
                }
                break;
            case SEL_XOR:
                switch (pulsed_bt) {
                    case OK_BT:
                        transition_to_input(selinput_pointer);
                        break;
                    case BACK_BT:
                        transition_to_main();
                        break;
                    case UP_BT:
                        if (xor_pointer > 0) {
                            xor_pointer--;
                        }
                        print_generic_menu(menu_xor, cXOR_n_opt, xor_pointer);
                        break;
                    case DOWN_BT:
                        if (xor_pointer < (cXOR_n_opt-1)) {
                            xor_pointer++;
                        }
                        print_generic_menu(menu_xor, cXOR_n_opt, xor_pointer);
                        break;
                    case LEFT_BT:
                        break;
                    case RIGHT_BT:
                        break;
                    default:
                        break;
                }
                break;
            case SEL_SD_BLOCK:
                switch (pulsed_bt) {
                    case OK_BT:
                        if (main_pointer==cMAIN_ERASESD) { // Erase
                            for (int i = 0; i < 512; i++) buffer[i] = 0; // Clear the sector buffer
                            if (sd_write_block(SDblock_pointer+SD_page*cSDBLOCK_n_opt, buffer)) { // Write the block
                                drawtext(70, 20 + 10*SDblock_pointer, "ERASE SUCCESS", ST7735_GREEN, ST7735_BLACK, 1);
                            } else {
                                drawtext(70, 20 + 10*SDblock_pointer, "ERASE ERROR ", ST7735_RED, ST7735_BLACK, 1);
                            }
                            break;

                        }else{ // Read
                            int sd_status = load_and_verify_sd_slot(SDblock_pointer + SD_page * cSDBLOCK_n_opt);
                            if (sd_status == 0) {
                                size_pointer=buffer[cSD_SIZE_ADDR];
                                if (main_pointer == cMAIN_create && seed_pointer == cSEED_triple) {
                                    if (size_pointer != cSIZE_24) {
                                        drawtext(70, 20 + 10*SDblock_pointer, "WRONG SIZE", ST7735_RED, ST7735_BLACK, 1);
                                        break;
                                    }
                                    drawtext(70, 20 + 10*SDblock_pointer, LOAD_OK, ST7735_GREEN, ST7735_BLACK, 1);
                                    black_screen();
                                    estado = PROCESS_TRIPLE;
                                    break;
                                } else if (main_pointer==cMAIN_SSS){
                                    drawtext(70, 20 + 10*SDblock_pointer, LOAD_OK, ST7735_GREEN, ST7735_BLACK, 1);
                                    black_screen();
                                    expand_sss_coefficients();
                                    sss_split_kofm(data_array_256b /* c0 */,
                                        coeffs, SSS_K /* k threshold */,
                                        LEN,
                                        cN_MAX /* total shares */, // Always kept at max capacity
                                        shares);
                                    for (int i = 0; i < 16 + size_pointer*16; i++) data_array_256b[i]=shares[selected_share_id-1][i];

                                }else if (main_pointer==cMAIN_OBFUS) {
                                    drawtext(70, 20 + 10*SDblock_pointer, LOAD_OK, ST7735_GREEN, ST7735_BLACK, 1);
                                    black_screen();
                                    if (obfuscation_pointer==cOBFUS_NOT){
                                        not_operator(data_array_256b,16 + size_pointer*16);
                                    } else if (obfuscation_pointer==cOBFUS_SHIFT){
                                        if (obfus_dir_op == 0){
                                            for (int i = 0; i < obfus_amount; i++) shift_left(data_array_256b,16 + size_pointer*16);
                                        } else {
                                            for (int i = 0; i < obfus_amount; i++) shift_right(data_array_256b,16 + size_pointer*16);
                                        }
                                    } else if (obfuscation_pointer==cOBFUS_ADD){
                                        addsub_11bit_groups(16 + size_pointer*16, obfus_amount, obfus_dir_op);
                                    } else if (obfuscation_pointer == cOBFUS_1WORD_XOR) {
                                        apply_1word_xor(obfus_xor_word_idx, size_pointer); // Apply 1 Word XOR
                                    }
                                }else if (main_pointer==cMAIN_BIP85) {
                                    drawtext(70, 20 + 10*SDblock_pointer, LOAD_OK, ST7735_GREEN, ST7735_BLACK, 1);
                                    black_screen();
                                    drawtext(30, 30, "COMPUTING CHILD", ST7735_WHITE, ST7735_BLACK, 1);
                                    drawtext(30, 45, "MNEMONIC...", ST7735_WHITE, ST7735_BLACK, 1);
                                    estado = PROCESS_BIP85;
                                    break;
                                }else if (main_pointer==cMAIN_MNEM2CARD) {
                                    drawtext(70, 20 + 10*SDblock_pointer, LOAD_OK, ST7735_GREEN, ST7735_BLACK, 1);
                                    black_screen();
                                    calculate_card_encoding();
                                    estado = SHOW_CARD_ENCODING;
                                    print_card_encoding_screen();
                                    break;
                                }
                                redraw_show_seed_with_offset();
                            } else if (sd_status == 2) {
                                drawtext(70, 20 + 10*SDblock_pointer, "NO SEED", ST7735_RED, ST7735_BLACK, 1);
                                break;
                            } else {
                                black_screen();
                                drawtext(10, 30, "SD ERROR", ST7735_RED, ST7735_BLACK, 1);
                                estado = END_MODE;
                                break;
                            }
                            break;
                        }

                    case BACK_BT:
                        if (main_pointer==cMAIN_OBFUS || main_pointer==cMAIN_XOR || main_pointer==cMAIN_LOAD || main_pointer==cMAIN_SSS || main_pointer==cMAIN_BIP85 || main_pointer==cMAIN_MNEM2CARD || (main_pointer == cMAIN_create && seed_pointer == cSEED_triple)){
                            transition_to_input(selinput_pointer);
                        }else {
                            transition_to_main();
                        }
                        break;
                   case UP_BT:
                        if ((SDblock_pointer == 0) & (SD_page >0)){// Page down and point to slot 8
                            black_screen();
                            SDblock_pointer=cSDBLOCK_n_opt-1;
                            SD_page--;
                            sel_sd_block_screen_generic(SDblock_pointer);

                        }else if (SDblock_pointer > 0) {
                            SDblock_pointer--;
                            sel_sd_block_screen_generic(SDblock_pointer);

                        }
                        break;
                    case DOWN_BT:
                        if (SDblock_pointer == (cSDBLOCK_n_opt-1)) {
                            black_screen();
                            SDblock_pointer=0;
                            SD_page++;
                        }else if(SDblock_pointer < (cSDBLOCK_n_opt-1)){
                            SDblock_pointer++;
                        }

                        sel_sd_block_screen_generic(SDblock_pointer);

                        break;
                    case LEFT_BT:
                        if (SD_page > 0) {
                            SD_page--;
                            black_screen();
                            sel_sd_block_screen_generic(SDblock_pointer);
                        }
                        break;
                    case RIGHT_BT:
                        black_screen();
                        SD_page++;
                        sel_sd_block_screen_generic(SDblock_pointer);
                        break;
                    default:
                        break;
                }
                break;
            case SEL_SD_BLOCK_WR:
                switch (pulsed_bt) {
                    case OK_BT: // Write
                        // Reinitialize the SD card if the first read fails.
                        if (!sd_read_block(SDblock_pointer +SD_page*cSDBLOCK_n_opt, buffer)) {
                            sd_init();
                        }
                        time_now = TMR1;              // Read the 16-bit timer
                        XOR_SD = (uint8_t)time_now;   // Low byte
                        for (int i = 0; i < 512; i++) buffer[i] = 0; // Clear the sector buffer
                        buffer[cSD_XOR_ADDR] = XOR_SD;
                        for (int i = 0; i < 16 +16*size_pointer; i++) {
                            buffer[i]= data_array_256b[i] ^ XOR_SD; // Store raw entropy without seed-word checksum
                            buffer[cSD_CHECKSUM_ADDR]+=buffer[i];   // Accumulate checksum
                        }
                        buffer[cSD_CHECKSUM_ADDR]+=1; // Avoid checksum 0 on a clean SD card

                        buffer[cSD_SIZE_ADDR]=size_pointer; // Store size metadata next
                        if (sd_write_block(SDblock_pointer+SD_page*cSDBLOCK_n_opt, buffer)) { // Write the block
                            drawtext(70, 20 + 10*SDblock_pointer, "WRITE SUCCESS", ST7735_GREEN, ST7735_BLACK, 1);
                        } else {
                            drawtext(70, 20 + 10*SDblock_pointer, "WRITE ERROR ", ST7735_RED, ST7735_BLACK, 1);
                        }

                        estado = SEL_SD_BLOCK_WR;
                        break;

                     case BACK_BT:
                        redraw_show_seed_with_offset();
                        break;
                    case UP_BT:
                        if ((SDblock_pointer == 0) & (SD_page >0)){// Page down and point to slot 8
                            black_screen();
                            SDblock_pointer=cSDBLOCK_n_opt-1;
                            SD_page--;
                            sel_sd_block_screen_wr(SDblock_pointer);
                        }else if (SDblock_pointer > 0) {
                            SDblock_pointer--;
                            sel_sd_block_screen_wr(SDblock_pointer);
                        }
                        break;
                    case DOWN_BT:
                        if (SDblock_pointer == (cSDBLOCK_n_opt-1)) {
                            black_screen();
                            SDblock_pointer=0;
                            SD_page++;
                        }else if(SDblock_pointer < (cSDBLOCK_n_opt-1)){
                            SDblock_pointer++;
                        }
                        sel_sd_block_screen_wr(SDblock_pointer);
                        break;
                    case LEFT_BT:
                        if (SD_page > 0) {
                            black_screen();
                            SD_page--;
                            sel_sd_block_screen_wr(SDblock_pointer);
                        }
                        break;
                    case RIGHT_BT:
                        black_screen();
                        SD_page++;
                        sel_sd_block_screen_wr(SDblock_pointer);
                        break;

                    default:
                        break;
                }
                break;
            case SEL_SD_BLOCK_XOR:
                switch (pulsed_bt) {
                    case OK_BT:
                        {
                            int sd_status = load_and_verify_sd_slot(SDblock_pointer + SD_page * cSDBLOCK_n_opt);
                            if (sd_status == 0) {
                                // Check size
                                if (buffer[cSD_SIZE_ADDR]==size_pointer){
                                    drawtext(70, 20 + 10*SDblock_pointer, "XOR INPUT OK", ST7735_GREEN, ST7735_BLACK, 1);
                                    if (xor_merge_words_available <= xor_pointer){
                                        for (int i = 0; i < 32; i++) {
                                            if (xor_merge_words_available==0){
                                                xor_merge_word1[i] = data_array_256b[i];
                                            } else if (xor_merge_words_available==1){
                                                xor_merge_word2[i] = data_array_256b[i];
                                            } else if (xor_merge_words_available==2){
                                                xor_merge_word3[i] = data_array_256b[i];
                                            }
                                        }
                                        xor_merge_words_available++;
                                        pulsed_bt = NONE;
                                        break;
                                    } else { // We have everything
                                        black_screen();
                                        for (int i = 0; i < 16 + 16*size_pointer; i++) {
                                            data_array_256b[i] = data_array_256b[i] ^ xor_merge_word1[i]^ xor_merge_word2[i]^ xor_merge_word3[i];
                                        }
                                        redraw_show_seed_with_offset();
                                        break;

                                    }
                                }else{
                                    drawtext(70, 20 + 10*SDblock_pointer, "WRONG SIZE", ST7735_RED, ST7735_BLACK, 1);
                                    break;
                                }

                            } else if (sd_status == 2) {// Checksum error
                                drawtext(70, 20 + 10*SDblock_pointer, "NO SEED", ST7735_RED, ST7735_BLACK, 1);
                                break;
                            } else {
                                black_screen();
                                drawtext(10, 30, "SD ERROR", ST7735_RED, ST7735_BLACK, 1);
                                estado = END_MODE;
                                break;
                            }
                            break;
                        }

                    case BACK_BT:
                        transition_to_size();
                        break;
                    case UP_BT:
                        if ((SDblock_pointer == 0) & (SD_page >0)){// Page down and point to slot 8
                            black_screen();
                            SDblock_pointer=cSDBLOCK_n_opt-1;
                            SD_page--;
                            sel_sd_block_screen_generic(SDblock_pointer);
                        }else if (SDblock_pointer > 0) {
                            SDblock_pointer--;
                            sel_sd_block_screen_generic(SDblock_pointer);
                        }
                        break;
                    case DOWN_BT:
                        if (SDblock_pointer == (cSDBLOCK_n_opt-1)) {
                            black_screen();
                            SDblock_pointer=0;
                            SD_page++;
                        }else if(SDblock_pointer < (cSDBLOCK_n_opt-1)){
                            SDblock_pointer++;
                        }
                        sel_sd_block_screen_generic(SDblock_pointer);
                        break;
                    case LEFT_BT:
                        if (SD_page > 0){
                            SD_page--;
                            sel_sd_block_screen_generic(SDblock_pointer);
                            black_screen();
                        }
                        break;
                    case RIGHT_BT:
                        SD_page++;
                        sel_sd_block_screen_generic(SDblock_pointer);
                        break;
                    default:
                        break;
                }
                break;
           case SEL_SD_BLOCK_MERGE:
                switch (pulsed_bt) {
                    case OK_BT:
                        {
                            if (is_share_id_already_loaded(selected_share_id, share_indices)) {
                                drawtext(70, 20 + 10*SDblock_pointer, "ID REPEATED   ", ST7735_RED, ST7735_BLACK, 1);
                                break;
                            }
                            int sd_status = load_and_verify_sd_slot(SDblock_pointer + SD_page * cSDBLOCK_n_opt);
                            if (sd_status == 0) {
                                // Load size from the first share and validate the rest.
                                if (shares_loaded==0){
                                    size_pointer=buffer[cSD_SIZE_ADDR];
                                }else if (buffer[cSD_SIZE_ADDR]!=size_pointer){
                                    drawtext(70, 20 + 10*SDblock_pointer, "WRONG SIZE", ST7735_RED, ST7735_BLACK, 1);
                                    break;
                                }
                                // Everything is valid; store the share.
                                for (int i = 0; i < 32; i++) {
                                        shares_input[shares_loaded][i] = data_array_256b[i];
                                }
                                share_indices[shares_loaded] = selected_share_id;
                                shares_loaded++;
                                drawtext(70, 20 + 10*SDblock_pointer,  "SHARE OK   ", ST7735_GREEN, ST7735_BLACK, 1);

                                if (shares_loaded >= (SSS_K)) { // We already have K shares
                                    black_screen();
                                    if (!shamir_interpolate(SSS_result,0,share_indices, shares_input,SSS_K,LEN)){
                                        drawtext(5,39, "Shamir Error", ST7735_RED, ST7735_BLACK, 1);
                                        estado = END_MODE;
                                        break;
                                    }
                                    for (int i = 0; i < 32; i++) data_array_256b[i]=SSS_result[i]; // Move result to data array
                                    redraw_show_seed_with_offset();
                                    break;

                                } else {
                                    if (selected_share_id < cN_MAX) selected_share_id++;
                                    sel_sd_block_screen_merge(SDblock_pointer, selected_share_id);
                                    break;
                                }
                            } else if (sd_status == 2) {// Checksum error
                                drawtext(70, 20 + 10*SDblock_pointer, "NO SEED FOUND", ST7735_RED, ST7735_BLACK, 1);
                                break;
                            } else {
                                black_screen();
                                drawtext(10, 30, "SD ERROR", ST7735_RED, ST7735_BLACK, 1);
                                estado = END_MODE;
                                break;
                            }
                            break;
                        }

                    case BACK_BT:
                        transition_to_size();
                        break;
                    case UP_BT:
                        if ((SDblock_pointer == 0) & (SD_page >0)){// Page down and point to slot 8
                            black_screen();
                            SDblock_pointer=cSDBLOCK_n_opt-1;
                            SD_page--;
                            sel_sd_block_screen_merge(SDblock_pointer,selected_share_id);
                        }else if (SDblock_pointer > 0) {
                            SDblock_pointer--;
                            sel_sd_block_screen_merge(SDblock_pointer,selected_share_id);
                        }
                        break;
                    case DOWN_BT:
                        if (SDblock_pointer == (cSDBLOCK_n_opt-1)) {
                            black_screen();
                            SDblock_pointer=0;
                            SD_page++;
                        }else if(SDblock_pointer < (cSDBLOCK_n_opt-1)){
                            SDblock_pointer++;
                        }
                        sel_sd_block_screen_merge(SDblock_pointer,selected_share_id);
                        break;
                    case LEFT_BT:// Cannot page up/down here
                        if(selected_share_id>1)selected_share_id--;
                        sel_sd_block_screen_merge(SDblock_pointer,selected_share_id);
                        break;
                    case RIGHT_BT:
                        if(selected_share_id<cN_MAX)selected_share_id++;
                        sel_sd_block_screen_merge(SDblock_pointer,selected_share_id);
                        break;
                    default:
                        break;
                }
                break;
           case SEL_INPUT:
                switch (pulsed_bt) {
                    case OK_BT:
                        if (selinput_pointer==cKEYBOARD){
                            black_screen();
                            if (seed_pointer == cSEED_triple && main_pointer == cMAIN_create) {
                                estado = WRITE_WORD;
                                word_number=1;
                                clear_string(word);
                                found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                                print_word_number_top(word_number, word_number_text);
                                print_previous_confirmed_word(word_number, word_number_text);
                                print_keyboard_with_validation(lt_idx, found_bool, word);
                            } else {
                                transition_to_size();
                            }
                        } else if (selinput_pointer==cQRSCAN) {
                            black_screen();
                            drawtext(10, 10, "READY TO SCAN", ST7735_YELLOW, ST7735_BLACK, 1);
                            //drawtext(10, 60, "BACK TO CANCEL", ST7735_WHITE, ST7735_BLACK, 1);
                            estado = QR_SCANNING;
                        
                        } else { // cFROMSD
                            black_screen();
                            if (seed_pointer == cSEED_triple && main_pointer == cMAIN_create) {
                                transition_to_sd_block(SDblock_pointer);
                            } else if (main_pointer==cMAIN_XOR){
                                transition_to_size();
                            }else if ((main_pointer==cMAIN_SSS) & (sss_pointer==cMERGE)){
                                shares_loaded = 0;
                                sel_sd_block_screen_merge(SDblock_pointer,selected_share_id);
                                estado = SEL_SD_BLOCK_MERGE;
                            }else if ((main_pointer==cMAIN_SSS) & (sss_pointer==cSPLIT)){
                                estado = TMR_INPUT;
                                dice_x_pointer = 0;
                                dice_y_pointer = 25;
                                bit_count_dice = 0;
                                size_pointer=cSIZE_24;
                                entropy_bits = cENTROPY_BITS24W;
                                print_TMR_screen(size_pointer);
                            }else{// cMAIN_OBFUS or cMAIN_LOAD or cMAIN_BIP85 or cMAIN_MNEM2CARD
                                transition_to_sd_block(SDblock_pointer);
                            }
                        }

                        break;
                    case BACK_BT:
                        if (main_pointer == cMAIN_XOR)   {
                            black_screen();
                            print_generic_menu(menu_xor, cXOR_n_opt, xor_pointer);
                            estado = SEL_XOR;
                        }else if((main_pointer==cMAIN_SSS) & (sss_pointer==cSPLIT)){
                            black_screen();
                            print_selkn_screen(SSS_K, SSS_N, sel_K_N);
                            estado = SEL_KN;
                        }else if((main_pointer==cMAIN_SSS) & (sss_pointer==cMERGE)){
                            black_screen();
                            print_selk_screen(SSS_K);
                            estado = SEL_K;
                        }else if(main_pointer==cMAIN_OBFUS){
                            transition_to_obfus();
                        }else if (main_pointer == cMAIN_create) { 
                            transition_to_create_seed();
                        }else if (main_pointer == cMAIN_BIP85) {
                            black_screen();
                            print_child_config_screen();
                            estado = CHILD_CONFIG;
                        }else {
                            transition_to_main();
                        }
                        break;
                    case UP_BT:
                        if (selinput_pointer > 0) {
                            selinput_pointer--;
                        }
                        print_generic_menu(menu_input, cSELINPUT_n_opt, selinput_pointer);
                        break;
                    case DOWN_BT:
                        if (selinput_pointer < (cSELINPUT_n_opt-1)) {
                            selinput_pointer++;
                        }
                        print_generic_menu(menu_input, cSELINPUT_n_opt, selinput_pointer);
                        break;
                    case LEFT_BT:
                        break;
                    case RIGHT_BT:
                        break;
                    default:
                        break;
                }
                break;
            case SEL_SSS:
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        if (sss_pointer==cSPLIT){
                            print_selkn_screen(SSS_K, SSS_N, sel_K_N);
                            estado = SEL_KN;
                        } else {// Merge
                            print_selk_screen(SSS_K);
                            estado = SEL_K;
                        }
                        break;
                    case BACK_BT:
                        transition_to_main();
                        break;
                    case UP_BT:
                        if (sss_pointer > 0) {
                            sss_pointer--;
                        }
                        print_generic_menu(menu_sss, cSSS_n_opt, sss_pointer);
                        break;
                    case DOWN_BT:
                        if (sss_pointer < (cSSS_n_opt-1)) {
                            sss_pointer++;
                        }
                        print_generic_menu(menu_sss, cSSS_n_opt, sss_pointer);
                        break;
                    case LEFT_BT:
                        break;
                    case RIGHT_BT:
                        break;
                    default:
                        break;
                }
                break;
           case SEL_KN:
                switch (pulsed_bt) {
                    case OK_BT:
                        transition_to_input(selinput_pointer);
                        break;
                    case BACK_BT:
                        black_screen();
                        print_generic_menu(menu_sss, cSSS_n_opt, sss_pointer);
                        estado = SEL_SSS;
                        break;
                    case UP_BT:
                        if (sel_K_N==0){
                            if (SSS_K<cK_MAX)SSS_K++;
                        } else { if (SSS_N<cN_MAX)SSS_N++;}
                        print_selkn_screen(SSS_K, SSS_N, sel_K_N);
                        break;
                    case DOWN_BT:
                        if (sel_K_N==0){
                            if (SSS_K>2)SSS_K--;
                        } else { if (SSS_N>3)SSS_N--;}
                        print_selkn_screen(SSS_K, SSS_N, sel_K_N);
                        break;
                    case LEFT_BT:
                        if (sel_K_N==1)sel_K_N=0;
                        print_selkn_screen(SSS_K, SSS_N, sel_K_N);
                        break;
                    case RIGHT_BT:
                        if (sel_K_N==0)sel_K_N=1;
                        print_selkn_screen(SSS_K, SSS_N, sel_K_N);
                        break;
                    default:
                        break;
                }
                break;
           case SEL_K:
                switch (pulsed_bt) {
                    case OK_BT:
                        transition_to_input(selinput_pointer);
                        break;
                    case BACK_BT:
                        black_screen();
                        print_generic_menu(menu_sss, cSSS_n_opt, sss_pointer);
                        estado = SEL_SSS;
                        break;
                    case UP_BT:
                        if (SSS_K<cK_MAX)SSS_K++;
                        print_selk_screen(SSS_K);
                        break;
                    case DOWN_BT:
                        if (SSS_K>2)SSS_K--;
                        print_selk_screen(SSS_K);
                        break;
                    case LEFT_BT:
                        break;
                    case RIGHT_BT:
                        break;
                    default:
                        break;
                }
                break;

           case SEL_SHARE:
                switch (pulsed_bt) {
                    case OK_BT:
                        if (is_share_id_already_loaded(selected_share_id, share_indices)) {
                            drawtext(10, 50, "ID REPEATED", ST7735_RED, ST7735_BLACK, 1);
                            break; 
                        }
                        black_screen();
                        estado = WRITE_WORD;
                        word_number=1;
                        lt_idx=0;
                        clear_string(word);
                        found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                        print_word_number_top(word_number, word_number_text);
                        print_previous_confirmed_word(word_number, word_number_text);
                        print_keyboard_with_validation(lt_idx, found_bool, word);
                    case BACK_BT:// No return here
                        break;
                    case UP_BT:
                        if (selected_share_id<cN_MAX)selected_share_id++;
                        print_sel_share_screen(selected_share_id);
                        break;
                    case DOWN_BT:
                        if (selected_share_id>1)selected_share_id--;
                        print_sel_share_screen(selected_share_id);
                        break;
                    case LEFT_BT:
                        break;
                    case RIGHT_BT:
                        break;
                    default:
                        break;
                }
                break;

            case TMR_INPUT:
                switch (pulsed_bt) {
                    case OK_BT:
                        time_now = TMR1;
                        last_input_len = 16;
                        for (int i = 15; i >= 0; i--) {
                            int bit_i = (int)((time_now >> i) & 1u);
                            set_bit(data_array_256b, bit_count_dice, bit_i);
                            bit_count_dice+=1;
                        }
                        draw_hex16(dice_x_pointer, dice_y_pointer, time_now, 1, ST7735_WHITE, ST7735_BLACK, 1);
                        dice_xy_pointer_line_adjust();
                        if (check_dice_count_end()){
                            if (main_pointer==cMAIN_SSS){ // This time was used to fill the coefficients
                                transition_to_sd_block(SDblock_pointer);
                            }
                            break;
                        }

                        update_dice_bit_count_display(bit_count_dice);

                        break;
                    case BACK_BT:
                    case UP_BT:
                    case DOWN_BT:
                    case LEFT_BT:
                    case RIGHT_BT:
                        break;
                    default:
                        break;
                }
                break;
            case ROLL_DICE1:  /////  ROLL DICE or COIN /////////////
                switch (pulsed_bt) {
                    case OK_BT:
                        if (seed_pointer == cSEED_dice) {
                            append_entropy_bits("11", 2);
                            refresh_entropy_screen();
                        }
                        break;
                    case BACK_BT:
                        if (seed_pointer == cSEED_dice) {
                            append_entropy_bits("01", 2);
                            refresh_entropy_screen();
                        } else if (seed_pointer == cSEED_coin) {
                            if (bit_count_dice > 0) {
                                bit_count_dice--;
                                set_bit(data_array_256b, bit_count_dice, 0);
                                last_input_len = 0; // Clear purple highlight on delete
                                refresh_entropy_screen();
                            }
                        }
                        break;
                    case UP_BT:
                        if (seed_pointer == cSEED_dice) {
                            append_entropy_bits("10", 2);
                            refresh_entropy_screen();
                        }
                        break;
                    case DOWN_BT:
                        append_entropy_bits("1", 1);
                        refresh_entropy_screen();
                        break;
                    case LEFT_BT:
                        append_entropy_bits("0", 1);
                        refresh_entropy_screen();
                        break;
                    case RIGHT_BT:
                        if (seed_pointer == cSEED_dice) {
                            append_entropy_bits("00", 2);
                            refresh_entropy_screen();
                        }
                        break;
                    default:
                        break;
                }
                break;
            case DICE_STRING_INPUT:
                switch (pulsed_bt) {
                    case OK_BT: {
                        int target = (size_pointer == cSIZE_12) ? c12_rolls : c24_rolls;
                        int len = strlen(dice_string_buf);
                        
                        if (dice_input_idx < 6) {
                            if (len < char_hash_limit-1) {
                                char new_char = '1' + dice_input_idx;
                                // 1. Add to buffer
                                add_char_dice(dice_string_buf, dice_input_idx + 1, char_hash_limit);
                                // 2. Delta update: draw the new character on screen
                                update_dice_string_char(len, new_char, false);
                                // 3. Update the counter
                                print_dice_string_counter(len + 1, target);
                                // 4. Refresh keyboard to update DONE color if target is reached
                                print_dice_string_keyboard(dice_input_idx, len + 1, target);
                            }
                        } else if (dice_input_idx == 6) {
                            if (len >= target) {
                                // If Keystone standard (0-5 format) is selected, substitute '6' for '0'
                                if (hash_mode_pointer == 1) { 
                                    for (int i = 0; i < len; i++) {
                                        if (dice_string_buf[i] == '6') {
                                            dice_string_buf[i] = '0';
                                        }
                                    }
                                }
                                
                                // Hash the full string input
                                BYTE hash[SHA256_BLOCK_SIZE];
                                SHA256_CTX ctx;
                                sha256_init(&ctx);
                                sha256_update(&ctx, (BYTE*)dice_string_buf, len);
                                sha256_final(&ctx, hash);
                                
                                // Feed hash output to the main entropy storage
                                for (int i = 0; i < 32; i++) {
                                    data_array_256b[i] = hash[i];
                                }
                                bit_count_dice = (size_pointer == cSIZE_12) ? 128 : 256;
                                
                                black_screen();
                                print_checksum_screen();
                                estado = SHOW_CHECKSUM_DETAILS;
                            }
                        }
                        break;
                    }
                    case BACK_BT: {
                        int target = (size_pointer == cSIZE_12) ? c12_rolls : c24_rolls;
                        int len = strlen(dice_string_buf);
                        
                        if (len > 0) {
                            // 1. Delta update: erase the last character from the screen
                            update_dice_string_char(len - 1, ' ', true);
                            // 2. Delete from buffer
                            remove_last_char(dice_string_buf);
                            // 3. Update the counter
                            print_dice_string_counter(len - 1, target);
                            
                            // Prevent cursor from being stuck on DONE if length falls below target
                            if (len - 1 < target && dice_input_idx == 6) {
                                dice_input_idx = 5;
                            }
                            print_dice_string_keyboard(dice_input_idx, len - 1, target);
                            
                        } else {
                            transition_to_size();
                        }
                        break;
                    }
                    case LEFT_BT: {
                        int target = (size_pointer == cSIZE_12) ? c12_rolls : c24_rolls;
                        int len = strlen(dice_string_buf);
                        if (dice_input_idx > 0) {
                            dice_input_idx--;
                        } else {
                            dice_input_idx = (len >= target) ? 6 : 5;
                        }
                        print_dice_string_keyboard(dice_input_idx, len, target);
                        break;
                    }
                    case RIGHT_BT: {
                        int target = (size_pointer == cSIZE_12) ? c12_rolls : c24_rolls;
                        int len = strlen(dice_string_buf);
                        int max_idx = (len >= target) ? 6 : 5;
                        if (dice_input_idx < max_idx) {
                            dice_input_idx++;
                        } else {
                            dice_input_idx = 0;
                        }
                        print_dice_string_keyboard(dice_input_idx, len, target);
                        break;
                    }
                    case UP_BT:
                    case DOWN_BT:
                        break;
                    default:
                        break;
                }
                break;
            case CARD_INPUT:
                switch (pulsed_bt) {
                    case OK_BT:
                        if (append_selected_card_entropy()) {
                            if (!check_dice_count_end()) {
                                print_card_input_screen();
                            }
                        } else {
                            print_card_input_screen();
                        }
                        break;
                    case BACK_BT:
                        if (card_history_count > 0) {
                            remove_last_card_entropy();
                            print_card_input_screen();
                        } else {
                            transition_to_size();
                        }
                        break;
                    case UP_BT:
                        if (card_field_pointer == 0) {
                            card_rank_pointer++;
                            if (card_rank_pointer > 12) {
                                card_rank_pointer = 0;
                            }
                        } else {
                            card_suit_pointer++;
                            if (card_suit_pointer > 3) {
                                card_suit_pointer = 0;
                            }
                        }
                        print_card_input_screen();
                        break;
                    case DOWN_BT:
                        if (card_field_pointer == 0) {
                            card_rank_pointer--;
                            if (card_rank_pointer < 0) {
                                card_rank_pointer = 12;
                            }
                        } else {
                            card_suit_pointer--;
                            if (card_suit_pointer < 0) {
                                card_suit_pointer = 3;
                            }
                        }
                        print_card_input_screen();
                        break;
                    case LEFT_BT:
                        card_field_pointer = 0;
                        print_card_input_screen();
                        break;
                    case RIGHT_BT:
                        card_field_pointer = 1;
                        print_card_input_screen();
                        break;
                    default:
                        break;
                }
                break;
            case WRITE_WORD:
                switch (pulsed_bt) {
                    case OK_BT:
                       if (lt_idx < 26){
                           bool valid_letters[26];
                           get_valid_next_letters(word, valid_letters);
                           if (valid_letters[lt_idx]) {
                               add_char(word, lt_idx, 32);
                               found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);

                               lt_idx = get_nearest_valid_key(lt_idx, word, found_bool);

                               print_keyboard_with_validation(lt_idx, found_bool, word);
                           }
                       } else if(lt_idx==26){
                            if (found != NULL){
                                if (capturing_xor_word) {
                                    // Save the word index and move to SD/Keyboard selection
                                    obfus_xor_word_idx = find_word_index(found);
                                    capturing_xor_word = false; // Release the hijack
                                    clear_string(word);
                                    found_bool = false;
                                    transition_to_input(selinput_pointer);
                                    break;
                                }
                                // Store the bits
                                write_11bit_value(data_array_256b, word_number,  find_word_index(found));
                                clear_string(word);
                                found_bool= false;

                                if (word_number > (entropy_bits / 11)) { // All words are already entered
                                    black_screen();
                                    if (main_pointer == cMAIN_create && seed_pointer == cSEED_triple) {
                                        estado = PROCESS_TRIPLE;
                                        break;
                                    }
                                    if (main_pointer !=cMAIN_create) { // Check checksum
                                        if(!matches_last_word_checksum(data_array_256b,result,size_pointer)){
                                            if ((main_pointer==cMAIN_XOR) || ((main_pointer==cMAIN_SSS) & (sss_pointer==cMERGE))) {
                                                show_word_list_retry_error();
                                                estado = WORD_LIST_ERROR;
                                            } else {
                                                black_screen();
                                                drawtext(10,10, INCORRECT_MSG, ST7735_RED, ST7735_BLACK, 1);
                                                estado = END_MODE;
                                            }
                                            break;
                                        }
                                    }
                                    
                                    if (main_pointer == cMAIN_MNEM2CARD) {
                                        calculate_card_encoding();
                                        estado = SHOW_CARD_ENCODING;
                                        print_card_encoding_screen();
                                        break;
                                    }
                                    
                                    if (main_pointer==cMAIN_OBFUS) {
                                        if (obfuscation_pointer==cOBFUS_SHIFT){
                                            if (obfus_dir_op == 0){
                                                for (int i = 0; i < obfus_amount; i++) {
                                                    shift_left(data_array_256b, 16 + size_pointer*16);
                                                }
                                            } else {
                                                for (int i = 0; i < obfus_amount; i++) {
                                                    shift_right(data_array_256b, 16 + size_pointer*16);
                                                }
                                            }
                                        } else if (obfuscation_pointer==cOBFUS_NOT){
                                            not_operator(data_array_256b,16 +size_pointer*16);
                                        } else if (obfuscation_pointer==cOBFUS_ADD){
                                            addsub_11bit_groups(16 + size_pointer*16, obfus_amount, obfus_dir_op);
                                        } else if (obfuscation_pointer == cOBFUS_1WORD_XOR) {
                                            apply_1word_xor(obfus_xor_word_idx, size_pointer); // Apply 1 Word XOR
                                        }
                                    } else if ((main_pointer==cMAIN_SSS) & (sss_pointer==cSPLIT)){
                                        expand_sss_coefficients();
                                        sss_split_kofm(data_array_256b /* c0 */,
                                            coeffs, SSS_K /* k threshold */,
                                            LEN,
                                            cN_MAX /* total shares */, // Always kept at max capacity
                                            shares);
                                        for (int i = 0; i < 16 + size_pointer*16; i++) data_array_256b[i]=shares[selected_share_id-1][i];

                                    } else if ((main_pointer==cMAIN_SSS) & (sss_pointer==cMERGE)){
                                        for (int i = 0; i < 32; i++) {
                                                shares_input[shares_loaded][i] = data_array_256b[i];
                                        }
                                        share_indices[shares_loaded] = selected_share_id;
                                        shares_loaded++;
                                        if (shares_loaded>=(SSS_K)){ // We already have K shares
                                            black_screen();
                                            if (!shamir_interpolate(SSS_result,0,share_indices, shares_input,SSS_K,LEN)){
                                                drawtext(10,39, "(Shamir error)", ST7735_RED, ST7735_BLACK, 1);
                                                estado = END_MODE;
                                                break;
                                            }
                                            for (int i = 0; i < 32; i++) data_array_256b[i] = SSS_result[i]; // Copy the result into the data buffer
                                            redraw_show_seed_with_offset();
                                            break;
                                        }
                                        // The merge is not complete yet
                                        black_screen();
                                        print_sel_share_screen(selected_share_id);
                                        estado = SEL_SHARE;
                                        break;

                                    } else if (main_pointer==cMAIN_XOR) {
                                        if (xor_merge_words_available<=xor_pointer){
                                            for (int i = 0; i < 32; i++) {
                                                if (xor_merge_words_available==0){
                                                    xor_merge_word1[i] = data_array_256b[i];
                                                } else if (xor_merge_words_available==1){
                                                    xor_merge_word2[i] = data_array_256b[i];
                                                } else if (xor_merge_words_available==2){
                                                    xor_merge_word3[i] = data_array_256b[i];
                                                }
                                            }
                                            xor_merge_words_available++;
                                            black_screen();
                                            estado = WRITE_WORD;
                                            word_number=1;
                                            // Reset the word buffer before entering the next word
                                            lt_idx=0;
                                            clear_string(word);
                                            found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                                            print_word_number_top(word_number, word_number_text);
                                            print_previous_confirmed_word(word_number, word_number_text);
                                            print_keyboard_with_validation(lt_idx, found_bool, word);
                                            estado = WRITE_WORD;
                                            break;
                                        } else { // All XOR inputs are already loaded
                                            for (int i = 0; i < 16 + size_pointer*16 ; i++) {
                                                data_array_256b[i] = data_array_256b[i] ^ xor_merge_word1[i]^ xor_merge_word2[i]^ xor_merge_word3[i];
                                            }
                                        }
                                    } else if (main_pointer==cMAIN_BIP85) {
                                        black_screen();
                                        drawtext(20, 50, "COMPUTING CHILD", ST7735_WHITE, ST7735_BLACK, 1);
                                        drawtext(20, 65, "MNEMONIC...", ST7735_WHITE, ST7735_BLACK, 1);
                                        estado = PROCESS_BIP85;
                                        break;
                                    }

                                    if (main_pointer == cMAIN_create) {
                                        print_checksum_screen();
                                        estado = SHOW_CHECKSUM_DETAILS;
                                        break;
                                    }

                                    // Finally show the full result for non-create paths
                                    redraw_show_seed_with_offset();
                                    break;
                                }

                                // More words remain after confirming this one.
                                word_number +=1;
                                // Reset the word buffer before entering the next word.
                                lt_idx=0;
                                found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                                print_word_number_top(word_number, word_number_text);
                                print_previous_confirmed_word(word_number, word_number_text);
                                print_keyboard_with_validation(lt_idx, found_bool, word);
                            }
                        }
                        break;
                    case BACK_BT:
                        if (capturing_xor_word && (strlen(word) == 0)) {
                            // Abort and return to obfuscation menu
                            capturing_xor_word = false; 
                            transition_to_obfus();
                            break;
                        } else if ((strlen(word) == 0) & (word_number > 1)) { // Go back one word
                            const char *saved_word;
                            word_number-=1;
                            clear_string(word);
                            saved_word = get_confirmed_word_from_entropy(data_array_256b, word_number);
                            if (saved_word != NULL) {
                                int i = 0;
                                while (i < 31 && saved_word[i] != '\0') {
                                    word[i] = saved_word[i];
                                    i++;
                                }
                                word[i] = '\0';
                                word[31] = '\0';
                            }
                            found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                            print_word_number_top(word_number, word_number_text);
                            print_previous_confirmed_word(word_number, word_number_text);
                            lt_idx=0;
                            print_keyboard_with_validation(lt_idx, found_bool, word);

                        }else{ // Normal backspace
                            remove_last_char(word);
                            found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                            print_keyboard_with_validation(lt_idx, found_bool, word);
                        }
                        break;
                    case UP_BT:
                        update_keyboard_selection(&lt_idx, -9, word, found_bool, word_number, word_number_text);
                        break;
                    case DOWN_BT:
                        update_keyboard_selection(&lt_idx, 9, word, found_bool, word_number, word_number_text);
                        break;
                    case LEFT_BT:
                        update_keyboard_selection(&lt_idx, -1, word, found_bool, word_number, word_number_text);
                        break;
                    case RIGHT_BT:
                        update_keyboard_selection(&lt_idx, 1, word, found_bool, word_number, word_number_text);
                        break;
                    default:
                        break;
                }
                break;
            case SHOW_CHECKSUM_DETAILS:
                switch (pulsed_bt) {
                    case OK_BT:
                        redraw_show_seed_with_offset();
                        break;
                    case BACK_BT:
                    case UP_BT:
                    case DOWN_BT:
                    case LEFT_BT:
                    case RIGHT_BT:
                        break;
                    default:
                        break;
                }
                break;
            case QR_TUTORIAL:
                switch (pulsed_bt) {
                    case OK_BT:
                        break;
                    case BACK_BT:
                        transition_to_main();
                        break;
                    case UP_BT:
                    case DOWN_BT:
                    case LEFT_BT:
                    case RIGHT_BT:
                        break;
                    default:
                        break;
                }
                break;
            case PRECOMPUTE_BIP84:
                // Perform the heavy calculation (shows progress bar)
                precompute_bip84_account();
                
                if (bip84_qr_return_to_menu) {
                    // Returning from Passphrase edit, go back to BIP84 menu
                    bip84_qr_return_to_menu = false;
                    black_screen();
                    print_bip84_menu();
                } else {
                    // Initial seed load, show the words screen
                    redraw_show_seed_with_offset(); 
                }
                
                // Flush any accidental button presses made while waiting
                pulsed_bt = NONE;
                break;
            case SHOW_SEED:
                switch (pulsed_bt) {
                    case OK_BT:
                        bip84_address_index = 0;
                        bip84_extended_key_page = 0;
                        //bip84_account_cached = false;
                        black_screen();
                        print_bip84_menu();
                        break;
                    case BACK_BT:
                        break;
                    case UP_BT:
                        if ((main_pointer==cMAIN_SSS) & (sss_pointer==cSPLIT) & (selected_share_id>1)){ // Shamir split: show previous share
                            selected_share_id--;
                            for (int i = 0; i < 32; i++) data_array_256b[i]=shares[selected_share_id-1][i];
                            redraw_show_seed_with_offset();
                        } else if (main_pointer == cMAIN_create && seed_pointer == cSEED_triple) {
                            if (triple_view_state > 0) {
                                triple_view_state--;
                                refresh_triple_view();
                            }
                        }
                        break;
                    case DOWN_BT:
                        if ((main_pointer==cMAIN_SSS) & (sss_pointer==cSPLIT) &(selected_share_id<(SSS_N))){ // Shamir split: show next share
                            selected_share_id++;
                            for (int i = 0; i < 32; i++) data_array_256b[i]=shares[selected_share_id-1][i];
                            redraw_show_seed_with_offset();
                        } else if (main_pointer == cMAIN_create && seed_pointer == cSEED_triple) {
                            if (triple_view_state < 2) {
                                triple_view_state++;
                                refresh_triple_view();
                            }
                        }
                        break;
                    case LEFT_BT:
                        black_screen();
                        sel_sd_block_screen_wr(SDblock_pointer);
                        estado=SEL_SD_BLOCK_WR;
                        break;
                    case RIGHT_BT: // Compact QR
                        bip84_address_index = 0;
                        bip84_extended_key_page = 0;
                        black_screen();
                        print_bip84_menu();

                        break;
                    default:
                        break;
                }
                break;
            case SHOW_SEED_MENU:
                switch (pulsed_bt) {
                    case OK_BT:
                        if (bip84_menu_pointer == cBIP84_PASSPHRASE) {
                            char pass_title[25] = "BIP39 PASSPHRASE:";
                            // Open text editor. Returns true if user selects SAVE
                            if (full_text_editor(pass_title, 25, bip84_passphrase, 200, PASSPHRASE_MODE)) {
                                // Invalidate cache to force a new derivation with the passphrase
                                bip84_account_cached = false;
                                black_screen();
                                bip84_qr_return_to_menu = true;
                                estado = PRECOMPUTE_BIP84; // Will recalculate and show progress bar
                            } else {
                                // User cancelled, return to menu cleanly
                                black_screen();
                                print_bip84_menu();
                            }
                        } else if (bip84_menu_pointer == cBIP84_SEEDQR) {
                            if (!seedqr_enabled) {
                                black_screen();
                                drawtext(1, 20, "SEEDQR DISABLED", ST7735_RED, ST7735_BLACK, 1);
                                grid_OK_only();
                                break;
                            }

                            white_screen();
                            {
                                BYTE *qr_buf = append_checksum(data_array_256b, 16 + size_pointer * 16);
                                draw_QRSEED(qr_buf, 16 + size_pointer * 16 + 1);                                
                            }
                            bip84_qr_return_to_menu = true;
                            estado = SHOW_QRSEED;
                        } else if (bip84_menu_pointer == cBIP84_SIGN) {
                            black_screen();
                            print_sign_menu();
                        } else {
                            print_bip84_info_screen();
                        }
                        break;
                    case BACK_BT:
                        redraw_show_seed_with_offset();
                        break;
                    case UP_BT:
                        if (bip84_menu_pointer > 0) {
                            bip84_menu_pointer--;
                        }
                        print_bip84_menu();
                        break;
                    case DOWN_BT:
                        if (bip84_menu_pointer < (cBIP84_n_opt - 1)) {
                            bip84_menu_pointer++;
                        }
                        print_bip84_menu();
                        break;
                    default:
                        break;
                }
                break;
            case SIGN_MENU:
                switch (pulsed_bt) {
                    case OK_BT:
                        if (sign_menu_pointer == cSIGN_QR) {
                            scan_ur_animated_qr();
                        } else {
                            load_psbt_from_sd();
                        }
                        black_screen();
                        print_sign_menu();
                        break;
                    case BACK_BT:
                        black_screen();
                        print_bip84_menu();
                        break;
                    case UP_BT:
                        if (sign_menu_pointer > 0) {
                            sign_menu_pointer--;
                        }
                        print_sign_menu();
                        break;
                    case DOWN_BT:
                        if (sign_menu_pointer < (cSIGN_n_opt - 1)) {
                            sign_menu_pointer++;
                        }
                        print_sign_menu();
                        break;
                    default:
                        break;
                }
                break;
            case SHOW_BIP84_INFO:
                switch (pulsed_bt) {
                    case OK_BT: 
                        {
                            if (bip84_menu_pointer == cBIP84_XPUB) {
                                // FAST PATH: Draw QR directly from cache without recalculating
                                const char *value = (bip84_extended_key_page == 0) ? bip84_cached_xpub : bip84_cached_zpub;
                                draw_xpub_qr(value);
                                bip84_qr_return_to_info = true;
                                estado = SHOW_QRSEED;
                            } else if (bip84_menu_pointer == cBIP84_RECEIVE || bip84_menu_pointer == cBIP84_CHANGE) {
                                BitcoinBip84Result result;
                                uint32_t chain = (bip84_menu_pointer == cBIP84_RECEIVE) ? 0u : 1u;
                                if (get_current_bip84_result(chain, bip84_address_index, &result)) {
                                    black_screen();
                                    white_screen();
                                    draw_url_qr(result.address);
                                    bip84_qr_return_to_info = true;
                                    estado = SHOW_QRSEED;
                                }
                            }
                        }
                        break;
                    case BACK_BT:
                        black_screen();
                        print_bip84_menu();
                        break;
                    case UP_BT:
                        if (bip84_menu_pointer == cBIP84_RECEIVE ||
                            bip84_menu_pointer == cBIP84_CHANGE) {
                            if (bip84_address_index > 0) {
                                bip84_address_index--;
                            }
                            print_bip84_info_screen();
                        }
                        break;
                    case DOWN_BT:
                        if (bip84_menu_pointer == cBIP84_RECEIVE ||
                            bip84_menu_pointer == cBIP84_CHANGE) {
                            bip84_address_index++;
                            print_bip84_info_screen();
                        }
                        break;
                    case LEFT_BT:
                    case RIGHT_BT:
                        if (bip84_menu_pointer == cBIP84_XPUB) {
                            bip84_extended_key_page = !bip84_extended_key_page;
                            print_bip84_info_screen();
                        }
                        break;
                    default:
                        break;
                }
                break;
           case SHOW_QRSEED:
                switch (pulsed_bt) {
                    case OK_BT:
                        break;
                    case BACK_BT:
                        if (bip84_qr_return_to_info) {
                            bip84_qr_return_to_info = false;
                            print_bip84_info_screen();
                            break;
                        }
                        if (bip84_qr_return_to_menu) {
                            bip84_qr_return_to_menu = false;
                            black_screen();
                            print_bip84_menu();
                            break;
                        }
                        redraw_show_seed_with_offset();
                        break;
                    case UP_BT:
                    case DOWN_BT:
                        break;
                    case LEFT_BT:
                        if (bip84_qr_return_to_menu) {
                            bip84_qr_return_to_menu = false;
                            black_screen();
                            print_bip84_menu();
                            break;
                        }
                        redraw_show_seed_with_offset();
                        break;
                    case RIGHT_BT:
                        break;
                    default:
                        break;
                }
                break;
            case SHOW_CARD_ENCODING:
                switch (pulsed_bt) {
                    case UP_BT:
                        if (card_view_page > 0) {
                            card_view_page--;
                            print_card_encoding_screen();
                        }
                        break;
                    case DOWN_BT:
                        if ((card_view_page + 1) * 32 < card_sequence_len) {
                            card_view_page++;
                            print_card_encoding_screen();
                        }
                        break;
                    case BACK_BT:
                    case LEFT_BT:
                        transition_to_input(selinput_pointer);
                        break;
                    default:
                        break;
                }
                break;
            case WORD_LIST_ERROR:
                if (pulsed_bt != NONE) {
                    reset_current_word_list_buffer();
                    word_number=1;
                    lt_idx=0;
                    clear_string(word);
                    black_screen();
                    found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                    print_word_number_top(word_number, word_number_text);
                    print_previous_confirmed_word(word_number, word_number_text);
                    print_keyboard_with_validation(lt_idx, found_bool, word);
                    estado = WRITE_WORD;
                }
                break;
            case PROCESS_BIP85:
                process_bip85_derivation();
                redraw_show_seed_with_offset();
                break;
            case PROCESS_TRIPLE: {
                black_screen();
                drawtext(20, 50, "COMPUTING TRIPLE", ST7735_WHITE, ST7735_BLACK, 1);
                drawtext(20, 65, "MNEMONIC...", ST7735_WHITE, ST7735_BLACK, 1);
                
                // 1. Fixing Word 12 (first 128 bits checksum)
                BYTE hash12_first[SHA256_BLOCK_SIZE];
                SHA256_CTX ctx;
                sha256_init(&ctx);
                sha256_update(&ctx, data_array_256b, 16);
                sha256_final(&ctx, hash12_first);

                for (int b = 0; b < 4; b++) {
                    int bit = (hash12_first[0] >> (7 - b)) & 1;
                    set_bit(data_array_256b, 128 + b, bit);
                }

                // 2. Bruteforcing the second half entropy
                while (1) {
                    SYS_Tasks(); // Keep watchdog/system happy
                    
                    // Hash full 256 bits for Word 24
                    BYTE hash24[SHA256_BLOCK_SIZE];
                    sha256_init(&ctx);
                    sha256_update(&ctx, data_array_256b, 32);
                    sha256_final(&ctx, hash24);

                    for (int b = 0; b < 8; b++) {
                        int bit = (hash24[0] >> (7 - b)) & 1;
                        set_bit(data_array_256b, 256 + b, bit);
                    }

                    // Hash the 128 bits of the second seed
                    BYTE second_half_entropy[16] = {0};
                    for (int b = 0; b < 128; b++) {
                        int bit = read_entropy_bit(data_array_256b, 132 + b);
                        if (bit) second_half_entropy[b / 8] |= (1 << (7 - (b % 8)));
                    }
                    
                    BYTE hash12_second[SHA256_BLOCK_SIZE];
                    sha256_init(&ctx);
                    sha256_update(&ctx, second_half_entropy, 16);
                    sha256_final(&ctx, hash12_second);

                    // Check if both hashes match
                    bool match = true;
                    for (int b = 0; b < 4; b++) {
                        int bit_array = read_entropy_bit(data_array_256b, 260 + b);
                        int bit_hash = (hash12_second[0] >> (7 - b)) & 1;
                        if (bit_array != bit_hash) {
                            match = false;
                            break;
                        }
                    }

                    if (match) break;

                    // Increment the 256-bit entropy starting backwards
                    int pos = 255;
                    while (pos >= 132) {
                        if (read_entropy_bit(data_array_256b, pos) == 0) {
                            set_bit(data_array_256b, pos, 1);
                            break;
                        } else {
                            set_bit(data_array_256b, pos, 0);
                            pos--;
                        }
                    }
                }
                
                // Back up the full 24-word generated entropy
                for(int i=0; i<36; i++) triple_backup_256b[i] = data_array_256b[i];

                black_screen();
                print_triple_checksum(12);
                estado = SHOW_TRIPLE_CHKSUM_12;
                break;
            }

            case SHOW_TRIPLE_CHKSUM_12:
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        print_triple_checksum(24);
                        estado = SHOW_TRIPLE_CHKSUM_24;
                        break;
                    default:
                        break;
                }
                break;

            case SHOW_TRIPLE_CHKSUM_24:
                switch (pulsed_bt) {
                    case OK_BT:
                        triple_view_state = 0;
                        refresh_triple_view();
                        break;
                    default:
                        break;
                }
                break;
            case OBFUS_QR_VIEW:
                switch (pulsed_bt) {
                    case OK_BT:
                        break;
                    case BACK_BT:
                        transition_to_obfus();
                        break;
                    default:
                        break;
                }
                break;
            case SEL_SETTINGS:
                switch (pulsed_bt) {
                    case OK_BT:
                        if (settings_pointer == cSETTINGS_SEEDQR) {
                            if (!seedqr_enabled) {
                                seedqr_enabled = true; // OFF -> ON
                                print_seedqr_warning();
                                estado = WARNING_SEEDQR;
                            } else {
                                seedqr_enabled = false; // ON -> OFF
                                black_screen();
                                print_settings_screen(settings_pointer);
                            }
                        }
                    else if (settings_pointer == cSETTINGS_MCU_SERIAL) {
                        print_mcu_serial_screen();
                        estado = SHOW_MCU_SERIAL;
                    }
                    else if (settings_pointer == cSETTINGS_UPDATE_FW) {
                        // Call the warning screen instead of resetting immediately
                        print_update_fw_warning();
                        estado = WARNING_UPDATE_FW;
                    }
                    break;
                case BACK_BT:
                    transition_to_main();
                    break;
                case UP_BT:
                    if (settings_pointer > 0) settings_pointer--;
                    print_settings_screen(settings_pointer);
                    break;
                case DOWN_BT:
                    if (settings_pointer < (cSETTINGS_n_opt-1)) settings_pointer++;
                    print_settings_screen(settings_pointer);
                    break;
                default:
                    break;
            }
            break;

            case WARNING_SEEDQR:
            if (pulsed_bt == OK_BT) {                
                black_screen();
                print_settings_screen(settings_pointer);
                estado = SEL_SETTINGS;
            }
            break;
            case SHOW_MCU_SERIAL:
                if (pulsed_bt == OK_BT || pulsed_bt == BACK_BT) {
                    black_screen();
                    print_settings_screen(settings_pointer);
                    estado = SEL_SETTINGS;
                }
                break;
                
            case WARNING_UPDATE_FW:
                switch (pulsed_bt) {
                    case OK_BT:
                        // Trigger Bootloader Update Sequence
                        black_screen();
                        drawtext(20, 50, "REBOOTING TO", ST7735_ORANGE, ST7735_BLACK, 1);
                        drawtext(20, 65, "BOOTLOADER...", ST7735_WHITE, ST7735_BLACK, 1);
                        
                        delay_ms(1000);
                        
                        // 1. Write the magic word to the predefined RAM address
                        *UPDATE_FLAG_ADDR = MAGIC_WORD_UPDATE;
                        
                        // 2. Unlock system sequence to allow software reset
                        SYSKEY = 0x00000000;
                        SYSKEY = 0xAA996655;
                        SYSKEY = 0x556699AA;
                        
                        // 3. Trigger Software Reset
                        RSWRSTSET = _RSWRST_SWRST_MASK;
                        unsigned int dummy = RSWRST; 
                        (void)dummy;                 
                        
                        while(1); 
                        break;
                        
                    case BACK_BT:
                        // Cancel and return to settings menu
                        black_screen();
                        print_settings_screen(settings_pointer);
                        estado = SEL_SETTINGS;
                        break;
                    default:
                        break;
                }
                break;
                
            case QR_SCANNING:
                switch (pulsed_bt) {
                    case OK_BT: {
                        // 1. Clear hardware errors and flush the UART buffer before triggering
                        if (U2STAbits.OERR) {
                            U2STAbits.OERR = 0; 
                        }
                        while (U2STAbits.URXDA) {
                            (void)U2RXREG; 
                        }

                        // 2. Send the trigger command to the scanner
                        uint8_t trigger_cmd[] = {0x7E, 0x00, 0x08, 0x01, 0x00, 0x02, 0x01, 0xAB, 0xCD};
                        for (int i = 0; i < sizeof(trigger_cmd); i++) {
                            while (U2STAbits.UTXBF); 
                            U2TXREG = trigger_cmd[i]; 
                        }
                        
                        drawtext(10, 30, "SCANNING...    ", ST7735_GREEN, ST7735_BLACK, 1);
                        
                        uint8_t rx_buf[2048];
                        int rx_len = 0;
                        uint32_t timeout = 100000;

                        // 3. Wait for the response
                        while (timeout > 0 && rx_len < sizeof(rx_buf) - 1) {
                            if (U2STAbits.URXDA) {               
                                rx_buf[rx_len++] = U2RXREG; 
                                
                                if (rx_len > 16) {
                                    timeout = 100000; // Time to stop waiting after qr code has already been detected
                                } else {
                                    timeout = 8500000; //Time to detect a QR code
                                }
                            }
                            timeout--;
                        }

                        bool success = false;
                        //char str_buf[8]; 


                        // Draw Total RX Length
                        //drawtext(0, 0, "RX LEN:", ST7735_WHITE, ST7735_BLACK, 1);
                        //u16_to_str((unsigned int)rx_len, str_buf);
                        //drawtext(45, 0, str_buf, ST7735_WHITE, ST7735_BLACK, 1);

                        // 4. Analyze data if we received anything
                        if (rx_len > 0) {
                            uint8_t scan_resp[] = {0x02, 0x00, 0x00, 0x01, 0x00, 0x33, 0x31};
                            int data_start = 0;

                            // Check for the module's start echo
                            if (rx_len >= 7 && memcmp(rx_buf, scan_resp, 7) == 0) {
                                data_start = 7;
                            } 

                            int payload_len = rx_len - data_start;

                            // Draw Payload Length
                            //drawtext(0, 10, "PAY LEN:", ST7735_WHITE, ST7735_BLACK, 1);
                            //u16_to_str((unsigned int)payload_len, str_buf);
                            //drawtext(50, 10, str_buf, ST7735_WHITE, ST7735_BLACK, 1);

                            // Draw ONLY the header/echo
                            //drawtext(0, 20, "HDR:", ST7735_YELLOW, ST7735_BLACK, 1);
                            //int cur_x = 25;
                            //for (int i = 0; i < data_start; i++) {
                            //    u16_to_hex4((uint16_t)rx_buf[i], str_buf);
                                // Skip the first two '00' chars from u16_to_hex4 output
                            //    drawtext(cur_x, 20, &str_buf[2], ST7735_YELLOW, ST7735_BLACK, 1);
                            //    cur_x += 14; 
                            //}

                            if (payload_len > 0) {
                                //drawtext(0, 30, "PAY:", ST7735_CYAN, ST7735_BLACK, 1);

                                //cur_x = 25;
                                //int cur_y = 30;

                                // Loop through ALL payload bytes and print them with screen wrapping
                                //for (int i = 0; i < payload_len; i++) {
                                //    u16_to_hex4((uint16_t)rx_buf[data_start + i], str_buf);
                                    // Skip the first two '00' chars
                                //    drawtext(cur_x, cur_y, &str_buf[2], ST7735_CYAN, ST7735_BLACK, 1);

                                //    cur_x += 14; 

                                    // Screen wrap logic for 160px screen width
                                //    if (cur_x > 140) { 
                                //        cur_x = 25;
                                //        cur_y += 10;
                                //    }
                                //}

                                // Move Y cursor down after payload printing is done
                                //cur_y += 12;

                                // Execute validation
                                bool valid_res = validate_and_load_qr(&rx_buf[data_start], payload_len);

                                // Print validation result
                                //drawtext(0, cur_y, "VAL RES:", ST7735_WHITE, ST7735_BLACK, 1);
                                if (valid_res) {
                                    drawtext(10, 40, "OK!", ST7735_GREEN, ST7735_BLACK, 1);
                                    delay_ms(500); 
                                    redraw_show_seed_with_offset();
                                    success = true;
                                } else {
                                    drawtext(10, 40, "NO SEED or BAD CHECKSUM", ST7735_RED, ST7735_BLACK, 1);
                                }
                            } else {
                                drawtext(10, 40, "NO QR DETECTED", ST7735_RED, ST7735_BLACK, 1);
                            }
                        } else {
                            drawtext(10, 40, "NO RESPONSE FROM SENSOR", ST7735_RED, ST7735_BLACK, 1);
                        }

                        // 5. Keep the debug info on screen for 5 seconds before clearing
                        if (!success) {
                            delay_ms(1000); 
                            black_screen();
                            drawtext(10, 10, "READY TO SCAN", ST7735_YELLOW, ST7735_BLACK, 1);
                        }
                        break;
                    }
                    case BACK_BT:
                        transition_to_input(selinput_pointer);
                        break;
                    default:
                        break;
                }
                break;
            case END_MODE:
                switch (pulsed_bt) {
                    case OK_BT:
                    case BACK_BT:
                        transition_to_main();
                        break;
                    default:
                        break;
                }
                break;
            default:
                break;
        }
        
        pulsed_bt = NONE; // Global clear at the end of the tick
    }

    /* Execution should not come here during normal operation */

    return ( EXIT_FAILURE );
}


/*******************************************************************************
 End of File
*/