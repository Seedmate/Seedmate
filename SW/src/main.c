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
 * Date:        29/8/2026
 * Version:     v1.5                               
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
#include "words_opt.h"
#include <string.h>
#include "SSS/shamir.h"
#include "QRCode-master/src/qrcode.h"
#define QR_SCALE 4 // Size of each module in pixels
#define SCREEN_WIDTH 160
#define SCREEN_HEIGHT 128


#define cVersion "v1.5"

#define SD_SCK    PORTBbits.RB7
#define SD_CS     PORTCbits.RC9
#define SD_MISO   PORTAbits.RA4
#define SD_MOSI   PORTAbits.RA3

// Pin mapping
#define LED       PORTAbits.RA2   // CPU activity led

// LCD
#define LED_LCD   PORTBbits.RB10  // TFT backlight control

// Buttons
#define BT1       PORTBbits.RB2   // Button 1
#define BT2       PORTBbits.RB12  // Button 2
#define BT_OK     PORTBbits.RB13  // Button 3
#define BT4       PORTBbits.RB3   // Button 4
#define BT5       PORTBbits.RB11  // Button 5
#define BT6       PORTBbits.RB6   // Button 6



#define cMAIN_n_opt 8
#define cSEED_n_opt 6
#define cSIZE_n_opt 2
#define cOBFUS_n_opt 3
#define cXOR_n_opt 3
#define cSSS_n_opt 2
#define cQR_n_opt 2
#define cSDBLOCK_n_opt 8
#define cSELINPUT_n_opt 2
#define cDICE_MODE_n_opt 2
#define cHASH_MODE_n_opt 2
#define cRESOURCE_n_opt 4
#define cEND_OF_LINE 150
#define cENTROPY_BITS12W 127
#define cENTROPY_BITS24W 255
#define cCARD_MAX_HISTORY 128


#define cMAIN_create 0
#define cMAIN_LOAD 1
#define cMAIN_BIP85 2
#define cMAIN_SSS 3
#define cMAIN_XOR 4
#define cMAIN_OBFUS 5
#define cMAIN_ERASESD 6
#define cMAIN_QR 7 // Resources menu

#define cRESOURCE_tutorial 0
#define cRESOURCE_backup 1
#define cRESOURCE_dice_test 2
#define cRESOURCE_wordlist 3

#define cOBFUS_SHIFT 0
#define cOBFUS_NOT 1
#define cOBFUS_ADD 2

#define cSEED_coin 0
#define cSEED_dice 1
#define cSEED_word 2
#define cSEED_cards 3
#define cSEED_timer 4
#define cSEED_triple 5


#define cSIZE_12 0
#define cSIZE_24 1

#define cKEYBOARD 0
#define cFROMSD 1
#define cSD_CHECKSUM_ADDR 64
#define cSD_SIZE_ADDR 65
#define cSD_XOR_ADDR 66 // Key storage offset

#define cLEFT 0
#define cRIGTH 1

#define cADD 0
#define cSUB 1

#define cNOTSAFE 0
#define cSAFE 1

#define cREAD 0
#define cWRITE 1

#define cQRCOMPACT 1

#define  cSPLIT 0
#define  cMERGE 1

// SSS limits
#define  cK_MAX 6 // Max 6th order polynomial
#define  cN_MAX 9 // Max 9 samples

#define INCORRECT_MSG "INCORRECT SET OF WORDS"
#define LOAD_OK "LOAD OK"
#define OK_MSG "OK"

#define SHA512_SIZE 64          // SHA512 output size
#define BLOCK_SIZE 128 // SHA512 block size

// ============================================================================
// Global Menus (Forces the compiler to store pointers strictly in ROM)
// ============================================================================
const char* const menu_create[]   = {"THROW COINS", "ROLL DICE", "RANDOM WORD PICK", "DRAW CARDS", "STOPWATCH TEST ONLY", "TRIPLE MNEMONIC"};
const char* const menu_dice[]     = {"RAW ENTROPY BITS", "STRING HASH"};
const char* const menu_hash[]     = {"1-6 mode", "0-5 mode (Keystone)"};
const char* const menu_size[]     = {"12 WORDS", "24 WORDS"};
const char* const menu_qr[]       = {"STANDARD", "COMPACT"};
const char* const menu_xor[]      = {"A XOR B = C", "A XOR B XOR C = D", "A XOR B XOR C XOR D = E"};
const char* const menu_sss[]      = {"SPLIT", "MERGE"};
const char* const menu_input[]    = {"FROM KEYBOARD", "FROM SD"};
const char* const menu_resource[] = {"TUTORIAL", "BACKUP TOOL", "DICE TESTER", "PRINT WORDLIST"};
const char* const menu_obfus[]    = {"CIRCULAR SHIFT", "NOT OPERATOR", "WORDS ADD/SUB"}; 


int main_pointer = 0;
int obfuscation_pointer =0;
int sss_pointer = 0;
int resource_pointer = 0;
uint8_t  selected_share_id = 1;
int shares_loaded = 0;

int bip85_size = cSIZE_12;
int bip85_index = 0;
int bip85_cursor = 0;

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

#define char_hash_limit 501
char dice_string_buf[char_hash_limit] = {0};
int dice_input_idx = 0; // 0-5 for '1'-'6', 6 for DONE

BYTE data_array_256b[36] = {0}; // Increased buffer size to handle excess bits tracking
int size_pointer = 0;
int bit_count_dice = 0;
int entropy_bits = 0;
int last_input_len = 0; // Tracks the length of the most recent entropy input

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


int coeff_byte_idx = 0;

// Pointer table to avoid a switch
uint8_t * const coefficient_buffers[5] = { c0, c1, c2, c3, c4 };
static void u16_to_hex4(uint16_t value, char *buf);
static size_t u16_to_str(unsigned int n, char *buf);
static size_t u16_to_str_pad(unsigned int n, char *buf, unsigned int width);
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
void black_screen(void);
void set_bit(BYTE data_array[36], int bit_index, int value);
const char* get_confirmed_word_from_entropy(const BYTE data_array[36], int index);
int read_11bit_value(const BYTE data_array[36], int index);
void print_checksum_screen(void);
void print_word_number_top(int word_number, char *word_number_text);
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
            
            // Simple UI Progress Bar 
            if (j % 102 == 0) {
                int chunk = j / 102; // Yields 1 through 20
                rectan(20 + (chunk * 5), 70, 24 + (chunk * 5), 80, ST7735_GREEN);
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

void draw_hex16(unsigned int x, unsigned int y, uint16_t numero, int N, unsigned int color, unsigned int bg, unsigned int size) {
    char hex_text[5]; // 4 hex digits plus null terminator

    for (int i = 0; i < N; i++) {
        u16_to_hex4(numero, hex_text); // Convert the value to hexadecimal text
        drawtext(x + i * (12 * size), y, hex_text, color, bg, size); // Adjust spacing for the current size
    }
}


static void process_bip85_derivation(void) {
    char mnemonic_str[250]; 
    get_mnemonic_string(mnemonic_str);
    
    // Convert the entire mnemonic string to lowercase per BIP39 standard
    for (int i = 0; mnemonic_str[i] != '\0'; i++) {
        if (mnemonic_str[i] >= 'A' && mnemonic_str[i] <= 'Z') {
            mnemonic_str[i] = mnemonic_str[i] + ('a' - 'A');
        }
    }
    
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



void update_entropy_coefficients(void){
    if (coeff_byte_idx < (TOTAL_BYTES-2)) {
        uint16_t t = TMR1;               // Read the 16-bit timer
        uint8_t  lo = (uint8_t)t;        // Low byte
        uint8_t  hi = (uint8_t)(t >> 8); // High byte

        // Store the low byte first.
        write_coefficient_byte(coeff_byte_idx, lo);
        coeff_byte_idx += 1;
        write_coefficient_byte(coeff_byte_idx, hi);
        coeff_byte_idx += 1;

    }
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
    RIGTH_BT,
} PULSED_BT_t;


void spi_send(uint8_t data) {
    for (int i = 0; i < 8; i++) {
        if (data & 0x80) SD_MOSI = 1; else SD_MOSI = 0; // MOSI
        SD_SCK = 1; // SCK HIGH
        data <<= 1;
        SD_SCK = 0; // SCK LOW
    }
}

// ============================================================================
// BITMAP GRAPHICS REPLACEMENT
// ============================================================================
const uint16_t bmp_camera[11]      = { 0x0700, 0x0880, 0xF078, 0x8708, 0x8888, 0x9048, 0x9048, 0x8888, 0x8708, 0x8008, 0xFFF8 };
const uint16_t bmp_arrow_up[6]     = { 0x2000, 0x7000, 0xF800, 0x2000, 0x2000, 0x2000 };
const uint16_t bmp_arrow_down[6]   = { 0x2000, 0x2000, 0x2000, 0xF800, 0x7000, 0x2000 };
const uint16_t bmp_arrow_left[5]   = { 0x2000, 0x6000, 0xFC00, 0x6000, 0x2000 };
const uint16_t bmp_arrow_right[5]  = { 0x1000, 0x1800, 0xFC00, 0x1800, 0x1000 };
const uint16_t bmp_add_symbol[7]   = { 0x1000, 0x1000, 0x1000, 0xFE00, 0x1000, 0x1000, 0x1000 };

// Generic 1-bit monochrome renderer
void draw_bitmap(int x, int y, int w, int h, const uint16_t *bitmap, uint16_t color) {
    for (int j = 0; j < h; j++) {
        uint16_t row = bitmap[j];
        for (int i = 0; i < w; i++) {
            if (row & (0x8000 >> i)) {
                fillRect(x + i, y + j, 1, 1, color);
            }
        }
    }
}

void print_up_arrow(int x, int y) {
    draw_bitmap(x, y - 6, 5, 6, bmp_arrow_up, WHITE);
}

void print_add_symbol(int x, int y) {
    draw_bitmap(x, y - 7, 7, 7, bmp_add_symbol, WHITE);
}

void print_down_arrow(int x, int y) {
    draw_bitmap(x, y - 6, 5, 6, bmp_arrow_down, WHITE);
}

void print_left_arrow(int x, int y) {
    draw_bitmap(x, y - 5, 6, 5, bmp_arrow_left, WHITE);
}

void print_left_arrow_black(int x, int y) {
    draw_bitmap(x, y - 5, 6, 5, bmp_arrow_left, BLACK);
}

void print_rigth_arrow(int x, int y) {
    draw_bitmap(x, y - 5, 6, 5, bmp_arrow_right, WHITE);
}

void print_camera(int x, int y, int safe) {
    uint16_t color = (safe == cSAFE) ? ST7735_GREEN : ST7735_RED;
    draw_bitmap(x, y - 10, 13, 11, bmp_camera, color);
}
// ============================================================================



void print_cursor_grid(){
    drawFastHLine(60,105,90,WHITE);
    drawFastHLine(60,115,90,WHITE);
    drawFastHLine(60,125,90,WHITE);
    drawFastVLine(60,105,20,WHITE);
    drawFastVLine(90,105,20,WHITE);
    drawFastVLine(120,105,20,WHITE);
    drawFastVLine(150,105,20,WHITE);
}


void print_minus_symbol(int x,int y){
    drawFastHLine(x,y-3,7,WHITE);
}

void print_ok(){
    drawtext(130,107, OK_MSG, ST7735_WHITE, ST7735_WHITE, 1);
}


void grid_menu1(){
    print_cursor_grid();
    print_up_arrow(103,114);
    print_down_arrow(103,123);
    print_ok();
}
void grid_menuwr(){
    print_cursor_grid();
    print_up_arrow(103,114);
    print_down_arrow(103,123);
    print_ok();
    drawtext(64,107, "LIST", ST7735_WHITE, ST7735_WHITE, 1);
    drawtext(122,117, "PAGE+", ST7735_WHITE, ST7735_WHITE, 1);
    drawtext(62,117, "PAGE-", ST7735_WHITE, ST7735_WHITE, 1);
}

void print_back(){
    drawtext(64,107, "BACK", ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_menu2(){
    print_cursor_grid();
    print_up_arrow(103,114);
    print_down_arrow(103,123);
    print_ok();
    print_back();

}
void grid_menuSD(){
    print_cursor_grid();
    print_up_arrow(103,114);
    print_down_arrow(103,123);
    print_ok();
    print_back();
    drawtext(122,117, "PAGE+", ST7735_WHITE, ST7735_WHITE, 1);
    drawtext(62,117, "PAGE-", ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_menu2_merge(){
    print_cursor_grid();
    print_up_arrow(103,114);
    print_down_arrow(103,123);
    print_ok();
    print_back();
    drawtext(125,117, "ID++", ST7735_WHITE, ST7735_WHITE, 1);
    drawtext(64,117, "ID--", ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_nbits(){
    print_cursor_grid();
    print_add_symbol(103,114);
    print_minus_symbol(103,123);
    print_ok();
    print_back();
}

void grid_nbits_noback(){
    print_cursor_grid();
    print_add_symbol(103,114);
    print_minus_symbol(103,123);
    print_ok();
}

void grid_nbits_LR(){
    print_cursor_grid();
    print_add_symbol(103,114);
    print_minus_symbol(103,123);
    print_ok();
    print_back();
    print_left_arrow(73,123);
    print_rigth_arrow(133,123);
}

void grid_keyboard(){
    print_cursor_grid();
    print_up_arrow(103,114);
    print_down_arrow(103,123);
    print_left_arrow(73,123);
    print_rigth_arrow(133,123);
    print_ok();
    drawtext(67,107, "DEL", ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_keyboard_dice_hash(){
    print_cursor_grid();
    print_left_arrow(73,123);
    print_rigth_arrow(133,123);
    print_ok();
    drawtext(67,107, "DEL", ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_bip85(){
    print_cursor_grid();
    print_up_arrow(103,114);
    print_down_arrow(103,123);
    print_left_arrow(73,123);
    print_rigth_arrow(133,123);
    print_ok();
    print_back();
}

void draw_mini_dice(int x, int y, int value) {
    // Draw the background of the dice filled with white
    rectan(x, y, x + 6, y + 6, WHITE);

    // Draw the dots in BLACK
    // 1, 3, 5: Center dot
    if (value == 1 || value == 3 || value == 5) {
        fillRect(x + 3, y + 3, 1, 1, BLACK);
    }
    // 2, 3, 4, 5, 6: Top-left and bottom-right dots
    if (value >= 2) {
        fillRect(x + 1, y + 1, 1, 1, BLACK);
        fillRect(x + 5, y + 5, 1, 1, BLACK);
    }
    // 4, 5, 6: Top-right and bottom-left dots
    if (value >= 4) {
        fillRect(x + 5, y + 1, 1, 1, BLACK);
        fillRect(x + 1, y + 5, 1, 1, BLACK);
    }
    // 6: Center-left and right dots
    if (value == 6) {
        fillRect(x + 1, y + 3, 1, 1, BLACK);
        fillRect(x + 5, y + 3, 1, 1, BLACK);
    }
}

void grid_dices(){              
    print_cursor_grid();
    
    // Row 1: Dice 1, 2, 3
    draw_mini_dice(62, 107, 1);
    drawtext(71, 107, "=01", ST7735_WHITE, ST7735_BLACK, 1);

    draw_mini_dice(92, 107, 2);
    drawtext(101, 107, "=10", ST7735_WHITE, ST7735_BLACK, 1);

    draw_mini_dice(122, 107, 3);
    drawtext(131, 107, "=11", ST7735_WHITE, ST7735_BLACK, 1);

    // Row 2: Dice 4, 5, 6
    draw_mini_dice(65, 117, 4);
    drawtext(74, 117, "=0", ST7735_WHITE, ST7735_BLACK, 1);

    draw_mini_dice(95, 117, 5);
    drawtext(104, 117, "=1", ST7735_WHITE, ST7735_BLACK, 1);

    draw_mini_dice(122, 117, 6);
    drawtext(131, 117, "=00", ST7735_WHITE, ST7735_BLACK, 1);
}

void grid_coins(){              // Heads tails
    print_cursor_grid();
    drawtext(64,117, "HEAD", ST7735_WHITE, ST7735_WHITE, 1);
    drawtext(94,117, "TAIL", ST7735_WHITE, ST7735_WHITE, 1);
    // Added DEL button logic to grid representation for coins
    drawtext(67,107, "DEL", ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_TMR(){
    print_cursor_grid();
    print_ok();
}

void version_display(){

    drawtext(120,119, cVersion, ST7735_WHITE, ST7735_WHITE, 1);

}
static bool SD_ready= false;

// ============================================================================
// Generic Menu Renderer
// ============================================================================
void print_generic_menu(const char* const *options, int n_opt, int sel) {
    for (int i = 0; i < n_opt; i++) {
        uint16_t color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 10 + i * 10, (char*)options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
}

void main_screen(int sel) {
    char* opciones[] = {
        "CREATE NEW SEED WORDS",
        "LOAD SEED WORDS",
        "BIP85 CHILD SEED",
        "SHAMIR SECRET SHARE",
        "SEED WORD XOR",
        "OBFUSCATION",
        "ERASE SD",
        "RESOURCES"
    };

    for (int i = 0; i < cMAIN_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 5 + i * 10, opciones[i], color, ST7735_BLACK, 1);
    }
    if(SD_ready)drawtext(10, 118, "SD OK", ST7735_GREEN, ST7735_BLACK, 1);
    grid_menu1();
}

static int last_sel = 0;
void main_screen_fast(int sel) {
    char* opciones[] = {
        "CREATE NEW SEED WORDS",
        "LOAD SEED WORDS",
        "BIP85 CHILD SEED",
        "SHAMIR SECRET SHARE",
        "SEED WORD XOR",
        "OBFUSCATION",
        "ERASE SD",
        "RESOURCES"
    };

    if (last_sel != -1 && last_sel != sel) {
        // Repaint the previous one in white
        drawtext(1, 5 + last_sel * 10, opciones[last_sel], ST7735_WHITE, ST7735_BLACK, 1);
    }

    // Paint the new one in orange
    drawtext(1, 5 + sel * 10, opciones[sel], ST7735_ORANGE, ST7735_BLACK, 1);

    last_sel = sel;
}
int SD_page = 0;


static void u16_to_hex4(uint16_t value, char *buf) {
    static const char hex[] = "0123456789ABCDEF";
    buf[0] = hex[(value >> 12) & 0x0F];
    buf[1] = hex[(value >> 8) & 0x0F];
    buf[2] = hex[(value >> 4) & 0x0F];
    buf[3] = hex[value & 0x0F];
    buf[4] = '\0';
}

// Minimal base-10 itoa without dependencies
static size_t u16_to_str(unsigned int n, char *buf) {
    char tmp[6]; // Enough for 65535
    int i = 0;
    do {
        tmp[i++] = (char)('0' + (n % 10));
        n /= 10;
    } while (n > 0);
    // Reverse into the destination buffer
    int j = 0;
    while (i > 0) {
        buf[j++] = tmp[--i];
    }
    buf[j] = '\0';
    return (size_t)j;
}

static size_t u16_to_str_pad(unsigned int n, char *buf, unsigned int width) {
    char tmp[6];
    unsigned int i = 0;
    unsigned int j = 0;

    do {
        tmp[i++] = (char)('0' + (n % 10));
        n /= 10;
    } while (n > 0);

    while (i < width) {
        buf[j++] = '0';
        width--;
    }

    while (i > 0) {
        buf[j++] = tmp[--i];
    }

    buf[j] = '\0';
    return (size_t)j;
}



static uint8_t get_selected_card_index(void) {
    return (uint8_t)(card_suit_pointer * 13 + card_rank_pointer);
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

static void draw_card_bit_counter(void) {
    char current_bits[4];
    char counter_text[16];
    const char *target_bit_count = (size_pointer == cSIZE_24) ? "256 bits" : "128 bits";

    u16_to_str_pad((unsigned int)bit_count_dice, current_bits, 3);
    memcpy(counter_text, current_bits, 3);
    counter_text[3] = '/';
    memcpy(&counter_text[4], target_bit_count, strlen(target_bit_count) + 1);
    drawtext(45, 15, counter_text, ST7735_WHITE, ST7735_BLACK, 1);

}

static void draw_card_selection(void) {
    uint8_t card_index = get_selected_card_index();
    const char *bits = card_entropy_map[card_index];
    uint16_t rank_color = (card_field_pointer == 0) ? ST7735_ORANGE : ST7735_WHITE;
    uint16_t suit_color = (card_field_pointer == 1) ? ST7735_ORANGE : ST7735_WHITE;

    drawtext(1, 25, "CARD:", ST7735_WHITE, ST7735_BLACK, 1);
    char rank_text[2] = { card_rank_chars[card_rank_pointer], '\0' };
    char suit_text[2] = { card_suit_chars[card_suit_pointer], '\0' };
    drawtext(40, 25, rank_text, rank_color, ST7735_BLACK, 1);
    drawtext(48, 25, suit_text, suit_color, ST7735_BLACK, 1);
    drawtext(62, 25, "BITS:", ST7735_WHITE, ST7735_BLACK, 1);

    // Manual padding to save memory
    char padded_bits[6] = "     "; // 5 leading spaces plus null terminator
    for (int i = 0; i < 5 && bits[i] != '\0'; i++) {
        padded_bits[i] = bits[i];
    }

    drawtext(96, 25, padded_bits, ST7735_CYAN, ST7735_BLACK, 1);
}

// Unified visual helper for building entropy for cards, dice, and coins
static int read_entropy_bit(const BYTE data_array[36], int bit_index) {
    if (bit_index < 0 || bit_index >= 288) { // Updated bounds
        return 0;
    }

    int byte_index = bit_index / 8;
    int bit_position = 7 - (bit_index % 8);
    return (data_array[byte_index] >> bit_position) & 1;
}

void draw_shared_entropy_building(void) {
    rectan(0, 35, 159, 43, BLACK); 
    int completed_words = bit_count_dice / 11;
    int remaining_bits = bit_count_dice % 11;
    char buf[64];

    // Track the last known state to prevent unnecessary history redraws
    static int last_completed_words = -1;
    static bool history_has_purple = false;
    
    // Check if the number of completed words changed or if the screen was reset
    bool words_changed = (completed_words != last_completed_words) || (bit_count_dice == 0);
    
    // We redraw history if words changed, OR if we left purple bits in the history last time.
    bool redraw_history = words_changed || history_has_purple;
    last_completed_words = completed_words;

    // ---------------------------------------------------------
    // Row 1: Active bits currently being accumulated
    // (ALWAYS redraw this row since it changes on every input)
    // ---------------------------------------------------------
    if (remaining_bits > 0) {
        int cursor_x = 1;
        for (int i = 0; i < remaining_bits; i++) {
            int abs_idx = completed_words * 11 + i;
            uint16_t color = (abs_idx >= bit_count_dice - last_input_len) ? ST7735_MAGENTA : ST7735_ORANGE;
            char single_char[2] = { read_entropy_bit(data_array_256b, abs_idx) ? '1' : '0', '\0' };
            drawtext(cursor_x, 35, single_char, color, ST7735_BLACK, 1);
            cursor_x += 6;
        }
        // Pad spaces to overwrite any trailing characters
        char pad_str[24] = {0};
        for (int p = 0; p < 20 - remaining_bits; p++) pad_str[p] = ' ';
        drawtext(cursor_x, 35, pad_str, ST7735_BLACK, ST7735_BLACK, 1);
    } else if (bit_count_dice == 0) {
        // Draw a solid black row to clear TFT pixels before writing
        rectan(0, 35, 159, 44, BLACK); 
        drawtext(1, 35, "WAITING FOR INPUT...", ST7735_GREY, ST7735_BLACK, 1); 
    } else {
        // Clears the active row cleanly when bits exactly match a word boundary
        rectan(0, 35, 159, 44, BLACK); 
    }

    // ---------------------------------------------------------
    // Rows 2 to 6: Displaying up to the 5 previous completed words
    // ---------------------------------------------------------
    if (redraw_history) {
        int y_offset = 45;
        history_has_purple = false; // Reset the flag before drawing
        
        // If the only reason to redraw is to clear purple bits, we only need 
        // to update the first history row (which is the second row overall on the screen, r = 0).
        int rows_to_draw = words_changed ? 5 : 1;
        
        for (int r = 0; r < rows_to_draw; r++) {
            int word_index = completed_words - 1 - r; 
            
            if (word_index >= 0) {
                // There is a completed word to display for this row
                int word_val = read_11bit_value(data_array_256b, word_index + 1); 
                const char* word_str = get_confirmed_word_from_entropy(data_array_256b, word_index + 1);

                int cursor_x = 1;
                for (int b = 0; b < 11; b++) {
                    int abs_idx = word_index * 11 + b;
                    
                    bool is_purple = (abs_idx >= bit_count_dice - last_input_len);
                    if (is_purple) {
                        history_has_purple = true; // Mark that this row contains purple bits
                    }
                    uint16_t color = is_purple ? ST7735_MAGENTA : ST7735_GREEN;
                    
                    char single_char[2] = { read_entropy_bit(data_array_256b, abs_idx) ? '1' : '0', '\0' };
                    drawtext(cursor_x, y_offset, single_char, color, ST7735_BLACK, 1);
                    cursor_x += 6;
                }

                char dec_str[6];
                u16_to_str_pad((unsigned int)word_val, dec_str, 4);

                int pos = 0;
                buf[pos++] = ' ';
                
                int d = 0;
                while (dec_str[d] != '\0') buf[pos++] = dec_str[d++];
                
                buf[pos++] = ' ';                
               
                int w = 0;
                while (word_str && word_str[w] != '\0') buf[pos++] = word_str[w++];
                
                // Pad with spaces to overwrite ghost characters in shorter words.
                // Changed from 26 to 15 to prevent TFT line-wrap overlay.
                while (pos < 15) {
                    buf[pos++] = ' ';
                }
                buf[pos] = '\0';

                drawtext(cursor_x, y_offset, buf, ST7735_GREEN, ST7735_BLACK, 1);
            } else {
                // No word exists for this slot, print a solid black row to erase the TFT pixels completely
                rectan(0, y_offset, 159, y_offset + 9, BLACK);
            }
            
            y_offset += 10;
        }
    }
}

static void print_card_input_screen(void) {
    drawtext(1, 5, (size_pointer == cSIZE_24) ? "DRAW CARDS UP TO 256 BITS" : "DRAW CARDS UP TO 128 BITS", ST7735_WHITE, ST7735_BLACK, 1);
    draw_card_bit_counter();
    draw_card_selection();
    
    draw_shared_entropy_building();
    grid_keyboard();
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

    grid_TMR(); 
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
    grid_TMR(); 
}

void print_diceroll_screen(int sel, int sel2){

    // sel: 0 -> 128 bits, 1 -> 256 bits

     char *text_dices = sel ? "ROLL DICE up to 256 bits" : "ROLL DICE up to 128 bits";
     char *text_coins = sel ? "THROW COINS up to 256 bits" : "THROW COINS up to 128 bits";
     char *text_bits = sel ? "000/256 bits" : "000/128 bits";

        if (sel2==0){
            drawtext(1,5, text_coins, ST7735_WHITE, ST7735_BLACK, 1);
            grid_coins();
        } else {
            drawtext(1,5, text_dices, ST7735_WHITE, ST7735_BLACK, 1);
            grid_dices();
        }
        drawtext(45,15, text_bits, ST7735_WHITE, ST7735_BLACK, 1);
        draw_shared_entropy_building();
}

void print_TMR_screen(int size_TMR){

    // sel: 0 -> 128 bits, 1 -> 256 bits
    drawtext(1,5, "STOP timer to set entropy", ST7735_WHITE, ST7735_BLACK, 1);
    char *text_TMR_SEED = size_TMR ? "000/256 bits" : "000/128 bits";
    drawtext(45,15, text_TMR_SEED, ST7735_WHITE, ST7735_BLACK, 1);
    grid_TMR();
}

void print_child_config_screen(void) {
    drawtext(1, 10, "CHILD SIZE:", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(80, 10, "BIP85 INDEX:", ST7735_WHITE, ST7735_BLACK, 1);

    uint16_t size_color = (bip85_cursor == 0) ? ST7735_ORANGE : ST7735_WHITE;
    uint16_t index_color = (bip85_cursor == 1) ? ST7735_ORANGE : ST7735_WHITE;

    const char *size_str = (bip85_size == cSIZE_12) ? "12 WORDS" : "24 WORDS";
    drawtext(10, 30, (char*)size_str, size_color, ST7735_BLACK, 1);

    char index_str[12];
    u16_to_str((unsigned int)bip85_index, index_str);
    rectan(80, 30, 159, 38, BLACK); // clear index area
    drawtext(100, 30, index_str, index_color, ST7735_BLACK, 1);

    grid_bip85();
}

// Unified Obfuscation Configuration Screen
int obfus_cursor = 0;
int obfus_dir_op = 0;
int obfus_amount = 1;

void print_obfus_config_screen(void) {
    drawtext(1, 10, "Operation:", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(100, 10, "Amount:", ST7735_WHITE, ST7735_BLACK, 1);

    uint16_t op_color = (obfus_cursor == 0) ? ST7735_ORANGE : ST7735_WHITE;
    uint16_t amt_color = (obfus_cursor == 1) ? ST7735_ORANGE : ST7735_WHITE;

    const char *op_str = "";
    if (obfuscation_pointer == cOBFUS_SHIFT) {
        op_str = (obfus_dir_op == 0) ? "LEFT SHIFT " : "RIGHT SHIFT";
    } else {
        op_str = (obfus_dir_op == 0) ? "ADD WORDS" : "SUB WORDS";
    }
    
    drawtext(10, 30, (char*)op_str, op_color, ST7735_BLACK, 1);

    char amt_str[12];
    u16_to_str((unsigned int)obfus_amount, amt_str);
    rectan(100, 30, 159, 38, BLACK); // clear amount area
    drawtext(100, 30, amt_str, amt_color, ST7735_BLACK, 1);

    grid_bip85(); // Left/Right/Up/Down/OK/Back
}


// Update only roll count
void print_dice_string_counter(int current_len, int target) {
    char counter_text[24]; // Increased buffer size to fit the prefix
    char current_text[4];
    char target_text[4];
    
    u16_to_str_pad((unsigned int)current_len, current_text, 3);
    u16_to_str_pad((unsigned int)target, target_text, 3);
    
    int pos = 0;
    
    // Insert prefix
    memcpy(&counter_text[pos], "Dice rolls: ", 12); 
    pos += 12;
    
    // Insert the numbers
    memcpy(&counter_text[pos], current_text, 3); 
    pos += 3;
    counter_text[pos++] = '/';
    memcpy(&counter_text[pos], target_text, 3); 
    pos += 3;
    counter_text[pos] = '\0';
    
    // Adjusted X coordinate from 50 to 20 to keep it centered 
    // and prevent overflowing the 160px width
    drawtext(20, 5, counter_text, ST7735_WHITE, ST7735_BLACK, 1);
}

// Update only number selection
void print_dice_string_keyboard(int sel, int current_len, int target) {
    const char* keys[7] = {"1", "2", "3", "4", "5", "6", "DONE"};
    int kx[7] = {10, 30, 50, 70, 90, 110, 130};
    
    for(int i = 0; i < 6; i++) {
        uint16_t color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(kx[i], 90, (char*)keys[i], color, ST7735_BLACK, 1);
    }
    // DONE color logic
    uint16_t done_color;
    if (sel == 6) {
        done_color = ST7735_ORANGE; // Selected
    } else if (current_len >= target) {
        done_color = ST7735_GREEN;  // Enough rolls, can be selected
    } else {
        done_color = ST7735_GREY;   // Not enough rolls yet
    }
    
    drawtext(130, 90, "DONE", done_color, ST7735_BLACK, 1);
}

// Only update the modified character to speed up
void update_dice_string_char(int index, char c, bool is_delete) {
    int chars_per_line = 25;
    int screen_capacity = 200; // 8 lines * 25 characters
    
    // Wrap the index to fit within the 200-character screen limit
    int wrapped_index = index % screen_capacity;
    int wrap_count = index / screen_capacity;
    
    int line = wrapped_index / chars_per_line;
    int col = wrapped_index % chars_per_line;
    
    // 1 letter = 5 pixels width + 1 pixel space = 6
    int x = 5 + (col * 6); 
    // Start higher at Y=14 (just below the counter) and use 9px line spacing to prevent overlap
    int y = 14 + (line * 9);
    
    char single_char[2] = { '\0', '\0' };
    uint16_t color;
    
    if (is_delete) {
        if (wrap_count > 0) {
            // Restore the character from the previous page
            single_char[0] = dice_string_buf[index - screen_capacity];
            color = (wrap_count == 1) ? ST7735_CYAN : ST7735_YELLOW;
        } else {
            // Erase character on the first page by redrawing the exact same character in BLACK
            single_char[0] = dice_string_buf[index]; 
            color = ST7735_BLACK;
        }
    } else {
        single_char[0] = c;
        // Alternate colors based on how many times the screen has wrapped
        if (wrap_count == 0) {
            color = ST7735_CYAN;   // 1st page (0-199)
        } else if (wrap_count == 1) {
            color = ST7735_YELLOW; // 2nd page (200-399)
        } else {
            color = ST7735_MAGENTA; // 3rd page and beyond
        }
    }
    
    drawtext(x, y, single_char, color, ST7735_BLACK, 1);
}

void init_dice_string_input_screen(int sel, const char* str, int target) {
    int len = strlen(str);
    print_dice_string_counter(len, target);
    
    // Draw any existing characters (in case of returning from another screen)
    for(int i = 0; i < len; i++) {
        update_dice_string_char(i, str[i], false);
    }
    
    print_dice_string_keyboard(sel, len, target);
    grid_keyboard_dice_hash();
}


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

    text[len] = (char)('A' + letter_index);
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
            if (next_char >= 'A' && next_char <= 'Z') {
                valid_letters[next_char - 'A'] = true;
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

        strncpy(result, unique_match, result_size - 1);
        result[result_size - 1] = '\0';
        return result;
}

void draw_qr_code(const char *text) {
    // Generate standard QR (no Micro QR)
    size_t length = strlen(text);
    // QR buffer for version 3 (29x29)
    uint8_t qrcodeData[qrcode_getBufferSize(3)];
    QRCode qrcode;

    // Initialize the QR code with ECC_LOW correction.
    if (length>39){
        qrcode_initText(&qrcode, qrcodeData, 3, ECC_LOW, text);
    }else{
        qrcode_initText(&qrcode, qrcodeData, 2, ECC_LOW, text);
    }
    int qr_size = qrcode.size;
    int img_size = qr_size * QR_SCALE;
    // Center on screen
    int x_offset = (SCREEN_WIDTH - img_size) / 2;
    int y_offset = (SCREEN_HEIGHT - img_size) / 2;

    for (int y = 0; y < qr_size; y++) {
        for (int x = 0; x < qr_size; x++) {
            int pixel = qrcode_getModule(&qrcode, x, y) ? 1 : 0;
            fillRect(x_offset + x * QR_SCALE, y_offset + y * QR_SCALE, QR_SCALE, QR_SCALE, pixel ? ST7735_BLACK : ST7735_WHITE);
        }
    }
}

void draw_compactqr_code(int size, unsigned char *data){

    uint8_t qrcodeData[qrcode_getBufferSize(3)];
    QRCode qrcode;

    // Initialize the QR code with ECC_LOW correction.
    if (size==16){
       qrcode_initBytes(&qrcode, qrcodeData, 1, ECC_LOW, data, size);
    }else{
       qrcode_initBytes(&qrcode, qrcodeData, 2, ECC_LOW, data, size);
    }



    int qr_size = qrcode.size;
    int img_size = qr_size * QR_SCALE;
    // Center on screen
    int x_offset = (SCREEN_WIDTH - img_size) / 2;
    int y_offset = (SCREEN_HEIGHT - img_size) / 2;

    for (int y = 0; y < qr_size; y++) {
        for (int x = 0; x < qr_size; x++) {
            int pixel = qrcode_getModule(&qrcode, x, y) ? 1 : 0;
            fillRect(x_offset + x * QR_SCALE, y_offset + y * QR_SCALE, QR_SCALE, QR_SCALE, pixel ? ST7735_BLACK : ST7735_WHITE);
        }
    }

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


void black_screen(){
    rectan(0,0,159,127,BLACK);
}
void white_screen(){
    rectan(0,0,159,127,WHITE);
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
    free(c_buf); 
    

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

void show_word_list_retry_error(void) {
    black_screen();
    drawtext(10,10, INCORRECT_MSG, ST7735_RED, ST7735_BLACK, 1);
    drawtext(10,25, "PRESS ANY BUTTON", ST7735_WHITE, ST7735_BLACK, 1);
}

void clear_write_word_current_display() {
    rectan(60,10,159,18,BLACK);
}

void clear_write_word_previous_display() {
    rectan(45,80,159,88,BLACK);
}

// ============================================================================
// Shared Keyboard Selection Updater
// ============================================================================
void update_keyboard_selection(int *lt_idx, int step, const char *word, bool found_bool, int word_number, char *word_number_text) {
    *lt_idx = get_next_valid_key(*lt_idx, step, word, found_bool);
    print_word_number_top(word_number, word_number_text);
    print_keyboard_with_validation(*lt_idx, found_bool, word);
}


void print_keyboard(int index, bool word_found, bool *valid_letters){

    char letra;
    char letter_text[2];
    int print_index_x=10;
    int print_index_y=30;
    int current_index = 0;
    uint16_t color;

    for (letra = 'A'; letra <= 'Z'; letra++) {
        letter_text[0] = letra;
        letter_text[1] = '\0';
        
        if (current_index == index) {
            color = ST7735_ORANGE;
        } else if (valid_letters[current_index]) {
            color = ST7735_WHITE;
        } else {
            color = ST7735_GREY;
        }
        
        drawtext(print_index_x,print_index_y, letter_text, color, ST7735_BLACK, 1);
        if (print_index_x > (cEND_OF_LINE - 30)){
            print_index_x = 10;
            print_index_y = print_index_y +15;
        } else {
            print_index_x = print_index_x+15;
        }
        current_index++;
    }
    if (word_found){
        color = (current_index == index) ? ST7735_ORANGE : ST7735_GREEN;
        drawtext(print_index_x,print_index_y, OK_MSG, color, ST7735_BLACK, 1);
    } else {
        color = (current_index == index) ? ST7735_ORANGE : ST7735_GREY;
        drawtext(print_index_x,print_index_y, OK_MSG, color, ST7735_BLACK, 1);
    }


    grid_keyboard();
}

void print_keyboard_with_validation(int index, bool word_found, const char *current_word) {
    bool valid_letters[26];
    get_valid_next_letters(current_word, valid_letters);
    print_keyboard(index, word_found, valid_letters);
}


void update_dice_bit_count_display(int bit_count_dice_local){
    char bit_count_text[4]; // 3 digits plus null terminator
    u16_to_str_pad((unsigned int)bit_count_dice_local, bit_count_text, 3);
    drawtext(45,15, bit_count_text, ST7735_WHITE, ST7735_BLACK, 1);
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



 void   print_logo(){
    drawtext(10,10, "SEEDMATE", ST7735_WHITE, ST7735_BLACK, 3);
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

    drawtext(135,80, "SEED", ST7735_ORANGE, ST7735_BLACK, 1);
    drawtext(145,90, "QR", ST7735_ORANGE, ST7735_BLACK, 1);

    print_rigth_arrow(150,105);
    drawtext(90,117, "QR COMPACT", ST7735_ORANGE, ST7735_BLACK, 1);
    print_rigth_arrow(150,123);

    drawtext(7,117, "SAVE TO SD", ST7735_ORANGE, ST7735_BLACK, 1);
    print_left_arrow(0,123);
    if ((main_pointer==cMAIN_SSS) & (sss_pointer==cSPLIT)){
        char shareid_text[4];
        u16_to_str((unsigned int)selected_share_id, shareid_text);
        drawtext(145,30, "ID", ST7735_CYAN, ST7735_BLACK, 1);
        drawtext(146,40, shareid_text, ST7735_CYAN, ST7735_BLACK, 2);
        if (selected_share_id>1)print_up_arrow(72,123);
        if (selected_share_id<cN_MAX)print_down_arrow(80,123);
    }
    if (main_pointer == cMAIN_create && seed_pointer == cSEED_triple) {
         if (triple_view_state > 0) print_up_arrow(72,123);
         if (triple_view_state < 2) print_down_arrow(80,123);
    }
}


void draw_QRSEED(const unsigned char *data, size_t size) {
    int bit_index = 0;              // Bits accumulated in 'group'
    int word_index = 0;             // Rendered word counter
    unsigned int group = 0;         // Accumulated 11-bit value (0..2047)
    const int bits_total = (int)(size * 8);

    // Output buffer: 4 digits per word plus the NUL terminator.
    char text_buf[98];
    size_t text_len = 0;

    text_buf[0] = '\0';

    for (int i = 0; i < bits_total; i++) {
        // Read the current bit (MSB first within each byte).
        int byte_index = i / 8;
        int bit_position = 7 - (i % 8);
        int bit = (data[byte_index] >> bit_position) & 1;

        // Add the current bit to the 11-bit group.
        group = (group << 1) | (unsigned int)bit;
        bit_index++;

        // Convert every 11-bit group into a decimal chunk.
        if (bit_index == 11) {

            char num_str[6]; // "dddd" + '\0' (+1 extra for safety)

            unsigned int idx = (group & 0x7FFu);

            int written = (int)u16_to_str_pad(idx, num_str, 4);

            // Append the decimal chunk when there is enough room.
            if (written > 0) {

                const int add_space = 0;
                size_t need = (size_t)written + add_space;
                if (text_len + need + 1 /*NUL*/ < sizeof(text_buf)) {
                    memcpy(&text_buf[text_len], num_str, (size_t)written);
                    text_len += (size_t)written;
                    if (add_space) {
                        text_buf[text_len++] = ' ';
                    }
                    text_buf[text_len] = '\0';
                } else {
                    text_buf[text_len] = '\0';
                    break;
                }
            }

            // Reset accumulators for the next group.
            group = 0;
            bit_index = 0;
            word_index++;
        }

    }

    draw_qr_code(text_buf);
    print_camera(2,50,cNOTSAFE);
    print_camera(2,80,cNOTSAFE);
    print_camera(145,50,cNOTSAFE);
    print_camera(145,80,cNOTSAFE);
    print_left_arrow_black(5,123);
}



void print_word_number_top(int word_number, char *word_number_text) {
    char suffix;

    // Choose the suffix from the current XOR input slot.
    switch (xor_merge_words_available) {
        case 0: suffix = 'A'; break;
        case 1: suffix = 'B'; break;
        case 2: suffix = 'C'; break;
        case 3: suffix = 'D'; break;
        default: suffix = '?'; break; // Out-of-range value
    }

    // Build the final label.
    if (main_pointer==cMAIN_XOR) {// XOR mode, indicates A, B, C or D
        size_t len = u16_to_str((unsigned int)word_number, word_number_text);
        word_number_text[len] = suffix;
        word_number_text[len + 1] = '\0';
    } else {
        u16_to_str((unsigned int)word_number, word_number_text);
    }

    rectan(40,10,59,18,BLACK);
    drawtext(40,10, word_number_text, ST7735_WHITE, ST7735_BLACK, 1);
}

void print_previous_confirmed_word(int current_word_number, char *word_number_text) {
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



void print_selkn_screen(int k, int n, int sel){
    char k_text[3];
    char n_text[3];
    drawtext(10,15, "Select ( k , n ):", ST7735_WHITE, ST7735_BLACK, 1);
    u16_to_str((unsigned int)k, k_text);
    u16_to_str((unsigned int)n, n_text);
    int color_k = (sel==0) ? ST7735_ORANGE : ST7735_WHITE;
    int color_n = (sel==1) ? ST7735_ORANGE : ST7735_WHITE;
    drawtext(60,30, k_text, color_k, ST7735_BLACK, 2);
    drawtext(85,30, n_text, color_n, ST7735_BLACK, 2);
    grid_nbits_LR();

}


void print_selk_screen(int k){
    char k_text[3];
    drawtext(0,15, "N. of shares needed (k):", ST7735_WHITE, ST7735_BLACK, 1);
    u16_to_str((unsigned int)k, k_text);
    drawtext(70,30, k_text, ST7735_ORANGE, ST7735_BLACK, 2);
    grid_nbits();

}

void print_sel_share_screen(int k){
    char k_text[3];
    drawtext(0,15, "Share id:", ST7735_WHITE, ST7735_BLACK, 1);
    u16_to_str((unsigned int)k, k_text);
    drawtext(70,30, k_text, ST7735_ORANGE, ST7735_BLACK, 2);
    grid_nbits_noback();

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
    uint8_t data = 0;

    for (int i = 0; i < 8; i++) {
        SD_SCK = 1; // SCK HIGH
        data <<= 1;
        if (SD_MISO) data |= 1; // MISO
        SD_SCK = 0; // SCK LOW
    }

    return data;
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

    // Read 512 bytes
    for (int i = 0; i < 512; i++) buffer[i] = spi_recv();

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


void print_slots(int sel){

    for (int i = 0; i < cSDBLOCK_n_opt; i++) {
        // Compute the slot number for the current page.
        unsigned int slot_num = (unsigned int)(i + 1 + SD_page * cSDBLOCK_n_opt);
        // Build the label without sprintf.
        char line[16];              // Short temporary buffer
        line[0] = 'S'; line[1] = 'L'; line[2] = 'O'; line[3] = 'T';
        u16_to_str(slot_num, &line[4]);

        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(3, 20 + i * 10, line, color, ST7735_BLACK, 1);

    }
}

void print_SD_preview(){

    BYTE checksum_SD_aux =0;
    BYTE size_pointer_aux=0;
    sd_init();
    for (int i = 0; i < cSDBLOCK_n_opt; i++) {

        // Display information about the slot.

        if (sd_read_block(i+SD_page*cSDBLOCK_n_opt, buffer)) {
            checksum_SD_aux = 1; // Reset checksum and account for the checksum byte

            for (int i = 0; i < 32; i++){
                checksum_SD_aux += buffer[i]; // Recompute checksum
            }
            // Validate checksum.
            if (checksum_SD_aux==buffer[cSD_CHECKSUM_ADDR]){
                size_pointer_aux=buffer[cSD_SIZE_ADDR];
                        if (size_pointer_aux==cSIZE_12){// 12 words
                            drawtext(48, 20 + 10*i, "12W", ST7735_CYAN, ST7735_BLACK, 1);
                        }   else {
                            drawtext(48, 20 + 10*i, "24W", ST7735_CYAN, ST7735_BLACK, 1);
                        }
            }   else {
                drawtext(48, 20 + 10*i, "   ", ST7735_CYAN, ST7735_BLACK, 1);
            }
        } else {
            break;
        }
    }
}

void sel_sd_block_screen_generic(int sel) {
    drawtext(1, 10 , "SELECT SLOT", ST7735_WHITE, ST7735_BLACK, 1);
    switch (main_pointer) {
        case cMAIN_XOR:
        {
            char xor_lbl[] = " FOR XOR A";
            xor_lbl[9] = 'A' + xor_merge_words_available;
            drawtext(67, 10 , xor_lbl, ST7735_WHITE, ST7735_BLACK, 1);
            break;
        }
        case cMAIN_ERASESD:
            drawtext(67, 10 , " TO ERASE", ST7735_WHITE, ST7735_BLACK, 1);
            break;
        default:
            drawtext(67, 10 , " TO READ", ST7735_WHITE, ST7735_BLACK, 1);
            break;
    }
    print_slots(sel);

    print_SD_preview();
    grid_menuSD();
}


void sel_sd_block_screen_wr(int sel) {

    drawtext(1, 10 , "SELECT SLOT TO WRITE", ST7735_WHITE, ST7735_BLACK, 1);
    // Paint 8 lines "SLOT <num>"
    print_slots(sel);
    print_SD_preview();
    grid_menuwr();
}


void sel_sd_block_screen_merge(int sel,int id) {

    char merge_text[25];
    memcpy(merge_text, "SELECT SLOT ID:", 15);
    u16_to_str((unsigned int)id, &merge_text[15]);
    drawtext(1, 10 , merge_text, ST7735_ORANGE, ST7735_BLACK, 1);
    print_slots(sel);
    print_SD_preview();
    grid_menu2_merge();
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


int main ( void ){
    /* Initialize all modules */
    SYS_Initialize ( NULL );
    R_LCD=1;
    LED_LCD =1;
    A0_LCD=0;
    LED = 0;
    SPI1CON= 0x10000120;
    SPI1CON= 0x10008120;
    SPI1BRG= 1;
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
    drawtext(10,119, "(Press any button)", ST7735_WHITE, ST7735_BLACK, 1);
    version_display();

    PULSED_BT_t pulsed_bt = NONE;

    // Initialize the SD card only once at startup.
    SD_ready = sd_init();
    tmr1_init();



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
                pulsed_bt = RIGTH_BT;
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
                    case RIGTH_BT:
                        transition_to_main();
                        break;
                    default:
                        break;
                }
                break;

            case MAIN:
                switch (pulsed_bt) {
                    case OK_BT:
                        if (main_pointer==cMAIN_create){// Create new seed
                            transition_to_create_seed();
                        } else if (main_pointer==cMAIN_LOAD ){// Load seed words
                            transition_to_input(selinput_pointer);
                        } else if (main_pointer == cMAIN_BIP85) { // BIP85 child seed
                            black_screen();
                            print_child_config_screen();
                            estado = CHILD_CONFIG;
                        } else if (main_pointer==cMAIN_XOR){// XOR
                            black_screen();
                            print_generic_menu(menu_xor, cXOR_n_opt, xor_pointer);
                            estado = SEL_XOR;
                        } else if (main_pointer==cMAIN_OBFUS){// Obfuscation
                            transition_to_obfus();
                        } else if (main_pointer==cMAIN_SSS){// Shamir
                            black_screen();
                            print_generic_menu(menu_sss, cSSS_n_opt, sss_pointer);
                            estado = SEL_SSS;
                        } else if (main_pointer==cMAIN_ERASESD){// Erase SD
                            transition_to_sd_block(SDblock_pointer);
                        } else if (main_pointer==cMAIN_QR){// Resources menu
                            black_screen();
                            print_generic_menu(menu_resource, cRESOURCE_n_opt, resource_pointer);
                            estado = RESOURCE_MENU;
                        }
                        break;
                    case BACK_BT:
                        break;
                    case UP_BT:
                        spi_send(0x33);
                        if (main_pointer > 0) {
                            main_pointer--;
                        }
                        main_screen_fast(main_pointer);
                        break;
                    case DOWN_BT:
                        spi_send(0x55);
                        if (main_pointer < (cMAIN_n_opt-1)) {
                            main_pointer++;
                        }
                        main_screen_fast(main_pointer);
                        break;

                    case LEFT_BT:
                        break;
                    case RIGTH_BT:
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
                    case RIGTH_BT:
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
                            draw_qr_code("youtu.be/8vy5LIxT1ls");
                        } else if (resource_pointer == cRESOURCE_backup) {
                            draw_qr_code("seedmate.github.io/Seedmate_HTML_backup/");
                        } else if (resource_pointer == cRESOURCE_dice_test) {
                            draw_qr_code("seedmate.github.io/Dice_tester/");
                        } else if (resource_pointer == cRESOURCE_wordlist) {
                            draw_qr_code("seedmate.net/Printable%20BIP39%20wordlist.pdf");
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
                    case RIGTH_BT:
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
                        if (obfuscation_pointer == cOBFUS_NOT) { // Negate seed words
                            transition_to_input(selinput_pointer);
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
                    case RIGTH_BT:
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
                    case RIGTH_BT:
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

                        } else if (main_pointer==cMAIN_LOAD || main_pointer==cMAIN_OBFUS || main_pointer==cMAIN_SSS || main_pointer==cMAIN_BIP85 ){// Check seed or obfuscate/SSS
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
                            int target = (size_pointer == cSIZE_12) ? 50 : 100;
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
                        } else if (main_pointer==cMAIN_XOR || main_pointer==cMAIN_LOAD || main_pointer==cMAIN_SSS || main_pointer==cMAIN_BIP85){
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
                    case RIGTH_BT:
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
                    case RIGTH_BT:
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
                                    }
                                }else if (main_pointer==cMAIN_BIP85) {
                                    drawtext(70, 20 + 10*SDblock_pointer, LOAD_OK, ST7735_GREEN, ST7735_BLACK, 1);
                                    black_screen();
                                    drawtext(30, 30, "COMPUTING CHILD", ST7735_WHITE, ST7735_BLACK, 1);
                                    drawtext(30, 45, "MNEMONIC...", ST7735_WHITE, ST7735_BLACK, 1);
                                    estado = PROCESS_BIP85;
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
                        if (main_pointer==cMAIN_OBFUS || main_pointer==cMAIN_XOR || main_pointer==cMAIN_LOAD || main_pointer==cMAIN_SSS || main_pointer==cMAIN_BIP85 || (main_pointer == cMAIN_create && seed_pointer == cSEED_triple)){
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
                    case RIGTH_BT:
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
                    case RIGTH_BT:
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
                    case RIGTH_BT:
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
                                drawtext(70, 20 + 10*SDblock_pointer,  "SHARE OK", ST7735_GREEN, ST7735_BLACK, 1);

                                if (shares_loaded >= (SSS_K)) { // We already have K shares
                                    black_screen();
                                    if (!shamir_interpolate(SSS_result,0,share_indices, shares_input,SSS_K,LEN)){
                                        drawtext(5,39, "(SSS Error, repeated id?)", ST7735_RED, ST7735_BLACK, 1);
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
                    case RIGTH_BT:
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
                            }else{// cMAIN_OBFUS or cMAIN_LOAD or cMAIN_BIP85
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
                    case RIGTH_BT:
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
                    case RIGTH_BT:
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
                    case RIGTH_BT:
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
                    case RIGTH_BT:
                        break;
                    default:
                        break;
                }
                break;

           case SEL_SHARE:
                switch (pulsed_bt) {
                    case OK_BT:
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
                    case RIGTH_BT:
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
                    case RIGTH_BT:
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
                    case RIGTH_BT:
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
                        int target = (size_pointer == cSIZE_12) ? 50 : 100;
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
                        int target = (size_pointer == cSIZE_12) ? 50 : 100;
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
                        int target = (size_pointer == cSIZE_12) ? 50 : 100;
                        int len = strlen(dice_string_buf);
                        if (dice_input_idx > 0) {
                            dice_input_idx--;
                        } else {
                            dice_input_idx = (len >= target) ? 6 : 5;
                        }
                        print_dice_string_keyboard(dice_input_idx, len, target);
                        break;
                    }
                    case RIGTH_BT: {
                        int target = (size_pointer == cSIZE_12) ? 50 : 100;
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
                    case RIGTH_BT:
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
                                        }
                                    } else if ((main_pointer==cMAIN_SSS) & (sss_pointer==cSPLIT)){
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
                        if ((strlen(word) == 0) & (word_number > 1)) { // Go back one word
                            const char *saved_word;
                            word_number-=1;
                            clear_string(word);
                            saved_word = get_confirmed_word_from_entropy(data_array_256b, word_number);
                            if (saved_word != NULL) {
                                strncpy(word, saved_word, 31);
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
                    case RIGTH_BT:
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
                    case RIGTH_BT:
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
                    case RIGTH_BT:
                        break;
                    default:
                        break;
                }
                break;
            case SHOW_SEED:
                switch (pulsed_bt) {
                    case OK_BT:
                        white_screen();
                        {
                            BYTE *qr_buf = append_checksum(data_array_256b, 16 + size_pointer*16);
                            draw_QRSEED(qr_buf, 16 + size_pointer*16 +1);
                            free(qr_buf);
                        }
                        estado = SHOW_QRSEED;
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
                    case RIGTH_BT: // Compact QR
                        white_screen();
                        draw_compactqr_code(16 + size_pointer*16, data_array_256b);
                        print_camera(2,50,cNOTSAFE);
                        print_camera(2,80,cNOTSAFE);
                        print_camera(145,50,cNOTSAFE);
                        print_camera(145,80,cNOTSAFE);
                        print_left_arrow_black(5,123);
                        estado = SHOW_QRSEED;

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
                        redraw_show_seed_with_offset();
                        break;
                    case UP_BT:
                    case DOWN_BT:
                        break;
                    case LEFT_BT:
                        redraw_show_seed_with_offset();
                        break;
                    case RIGTH_BT:
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