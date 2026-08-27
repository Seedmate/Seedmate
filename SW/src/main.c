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
 * Date:        18/8/2026
 * Version:     v1.4                               
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
#include "SHA256.h"
#include "words_opt.h"
#include <string.h>
#include "SSS/shamir.h"
#include "QRCode-master/src/qrcode.h"
#define QR_SCALE 4 // Size of each module in pixels
#define SCREEN_WIDTH 160
#define SCREEN_HEIGHT 128


#define cVersion "v1.4"

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



#define cMAIN_n_opt 7
#define cSEED_n_opt 6
#define cSIZE_n_opt 2
#define cOBFUS_n_opt 3
#define cXOR_n_opt 3
#define cSHIFT_n_opt 2
#define cSSS_n_opt 2
#define cQR_n_opt 2
#define cSDBLOCK_n_opt 8
#define cSELINPUT_n_opt 2
#define cDICE_MODE_n_opt 2
#define cHASH_MODE_n_opt 2
#define cEND_OF_LINE 150
#define cENTROPY_BITS12W 127//127
#define cENTROPY_BITS24W 255//255
#define cCARD_MAX_HISTORY 128


#define cMAIN_create 0
#define cMAIN_LOAD 1
#define cMAIN_SSS 2
#define cMAIN_XOR 3
#define cMAIN_OBFUS 4
#define cMAIN_ERASESD 5
#define cMAIN_QR 6 // tutorial

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
#define  cK_MAX 6 //max 6th order polinomial
#define  cN_MAX 9//max 9 samples

#define INCORRECT_MSG "INCORRECT SET OF WORDS"
#define OK_MSG "OK"

int main_pointer = 0;
int obfuscation_pointer =0;
int sss_pointer = 0;
uint8_t  selected_share_id = 1;
int shares_loaded = 0;

int extract_word_offset = 0;
int triple_view_state = 0;
BYTE triple_backup_256b[36] = {0};

int dice_x_pointer = 0;
int dice_y_pointer = 25;

int dice_mode_pointer = 0;
int hash_mode_pointer = 0;

#define char_hash_limit 301
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

void draw_hex16(unsigned int x, unsigned int y, uint16_t numero, int N, unsigned int color, unsigned int bg, unsigned int size) {
    char hex_text[5]; // 4 hex digits plus null terminator

    for (int i = 0; i < N; i++) {
        u16_to_hex4(numero, hex_text); // Convert the value to hexadecimal text
        drawtext(x + i * (12 * size), y, hex_text, color, bg, size); // Adjust spacing for the current size
    }
}

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
    CREATE_SEED,
    SEL_SIZE,
    SEL_XOR,
    SEL_OBFUS,
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
    WORD_LIST_ERROR,
    END_MODE,//final
    SEL_SHIFT,
    SEL_NBITS_SHIFT,
    SEL_ADD_SUB,
    SEL_SHARE,
    TMR_INPUT,
    CARD_INPUT,
    PROCESS_TRIPLE,
    SHOW_TRIPLE_CHKSUM_12,
    SHOW_TRIPLE_CHKSUM_24,
    SEL_DICE_MODE,
    SEL_HASH_MODE,
    DICE_STRING_INPUT
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


void print_cursor_grid(){
    drawFastHLine(60,105,90,WHITE);
    drawFastHLine(60,115,90,WHITE);
    drawFastHLine(60,125,90,WHITE);
    drawFastVLine(60,105,20,WHITE);
    drawFastVLine(90,105,20,WHITE);
    drawFastVLine(120,105,20,WHITE);
    drawFastVLine(150,105,20,WHITE);
}

void print_up_arrow(int x,int y){
    drawFastVLine(x+2,y-6,6,WHITE);
    drawFastHLine(x+1,y-5,3,WHITE);
    drawFastHLine(x,y-4,5,WHITE);

}

void print_add_symbol(int x,int y){
    drawFastVLine(x+3,y-7,7,WHITE);
    drawFastHLine(x,y-4,7,WHITE);
}

void print_down_arrow(int x,int y){
    drawFastVLine(x+2,y-6,6,WHITE);
    drawFastHLine(x+1,y-2,3,WHITE);
    drawFastHLine(x,y-3,5,WHITE);

}

void print_minus_symbol(int x,int y){
    drawFastHLine(x,y-3,7,WHITE);
}

void print_left_arrow(int x,int y){
    drawFastHLine(x,y-3,6,WHITE);
    drawFastVLine(x+1,y-4,3,WHITE);
    drawFastVLine(x+2,y-5,5,WHITE);

}

void print_left_arrow_black(int x,int y){
    drawFastHLine(x,y-3,6,BLACK);
    drawFastVLine(x+1,y-4,3,BLACK);
    drawFastVLine(x+2,y-5,5,BLACK);

}

void print_rigth_arrow(int x,int y){
    drawFastHLine(x,y-3,6,WHITE);
    drawFastVLine(x+4,y-4,3,WHITE);
    drawFastVLine(x+3,y-5,5,WHITE);

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

void grid_coins(){              // heads tails
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
void main_screen(int sel) {
    char* opciones[] = {
        "CREATE NEW SEED WORDS",
        "LOAD SEED WORDS",
        "SHAMIR SECRET SHARE",
        "SEED WORD XOR",
        "OBFUSCATION",
        "ERASE SD",
        "VIEW TUTORIAL"
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
        "SHAMIR SECRET SHARE",
        "SEED WORD XOR",
        "OBFUSCATION",
        "ERASE SD",
        "VIEW TUTORIAL"
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
    
    //rectan(0, 35, 159, 43, BLACK); 
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

void sel_input_screen(int sel) {
    char* options[] = {
        "FROM KEYBOARD",
        "FROM SD"
    };

    for (int i = 0; i < cSELINPUT_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 10 + i * 10, options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
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




void create_seed_screen(int sel){
    char* options[] = {
        "THROW COINS",
        "ROLL DICE",
        "RANDOM WORD PICK",
        "DRAW CARDS",
        "STOPWATCH TEST ONLY",
        "TRIPLE MNEMONIC"
    };
    for (int i = 0; i < cSEED_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 10 + i * 10, options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
}

void sel_dice_mode_screen(int sel){
    char* options[] = {
        "RAW ENTROPY BITS",
        "STRING HASH"
    };
    for (int i = 0; i < cDICE_MODE_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 10 + i * 10, options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
}

void sel_hash_mode_screen(int sel){
    char* options[] = {
        "1-6 mode",
        "0-5 mode (Keystone)"
    };
    for (int i = 0; i < cHASH_MODE_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 10 + i * 10, options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
}

// update only roll count
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

// Update only number sel
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
        done_color = ST7735_ORANGE; //selected
    } else if (current_len >= target) {
        done_color = ST7735_GREEN;  // enough rolls, can be selected
    } else {
        done_color = ST7735_GREY;   // not enough rolls yet
    }
    
   
    drawtext(130, 90, "DONE", done_color, ST7735_BLACK, 1);
}

//only updated the modified char to speed up
void update_dice_string_char(int index, char c, bool is_delete) {
    int chars_per_line = 25;
    int line = index / chars_per_line;
    int col = index % chars_per_line;
    
    // 1 letter = 5 pixels
    int x = 5 + (col * 6); 
    int y = 20 + (line * 10);
    
    char single_char[2] = { is_delete ? ' ' : c, '\0' };
    
    // When deleting, write black on top
    drawtext(x, y, single_char, ST7735_CYAN, ST7735_BLACK, 1);
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


void sel_obfus_screen(int sel){
    char* options[] = {
        "CIRCULAR SHIFT",
        "NOT OPERATOR",
        "WORDS ADD/SUB"
    };
    for (int i = 0; i < cOBFUS_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 10 + i * 10, options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
}

void print_selsize_screen(int sel){
    char* options[] = {
        "12 WORDS",
        "24 WORDS"
    };
    for (int i = 0; i < cSIZE_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 10 + i * 10, options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
}

void print_selQR_screen (int sel){
    char* options[] = {
        "STANDARD",
        "COMPACT"
    };
    for (int i = 0; i < cQR_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 10 + i * 10, options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
}

void print_xorsel_screen(int sel){
    char* options[] = {
        "A XOR B = C",// 2-xor
        "A XOR B XOR C = D",// 3-xor
        "A XOR B XOR C XOR D = E"    // 4-xor
    };
    for (int i = 0; i < cXOR_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 10 + i * 10, options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
}

void sel_shift_screen(int sel){
    char* options[] = {
        "CIRCULAR LEFT SHIFT",
        "CIRCULAR RIGHT SHIFT"

    };
    for (int i = 0; i < cSHIFT_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 10 + i * 10, options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
}



void sel_add_screen(int sel){
    char* options[] = {
        "ADD",
        "SUBSTRACT"
    };
    for (int i = 0; i < cSHIFT_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 10 + i * 10, options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
}

void sel_SSS_screen(int sel){
    char* options[] = {
        "SPLIT",
        "MERGE"
    };
    for (int i = 0; i < cSSS_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 10 + i * 10, options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
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
            
            // --- NEW: EXACT MATCH CHECK ---
            // If the next character in the dictionary is null, the length is identical
            if (ptr[prefix_len] == '\0') {
                unique_match = ptr;
                match_count = 1;
                break; // Exact match, stop searching
            }
            // --------------------------------------------------

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
    if (length>50){
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
    free(c_buf); // Fixed implicit memory leak
    

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


void print_keyboard(int index, bool word_found, bool *valid_letters){

    char letra;
    char letter_text[2];
    int print_index_x=10;
    int print_index_y=30;
    int current_index = 0;
    uint16_t color;
    //drawtext(65,10, "____", ST7735_WHITE, ST7735_BLACK, 1);

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
        //index out of range
        return;
    }

    int byte_index = bit_index / 8;
    int bit_position = 7 - (bit_index % 8); // MSB a LSB

    if (value == 1) {
        data_array[byte_index] |= (1 << bit_position);
    } else {
        data_array[byte_index] &= ~(1 << bit_position);
    }
}



 void   print_logo(){
    drawtext(10,10, "SEEDMATE", ST7735_WHITE, ST7735_BLACK, 3);
 }
 void print_camera(int x,int y, int safe){
    int color = (safe == cSAFE) ? ST7735_GREEN : ST7735_RED;
    drawFastHLine(x,y,13,color);//base
    drawFastHLine(x,y-8,4,color);//top left
    drawFastHLine(x+9,y-8,4,color);//top right
    drawFastHLine(x+5,y-10,3,color);//top center
    drawFastHLine(x+5,y-7,3,color);//top lens
    drawFastHLine(x+5,y-2,3,color);//bottom lens
    drawFastVLine(x,y-7,7,color);//left
    drawFastVLine(x+12,y-7,7,color);//right
    drawFastVLine(x+3,y-5,2,color);//lens left
    drawFastVLine(x+9,y-5,2,color);//lens right
    drawFastVLine(x+4,y-3,1,color);//stray pixel
    drawFastVLine(x+8,y-3,1,color);//stray pixel
    drawFastVLine(x+4,y-6,1,color);//stray pixel
    drawFastVLine(x+8,y-6,1,color);//stray pixel
    drawFastVLine(x+4,y-9,1,color);//stray pixel
    drawFastVLine(x+8,y-9,1,color);//stray pixel

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
            //sprintf(texto, "%02d", word_index);
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
            //delay_ms(500);
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
    //const int total_words = bits_total / 11;

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

    //drawtext(45,15, text_buf, ST7735_BLACK, ST7735_WHITE , 1);

    draw_qr_code(text_buf);
    //draw_compactqr_code(size, data);
    print_camera(2,50,cNOTSAFE);
    print_camera(2,80,cNOTSAFE);
    print_camera(145,50,cNOTSAFE);
    print_camera(145,80,cNOTSAFE);
    print_left_arrow_black(5,123);
}



void print_word_number_top(int word_number, int xor_merge_words_available, int main_pointer, char *word_number_text) {
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
    if (main_pointer==cMAIN_XOR) {//xor mode, indicates A, B, C or D
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
    BYTE *checksum_buffer = (BYTE*)malloc((size_t)N + 1u);

    if (!checksum_buffer) {
        return NULL;
    }

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
    free(checksum_buffer);
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

    // --- DEAD CODE REMOVED: No more ST7735_RED "nada" checking ---
    if (found != NULL) {
        clear_write_word_current_display();
        drawtext(60, 10, result, ST7735_GREEN, ST7735_BLACK, 1);
        drawtext(130, 60, OK_MSG, ST7735_GREEN, ST7735_BLACK, 1);
        *found_bool = true;
    }

    return found;
}

void print_nbits_screen(int shift_nbits){
    char shift_nbits_text[6];
    drawtext(70,30, "    ", ST7735_BLACK, ST7735_BLACK, 2);
    u16_to_str((unsigned int)shift_nbits, shift_nbits_text);
    if (main_pointer==cMAIN_OBFUS && obfuscation_pointer==cOBFUS_SHIFT){
        drawtext(10,15, "NUMBER OF BITS TO SHIFT:", ST7735_WHITE, ST7735_BLACK, 1);
    } else {
       drawtext(10,15, "ADD/SUB TO EACH WORD:", ST7735_WHITE, ST7735_BLACK, 1);
    }
    drawtext(70,30, shift_nbits_text, ST7735_ORANGE, ST7735_BLACK, 2);
    grid_nbits();

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
    //drawtext(10, 10, "(CMD0)", ST7735_WHITE, ST7735_BLACK, 1);
    uint8_t r1 = sd_get_response();               // Read R1
    SD_CS = 1; spi_send(0xFF);                    // Release + extra clocks
    if (r1 != 0x01) {                             // Card must be in IDLE
        //drawtext(10, 20, "CMD0 failed", ST7735_RED, ST7735_BLACK, 1);
        return false;
    }

    // ---- CMD8: SEND_IF_COND ----
    SD_CS = 0;
    sd_send_cmd(8, 0x000001AA, 0x87);             // Check 2.7-3.6V range + echo 0xAA
    //drawtext(10, 30, "(CMD8)", ST7735_WHITE, ST7735_BLACK, 1);
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
            //drawtext(10, 40, "CMD8 OK", ST7735_GREEN, ST7735_BLACK, 1);
        } else {
            //drawtext(10, 40, "CMD8 FAIL", ST7735_RED, ST7735_BLACK, 1);
            return false;
        }
    }


    bool v2_card = (r1 == 0x01);                  // v2 cards usually answer with 0x01
    // If r1 == 0x05 (illegal command), it is likely an SD v1 card.

    // ---- Loop: CMD55 + ACMD41 ----
    // Request HCS=1 for SDHC/SDXC-capable cards.
    uint32_t tries = 10000;
    do {
        // CMD55
        SD_CS = 0;
        sd_send_cmd(55, 0x00000000, 0x65);
        //drawtext(10, 40, "(CMD55)", ST7735_WHITE, ST7735_BLACK, 1);
        r1 = sd_get_response();
        SD_CS = 1; spi_send(0xFF);
        // r1 can be 0x01 if still idle, 0x00 if ready, or 0xFF on timeout.

        // ACMD41 (argument carries HCS when the card is v2)
        SD_CS = 0;
        uint32_t arg = v2_card ? 0x40000000 : 0x00000000; // HCS bit31
        sd_send_cmd(41, arg, 0x77);
        //drawtext(10, 50, "(ACMD41)", ST7735_WHITE, ST7735_BLACK, 1);
        r1 = sd_get_response();
        SD_CS = 1; spi_send(0xFF);

        if (r1 == 0x00) break; // Ready: leaves idle state
    } while (--tries);

    if (r1 != 0x00) {
        //drawtext(10, 60, "ACMD41 timeout", ST7735_RED, ST7735_BLACK, 1);
        return false;
    }

    // ---- CMD58: READ_OCR ----
    SD_CS = 0;
    sd_send_cmd(58, 0x00000000, 0xFD);
    //drawtext(10, 70, "(CMD58)", ST7735_WHITE, ST7735_BLACK, 1);
    r1 = sd_get_response();
    uint8_t ocr[4] = {0};
    ocr[0] = spi_recv(); // MSB
    ocr[1] = spi_recv();
    ocr[2] = spi_recv();
    ocr[3] = spi_recv(); // LSB
    SD_CS = 1; spi_send(0xFF);

    if (r1 != 0x00) {
        //drawtext(10, 80, "CMD58 failed", ST7735_RED, ST7735_BLACK, 1);
        return false;
    }

    // Bit CCS (Card Capacity Status) en OCR MSB bit6
    sd_is_sdhc = (ocr[0] & 0x40) != 0;
    if (sd_is_sdhc) {
        //drawtext(10, 90, "SDHC/SDXC", ST7735_GREEN, ST7735_BLACK, 1);
    } else {
        //drawtext(10, 90, "SDSC", ST7735_CYAN, ST7735_BLACK, 1);
    }

    // ---- CMD16: SET_BLOCKLEN (solo SDSC; SDHC ignora, siempre 512) ----
    if (!sd_is_sdhc) {
        SD_CS = 0;
        sd_send_cmd(16, 512, 0x15);
        //drawtext(10, 100, "(CMD16)", ST7735_WHITE, ST7735_BLACK, 1);
        r1 = sd_get_response();
        SD_CS = 1; spi_send(0xFF);
        if (r1 != 0x00) {
            //drawtext(10, 110, "CMD16 failed", ST7735_RED, ST7735_BLACK, 1);
            return false;
        }
    }

    //drawtext(10, 120, "SD Ready", ST7735_GREEN, ST7735_BLACK, 1);
    return true;
}


// Read R1 response of SD command (first byte different from 0xFF)
// Returns 0xFF if there is a timeout
uint8_t sd_get_r1(void) {
    uint8_t r;
    uint32_t timeout = 20000; // wide margin for bit banging
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


// Para SDHC, el 'sector' va como argumento directo.
// Para SDSC, el argumento es byte address = sector * 512.
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

// for the SD
uint8_t buffer[512];


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
                //drawtext(60, 20 + 10*SDblock_pointer, "LOAD OK", ST7735_GREEN, ST7735_BLACK, 1);
                size_pointer_aux=buffer[cSD_SIZE_ADDR];
                        if (size_pointer_aux==cSIZE_12){// 12 words
                            drawtext(48, 20 + 10*i, "12W", ST7735_CYAN, ST7735_BLACK, 1);
                        }   else {
                            drawtext(48, 20 + 10*i, "24W", ST7735_CYAN, ST7735_BLACK, 1);
                        }
            }   else {
                drawtext(48, 20 + 10*i, "   ", ST7735_CYAN, ST7735_BLACK, 1);
            }


            //draw_hex16(45, 20 + i * 10, (uint16_t)XOR_SD_aux, 1, ST7735_WHITE, ST7735_BLACK, 1);
            //drawtext(25, 20 + i * 10, XOR_SD_aux, ST7735_WHITE, ST7735_BLACK, 1);
        } else {
            //drawtext(50, 20 + 10*i, "SD error", ST7735_RED, ST7735_BLACK, 1);
            break;
        }
    }
}

void sel_sd_block_screen_generic(int sel) {
    drawtext(1, 10 , "SELECT SLOT", ST7735_WHITE, ST7735_BLACK, 1);
    switch (main_pointer) {
        case cMAIN_XOR:
            drawtext(67, 10 , "S FOR XOR", ST7735_WHITE, ST7735_BLACK, 1);
            break;
        case cMAIN_ERASESD:
            drawtext(67, 10 , " TO ERASE", ST7735_WHITE, ST7735_BLACK, 1);
            break;
        default:
            drawtext(67, 10 , " TO READ", ST7735_WHITE, ST7735_BLACK, 1);
            break;
    }
    //if (last_sel_sd != -1 && last_sel_sd != sel) {
    //    print_slots_fast(sel);
    //}else{
    //    print_slots(sel);
    //}
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


/* Evaluates y = S + a*x (GF(256)) for a bitsliced block. */
static void eval_affine_block(uint8_t *y_out,
                              const uint8_t *s_in,
                              const uint8_t *a_in,
                              size_t blk_len,
                              uint8_t x_val)
{
    uint32_t S[8], A[8], X[8], AX[8];

    bitslice(S, s_in, blk_len);
    bitslice(A, a_in, blk_len);
    bitslice_setall(X, x_val);      // Same x value for all lanes
    gf256_mul(AX, A, X);            // AX = A * X
    gf256_add(AX, S);               // AX ^= S  => Y = S + A*x
    unbitslice(y_out, AX, blk_len);
}

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

    // Optionally clear temporaries if they contain sensitive material
}


/* Generic split:
   - f(x) = c0 + c1*x + ... + cN*x^N  (N <= 6)
   - c0: secret buffer (len bytes)
   - coeffs: array of N pointers to buffers (c1..cN), each len bytes
   - x_vals: array de x's (non-zero, distinct from each other)
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
            // (Optional) validate x != 0 and uniqueness of x_vals[] elsewhere
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



/* Evaluates a share for any x value. */
void sss_eval_share(const uint8_t *secret, const uint8_t *a,
                    size_t len, uint8_t x,
                    uint8_t *share_out)
{
    size_t off = 0;
    while (off < len) {
        size_t blk = len - off;
        if (blk > BS_LANES) blk = BS_LANES;
        eval_affine_block(share_out + off, secret + off, a + off, blk, x);
        off += blk;
    }
}



void gen_a_nonzero(uint8_t *a, size_t len) {
    for (size_t i = 0; i < len; i++) {
        a[i] = 0x01;  // Non-zero constant (can use 0x01, 0xAA, etc.)
    }
}


/* Split (k-of-m) con polinomio grado N=k-1 <= 6
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
    if (m > 255) return false; // x son uint8

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
    T1CONbits.TCKPS = 0;       // Prescaler
    T1CONbits.SIDL = 0; // Do not stop in Idle
    PMD4bits.T1MD = 0;
    PR1 = 0xFFFF;
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


    //menu pointer handling
    int xor_pointer = 0;
    int shift_pointer = 0;
    int add_pointer = 0;


    int SSS_K = 2;
    //int SSS_N = 2;
    int SSS_N = 9;
    int sel_K_N = 0;
    int shift_nbits = 1;
    //int QR_pointer = 0;
    int SDblock_pointer = 0;
    int selinput_pointer = 0;

    uint16_t time_now ;
    //uint8_t  time_low ;

    //dice rolling variables



    BYTE checksum_SD =0;
    BYTE XOR_SD =0;
    //BYTE data_array_256b[32] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };

    BYTE xor_merge_word1[32] = {0};
    BYTE xor_merge_word2[32] = {0};
    BYTE xor_merge_word3[32] = {0};
    int xor_merge_words_available = 0;

    int lt_idx = 0; //letter index



    char* word = malloc(32 * sizeof(char));
    char result[32]; // Search result preview
    const char* found = NULL;
    bool found_bool = false;

    if (word != NULL) {
        word[0] = '\0';
    }

    int word_number = 1; // Tracks the word being entered
    char word_number_text[12];


    const size_t LEN = 32;


    //uint8_t secret[LEN], a[LEN];
    //uint8_t secret[LEN];
    uint8_t SSS_result[LEN];

    // f(x) = c0 + c1*x + c2*x^2



    const uint8_t *coeffs[cK_MAX-1] = { c0, c1, c2, c3, c4 }; // Maximum polynomial degree 6
    uint8_t sh1[LEN], sh2[LEN], sh3[LEN], sh4[LEN], sh5[LEN], sh6[LEN], sh7[LEN], sh8[LEN], sh9[LEN];
    uint8_t *shares[cN_MAX] = {sh1, sh2, sh3, sh4, sh5, sh6, sh7, sh8, sh9};

    // Buffers used while reconstructing shares.
    uint8_t *shares_input[cN_MAX] = {sh1, sh2, sh3, sh4, sh5, sh6, sh7, sh8, sh9};
    uint8_t share_indices[cK_MAX] = { 1, 2,0,0,0,0 };

    //int button_pressed = 0;
//    int aux2=0;
    while ( true )
    {
        /* Maintain state machines of all polled MPLAB Harmony modules. */
        SYS_Tasks ( );

        // button pressing logic
        if ((BT_OK ==0) & (BT_OK_ST==1)) {
            LED = 1;
            update_entropy_coefficients(); // Capture fresh coefficient bytes on each press
            delay_ms(30);
            LED = 0;
            if (BT_OK ==0) {
                BT_OK_ST=0;
                //button_pressed=3;
                pulsed_bt = OK_BT;
                //drawtext(aux_int,40, "X", ST7735_WHITE, ST7735_BLACK, 1);
                //aux_int = aux_int+5;
                }
         }  else if ((BT1 ==0) & (BT1_ST==1)) {
            LED = 1;
            update_entropy_coefficients();
            delay_ms(30);
            LED = 0;
            if (BT1 ==0) {
                BT1_ST=0;
                //button_pressed=1;
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
                //button_pressed=2;
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
            //draw_hex16(10, 10, TMR1, 1, ST7735_WHITE, ST7735_BLACK, 1);
//             ADC_test();
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
        // END button pressing logic


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
                        black_screen();
                        main_screen(0);
                        estado = MAIN;
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;

            case MAIN:
                switch (pulsed_bt) {
                    case OK_BT:
                        if (main_pointer==cMAIN_create){// create new seed
                            black_screen();
                            create_seed_screen(seed_pointer);
                            estado = CREATE_SEED;
                        } else if (main_pointer==cMAIN_LOAD ){// load seed words
                            black_screen();
                            sel_input_screen(selinput_pointer);
                            estado = SEL_INPUT;
                            //seed_pointer=2; //word pick
                        } else if (main_pointer==cMAIN_XOR){// XOR
                            black_screen();
                            print_xorsel_screen(xor_pointer);
                            estado = SEL_XOR;
                        } else if (main_pointer==cMAIN_OBFUS){// obfuscation
                            black_screen();
                            sel_obfus_screen(obfuscation_pointer);
                            estado = SEL_OBFUS;

                        } else if (main_pointer==cMAIN_SSS){// shamir
                            black_screen();
                            sel_SSS_screen(sss_pointer);
                            estado = SEL_SSS;
                        } else if (main_pointer==cMAIN_ERASESD){//ERASE SD
                            black_screen();
                            sel_sd_block_screen_generic(SDblock_pointer);
                            estado = SEL_SD_BLOCK;
                        } else if (main_pointer==cMAIN_QR){// tutorial
                            white_screen();
                            draw_qr_code("youtu.be/8vy5LIxT1ls");                            
                            print_camera(2,65,cSAFE);
                            estado = QR_TUTORIAL;
                            print_left_arrow_black(5,123);

                        }
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        spi_send(0x33);
                        if (main_pointer > 0) {
                            main_pointer--;
                        }
                        main_screen_fast(main_pointer);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        spi_send(0x55);
                        if (main_pointer < (cMAIN_n_opt-1)) {
                            main_pointer++;
                        }
                        main_screen_fast(main_pointer);
                        pulsed_bt = NONE;
                        break;

                    case LEFT_BT:
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
            case CREATE_SEED:        /////  SCREEN     2   /////////////
                switch (pulsed_bt) {
                    case OK_BT:
                        if (seed_pointer == cSEED_triple) {
                            black_screen();
                            sel_input_screen(selinput_pointer);
                            estado = SEL_INPUT;
                            size_pointer = cSIZE_24;
                            entropy_bits = cENTROPY_BITS24W;
                        } else if (seed_pointer == cSEED_dice) {
                            black_screen();
                            sel_dice_mode_screen(dice_mode_pointer);
                            estado = SEL_DICE_MODE;
                        } else {
                            black_screen();
                            print_selsize_screen(size_pointer);
                            estado = SEL_SIZE;
                        }
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        main_screen(0);
                        estado = MAIN;
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        if (seed_pointer > 0) {
                            seed_pointer--;
                        }
                        create_seed_screen(seed_pointer);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (seed_pointer < (cSEED_n_opt-1)) {
                            seed_pointer++;
                        }
                        create_seed_screen(seed_pointer);
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
            case SEL_DICE_MODE:
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        if (dice_mode_pointer == 0) { // Raw entropy bits
                            print_selsize_screen(size_pointer);
                            estado = SEL_SIZE;
                        } else { // String hash
                            sel_hash_mode_screen(hash_mode_pointer);
                            estado = SEL_HASH_MODE;
                        }
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        create_seed_screen(seed_pointer);
                        estado = CREATE_SEED;
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        if (dice_mode_pointer > 0) dice_mode_pointer--;
                        sel_dice_mode_screen(dice_mode_pointer);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (dice_mode_pointer < (cDICE_MODE_n_opt - 1)) dice_mode_pointer++;
                        sel_dice_mode_screen(dice_mode_pointer);
                        pulsed_bt = NONE;
                        break;
                    default:
                        pulsed_bt = NONE;
                        break;
                }
                break;
            case SEL_HASH_MODE:
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        print_selsize_screen(size_pointer);
                        estado = SEL_SIZE;
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        sel_dice_mode_screen(dice_mode_pointer);
                        estado = SEL_DICE_MODE;
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        if (hash_mode_pointer > 0) hash_mode_pointer--;
                        sel_hash_mode_screen(hash_mode_pointer);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (hash_mode_pointer < (cHASH_MODE_n_opt - 1)) hash_mode_pointer++;
                        sel_hash_mode_screen(hash_mode_pointer);
                        pulsed_bt = NONE;
                        break;
                    default:
                        pulsed_bt = NONE;
                        break;
                }
                break;
            case SEL_OBFUS:        /////  OBFUS SCREEN   /////////////
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        if (obfuscation_pointer==cOBFUS_NOT ){// negate seed words
                            sel_input_screen(selinput_pointer);
                            estado = SEL_INPUT;
                            //seed_pointer=2; //word pick

                        } else if (obfuscation_pointer==cOBFUS_SHIFT){// shift words
                            sel_shift_screen(shift_pointer);
                            estado = SEL_SHIFT;
                        } else {// cOBFUS_ADD
                            sel_add_screen(add_pointer);
                            estado = SEL_ADD_SUB;
                        }
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        main_screen(main_pointer);
                        estado = MAIN;
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        if (obfuscation_pointer > 0) {
                            obfuscation_pointer--;
                        }
                        sel_obfus_screen(obfuscation_pointer);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (obfuscation_pointer < (cOBFUS_n_opt-1)) {
                            obfuscation_pointer++;
                        }
                        sel_obfus_screen(obfuscation_pointer);
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
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
                        if (main_pointer==cMAIN_XOR) { // xor stuff
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
                                print_word_number_top(word_number, xor_merge_words_available, main_pointer,  word_number_text);
                                print_previous_confirmed_word(word_number, word_number_text);
                                print_keyboard_with_validation(lt_idx, found_bool, word);
                            }else{//SD
                                black_screen();
                                estado = SEL_SD_BLOCK_XOR;
                                sel_sd_block_screen_generic(SDblock_pointer);
                            }
                        }else if ((main_pointer==cMAIN_SSS) & (sss_pointer==cMERGE)){
                            black_screen();
                            print_sel_share_screen(selected_share_id);
                            estado = SEL_SHARE;
                            pulsed_bt = NONE;
                            break;

                        } else if (main_pointer==cMAIN_LOAD || main_pointer==cMAIN_OBFUS || main_pointer==cMAIN_SSS ){//check seed or obfuscate/SSS
                            black_screen();
                            estado = WRITE_WORD;
                            word_number=1;
                            clear_string(word);
                            found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                            print_word_number_top(word_number, xor_merge_words_available, main_pointer,  word_number_text);
                            print_previous_confirmed_word(word_number, word_number_text);
                            print_keyboard_with_validation(lt_idx, found_bool, word);
                        } else if (seed_pointer==cSEED_dice && dice_mode_pointer == 1){ // String hash
                            black_screen();
                            dice_string_buf[0] = '\0';
                            dice_input_idx = 0;
                            estado = DICE_STRING_INPUT;
                            int target = (size_pointer == cSIZE_12) ? 50 : 100;
                            init_dice_string_input_screen(dice_input_idx, dice_string_buf, target);
                        } else if (seed_pointer==cSEED_dice || seed_pointer==cSEED_coin){// roll dice or coins
                            black_screen();
                            print_diceroll_screen(size_pointer, seed_pointer);
                            estado = ROLL_DICE1;
                            bit_count_dice = 0;
                        } else if (seed_pointer==cSEED_word){//word pick
                            black_screen();
                            estado = WRITE_WORD;
                            word_number=1;
                            clear_string(word);
                            found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                            print_word_number_top(word_number, xor_merge_words_available, main_pointer,  word_number_text);
                            print_previous_confirmed_word(word_number, word_number_text);
                            print_keyboard_with_validation(lt_idx, found_bool, word);
                        }   else if (seed_pointer==cSEED_timer){//word pick
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
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        if (main_pointer==cMAIN_OBFUS) {
                            sel_obfus_screen(obfuscation_pointer);
                            estado = SEL_OBFUS;
                        } else if (main_pointer==cMAIN_XOR || main_pointer==cMAIN_LOAD || main_pointer==cMAIN_SSS){
                            sel_input_screen(selinput_pointer);
                            estado = SEL_INPUT;
                        } else {
                            if (seed_pointer == cSEED_dice) {
                                if (dice_mode_pointer == 1) { // String Hash back
                                    sel_hash_mode_screen(hash_mode_pointer);
                                    estado = SEL_HASH_MODE;
                                } else { // Raw back
                                    sel_dice_mode_screen(dice_mode_pointer);
                                    estado = SEL_DICE_MODE;
                                }
                            } else {
                                create_seed_screen(seed_pointer);
                                estado = CREATE_SEED;
                            }
                        }
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        if (size_pointer > 0) {
                            size_pointer--;
                        }
                        print_selsize_screen(size_pointer);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (size_pointer < (cSIZE_n_opt-1)) {
                            size_pointer++;
                        }
                        print_selsize_screen(size_pointer);
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
            case SEL_XOR:
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        sel_input_screen(selinput_pointer);
                        estado = SEL_INPUT;
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        main_screen(main_pointer);
                        estado = MAIN;
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        if (xor_pointer > 0) {
                            xor_pointer--;
                        }
                        print_xorsel_screen(xor_pointer);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (xor_pointer < (cXOR_n_opt-1)) {
                            xor_pointer++;
                        }
                        print_xorsel_screen(xor_pointer);
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
            case SEL_SHIFT:        /////  SCREEN     2   /////////////
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        //print_selsize_screen(size_pointer);
                        //estado = SEL_SIZE;
                        print_nbits_screen(shift_nbits);
                        estado = SEL_NBITS_SHIFT;
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        sel_obfus_screen(obfuscation_pointer);
                        estado = SEL_OBFUS;
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        if (shift_pointer > 0) {
                            shift_pointer--;
                        }
                        sel_shift_screen(shift_pointer);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (shift_pointer < (cSHIFT_n_opt-1)) {
                            shift_pointer++;
                        }
                        sel_shift_screen(shift_pointer);
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
            case SEL_ADD_SUB:
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        //print_selsize_screen(size_pointer);
                        //estado = SEL_SIZE;
                        print_nbits_screen(shift_nbits);
                        estado = SEL_NBITS_SHIFT;
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        sel_obfus_screen(obfuscation_pointer);
                        estado = SEL_OBFUS;
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        if (add_pointer > 0) {
                            add_pointer--;
                        }
                        sel_add_screen(add_pointer);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (add_pointer < (cSHIFT_n_opt-1)) {
                            add_pointer++;
                        }
                        sel_add_screen(add_pointer);
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
            case SEL_SD_BLOCK:
                switch (pulsed_bt) {
                    case OK_BT:
                        //clear preview text
                        //drawtext(50, 20 + 10*SDblock_pointer, "           ", ST7735_BLACK, ST7735_BLACK, 1);
                        if (main_pointer==cMAIN_ERASESD) { // Erase
                            for (int i = 0; i < 512; i++) buffer[i] = 0; // Clear the sector buffer
                            if (sd_write_block(SDblock_pointer+SD_page*cSDBLOCK_n_opt, buffer)) { // Write the block
                                drawtext(70, 20 + 10*SDblock_pointer, "ERASE SUCCESS", ST7735_GREEN, ST7735_BLACK, 1);
                            } else {
                                drawtext(70, 20 + 10*SDblock_pointer, "ERASE ERROR ", ST7735_RED, ST7735_BLACK, 1);
                            }
                            pulsed_bt = NONE;
                            break;

                        }else{ // Read

                            // Reinitialize the SD card if the first read fails.
                            if (!sd_read_block(SDblock_pointer +SD_page*cSDBLOCK_n_opt, buffer)) {
                                sd_init();
                            }
                            if (sd_read_block(SDblock_pointer +SD_page*cSDBLOCK_n_opt, buffer)) {
                                checksum_SD=1; // Reset checksum and account for the checksum byte
                                XOR_SD = buffer[cSD_XOR_ADDR];
                                for (int i = 0; i < 32; i++){
                                    data_array_256b[i]=buffer[i] ^ XOR_SD;// Load entropy data from SD
                                    checksum_SD+=buffer[i]; // Recompute checksum
                                }
                                // Validate checksum.
                                if (checksum_SD==buffer[cSD_CHECKSUM_ADDR]){

                                    size_pointer=buffer[cSD_SIZE_ADDR];
                                    if (main_pointer == cMAIN_create && seed_pointer == cSEED_triple) {
                                        if (size_pointer != cSIZE_24) {
                                            drawtext(70, 20 + 10*SDblock_pointer, "WRONG SIZE", ST7735_RED, ST7735_BLACK, 1);
                                            pulsed_bt = NONE;
                                            break;
                                        }
                                        drawtext(70, 20 + 10*SDblock_pointer, "LOAD OK", ST7735_GREEN, ST7735_BLACK, 1);
                                        black_screen();
                                        estado = PROCESS_TRIPLE;
                                        pulsed_bt = NONE;
                                        break;
                                    } else if (main_pointer==cMAIN_SSS){
                                        drawtext(70, 20 + 10*SDblock_pointer, "LOAD OK", ST7735_GREEN, ST7735_BLACK, 1);
                                        black_screen();
                                        sss_split_kofm(data_array_256b /* c0 */,
                                            coeffs, SSS_K /* k threshold */,
                                            LEN,
                                            cN_MAX /* total shares */, // always kept at max capacity
                                            shares);
                                        //extract_11bit_groups(append_checksum(shares[selected_share_id],16), 17);
                                        for (int i = 0; i < 16 + size_pointer*16; i++) data_array_256b[i]=shares[selected_share_id-1][i];

                                    }else if (main_pointer==cMAIN_OBFUS) {
                                        drawtext(70, 20 + 10*SDblock_pointer, "LOAD OK", ST7735_GREEN, ST7735_BLACK, 1);
                                        black_screen();
                                        if (obfuscation_pointer==cOBFUS_NOT){
                                            not_operator(data_array_256b,16 + size_pointer*16);
                                        } else if (obfuscation_pointer==cOBFUS_SHIFT){
                                            if (shift_pointer== cLEFT){
                                                for (int i = 0; i < shift_nbits; i++) shift_left(data_array_256b,16 + size_pointer*16);
                                            } else {
                                                for (int i = 0; i < shift_nbits; i++) shift_right(data_array_256b,16 + size_pointer*16);
                                            }
                                        } else if (obfuscation_pointer==cOBFUS_ADD){
                                            addsub_11bit_groups(16 + size_pointer*16, shift_nbits, add_pointer);
                                        }
                                    }
                                    redraw_show_seed_with_offset();

                                } else {//checksum error
                                    drawtext(70, 20 + 10*SDblock_pointer, "NO SEED", ST7735_RED, ST7735_BLACK, 1);
                                    pulsed_bt = NONE;
                                    break;
                                }
                                pulsed_bt = NONE;
                                break;

                            } else {
                                black_screen();
                                drawtext(10, 30, "SD ERROR", ST7735_RED, ST7735_BLACK, 1);
                                estado = END_MODE;
                                pulsed_bt = NONE;
                                break;
                            }
                        }

                    case BACK_BT:
                        black_screen();
                        if (main_pointer==cMAIN_OBFUS || main_pointer==cMAIN_XOR || main_pointer==cMAIN_LOAD || main_pointer==cMAIN_SSS || (main_pointer == cMAIN_create && seed_pointer == cSEED_triple)){
                            sel_input_screen(selinput_pointer);
                            estado = SEL_INPUT;
                        }else {
                            main_screen(main_pointer);
                            estado = MAIN;
                        }
                        pulsed_bt = NONE;
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
                        pulsed_bt = NONE;
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

                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        if (SD_page > 0) {
                            SD_page--;
                            black_screen();
                            sel_sd_block_screen_generic(SDblock_pointer);
                        }
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        black_screen();
                        SD_page++;
                        sel_sd_block_screen_generic(SDblock_pointer);
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
            case SEL_SD_BLOCK_WR:
                switch (pulsed_bt) {
                    case OK_BT: // Write
                        //clear preview
                        //drawtext(50, 20 + 10*SDblock_pointer, "           ", ST7735_BLACK, ST7735_BLACK, 1);
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
                        pulsed_bt = NONE;
                        break;

                     case BACK_BT:
                        redraw_show_seed_with_offset();
                        pulsed_bt = NONE;
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
                        pulsed_bt = NONE;
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
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        if (SD_page > 0) {
                            black_screen();
                            SD_page--;
                            sel_sd_block_screen_wr(SDblock_pointer);
                        }
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        black_screen();
                        SD_page++;
                        sel_sd_block_screen_wr(SDblock_pointer);
                        pulsed_bt = NONE;
                        break;

                    default:
                        break;
                }
                break;
            case SEL_SD_BLOCK_XOR:
                switch (pulsed_bt) {
                    case OK_BT:
                        //clear preview
                        //drawtext(50, 20 + 10*SDblock_pointer, "           ", ST7735_BLACK, ST7735_BLACK, 1);
                        // Reinitialize the SD card if the first read fails.
                        if (!sd_read_block(SDblock_pointer +SD_page*cSDBLOCK_n_opt, buffer)) {
                            sd_init();
                        }
                        if (sd_read_block(SDblock_pointer+SD_page*cSDBLOCK_n_opt, buffer)) {
                            checksum_SD=1; // Reset checksum and account for the checksum byte
                            XOR_SD = buffer[cSD_XOR_ADDR];
                            for (int i = 0; i < 32; i++){
                                data_array_256b[i]=buffer[i]^ XOR_SD; // Load entropy data from SD
                                checksum_SD+=buffer[i]; // Recompute checksum
                            }
                            // Validate checksum.
                            if (checksum_SD==buffer[cSD_CHECKSUM_ADDR]){
                                // Check size
                                if (buffer[cSD_SIZE_ADDR]==size_pointer){
                                    drawtext(70, 20 + 10*SDblock_pointer, "XOR INPUT OK", ST7735_GREEN, ST7735_BLACK, 1);
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
                                        pulsed_bt = NONE;
                                        break;
                                    } else { // We have everything
                                        black_screen();
                                        for (int i = 0; i < 16 + 16*size_pointer; i++) {
                                            data_array_256b[i] = data_array_256b[i] ^ xor_merge_word1[i]^ xor_merge_word2[i]^ xor_merge_word3[i];
                                        }
                                        redraw_show_seed_with_offset();
                                        pulsed_bt = NONE;
                                        break;

                                    }
                                }else{
                                    drawtext(70, 20 + 10*SDblock_pointer, "WRONG SIZE", ST7735_RED, ST7735_BLACK, 1);
                                    pulsed_bt = NONE;
                                    break;
                                }

                            } else {//checksum error
                                drawtext(70, 20 + 10*SDblock_pointer, "NO SEED", ST7735_RED, ST7735_BLACK, 1);
                                pulsed_bt = NONE;
                                break;
                            }
                            pulsed_bt = NONE;
                            break;

                        } else {
                            black_screen();
                            drawtext(10, 30, "SD ERROR", ST7735_RED, ST7735_BLACK, 1);
                            estado = END_MODE;
                            pulsed_bt = NONE;
                            break;
                        }

                    case BACK_BT:
                        black_screen();
                        print_selsize_screen(size_pointer);
                        estado = SEL_SIZE;
                        pulsed_bt = NONE;
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
                        pulsed_bt = NONE;
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
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        if (SD_page > 0){
                            SD_page--;
                            sel_sd_block_screen_generic(SDblock_pointer);
                            black_screen();
                        }
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        SD_page++;
                        sel_sd_block_screen_generic(SDblock_pointer);
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
           case SEL_SD_BLOCK_MERGE:
                switch (pulsed_bt) {
                    case OK_BT:
                        //clear preview
                        //drawtext(50, 20 + 10*SDblock_pointer, "           ", ST7735_BLACK, ST7735_BLACK, 1);
                        // Reinitialize the SD card if the first read fails.
                        if (!sd_read_block(SDblock_pointer +SD_page*cSDBLOCK_n_opt, buffer)) {
                            sd_init();
                        }
                        if (sd_read_block(SDblock_pointer+SD_page*cSDBLOCK_n_opt, buffer)) {
                            checksum_SD=1; // Reset checksum and account for the checksum byte
                            XOR_SD = buffer[cSD_XOR_ADDR];
                            for (int i = 0; i < 32; i++){
                                data_array_256b[i]=buffer[i]^ XOR_SD; // Load entropy data from SD
                                checksum_SD+=buffer[i]; // Recompute checksum
                            }
                            // Validate checksum.
                            if (checksum_SD==buffer[cSD_CHECKSUM_ADDR]){
                                // Load size from the first share and validate the rest.
                                if (shares_loaded==0){
                                    size_pointer=buffer[cSD_SIZE_ADDR];
                                }else if (buffer[cSD_SIZE_ADDR]!=size_pointer){
                                    drawtext(70, 20 + 10*SDblock_pointer, "WRONG SIZE", ST7735_RED, ST7735_BLACK, 1);
                                    pulsed_bt = NONE;
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
                                        pulsed_bt = NONE;
                                        break;
                                    }
                                    for (int i = 0; i < 32; i++) data_array_256b[i]=SSS_result[i]; // Move result to data array
                                    redraw_show_seed_with_offset();
                                    pulsed_bt = NONE;
                                    break;

                                }

                            } else {//checksum error
                                drawtext(70, 20 + 10*SDblock_pointer, "NO SEED FOUND", ST7735_RED, ST7735_BLACK, 1);
                                pulsed_bt = NONE;
                                break;
                            }
                            pulsed_bt = NONE;
                            break;

                        } else {
                            black_screen();
                            drawtext(10, 30, "SD ERROR", ST7735_RED, ST7735_BLACK, 1);
                            estado = END_MODE;
                            pulsed_bt = NONE;
                            break;
                        }

                    case BACK_BT:
                        black_screen();
                        print_selsize_screen(size_pointer);
                        estado = SEL_SIZE;
                        pulsed_bt = NONE;
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
                        pulsed_bt = NONE;
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
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:// Cannot page up/down here
                        if(selected_share_id>1)selected_share_id--;
                        sel_sd_block_screen_merge(SDblock_pointer,selected_share_id);
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        if(selected_share_id<cN_MAX)selected_share_id++;
                        sel_sd_block_screen_merge(SDblock_pointer,selected_share_id);
                        pulsed_bt = NONE;
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
                                print_word_number_top(word_number, xor_merge_words_available, main_pointer, word_number_text);
                                print_previous_confirmed_word(word_number, word_number_text);
                                print_keyboard_with_validation(lt_idx, found_bool, word);
                            } else {
                                print_selsize_screen(size_pointer);
                                estado = SEL_SIZE;
                            }
                        } else { //cFROMSD
                            black_screen();
                            if (seed_pointer == cSEED_triple && main_pointer == cMAIN_create) {
                                sel_sd_block_screen_generic(SDblock_pointer);
                                estado = SEL_SD_BLOCK;
                            } else if (main_pointer==cMAIN_XOR){
                                print_selsize_screen(size_pointer);
                                estado = SEL_SIZE;
                            }else if ((main_pointer==cMAIN_SSS) & (sss_pointer==cMERGE)){
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
                            }else{// cMAIN_OBFUS o cMAIN_LOAD
                                sel_sd_block_screen_generic(SDblock_pointer);
                                estado = SEL_SD_BLOCK;
                            }
                        }
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        if (main_pointer == cMAIN_XOR)   {
                            print_xorsel_screen(xor_pointer);
                            estado = SEL_XOR;
                        }else if((main_pointer==cMAIN_SSS) & (sss_pointer==cSPLIT)){
                            print_selkn_screen(SSS_K, SSS_N, sel_K_N);
                            estado = SEL_KN;
                        }else if((main_pointer==cMAIN_SSS) & (sss_pointer==cMERGE)){
                            print_selk_screen(SSS_K);
                            estado = SEL_K;
                        }else if(main_pointer==cMAIN_OBFUS){
                            if(obfuscation_pointer==cOBFUS_SHIFT || obfuscation_pointer==cOBFUS_ADD){
                                print_nbits_screen(shift_nbits);
                                estado = SEL_NBITS_SHIFT;
                            }else{ // cOBFUS_NOT
                                sel_obfus_screen(obfuscation_pointer);
                                estado = SEL_OBFUS;
                            }
                        }else if (main_pointer == cMAIN_create) { 
                            create_seed_screen(seed_pointer);
                            estado = CREATE_SEED;
                        }else {
                            main_screen(main_pointer);
                            estado = MAIN;
                        }

                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        if (selinput_pointer > 0) {
                            selinput_pointer--;
                        }
                        sel_input_screen(selinput_pointer);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (selinput_pointer < (cSELINPUT_n_opt-1)) {
                            selinput_pointer++;
                        }
                        sel_input_screen(selinput_pointer);
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
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
                        } else {//merge
                            print_selk_screen(SSS_K);
                            estado = SEL_K;
                        }
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        main_screen(main_pointer);
                        estado = MAIN;
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        if (sss_pointer > 0) {
                            sss_pointer--;
                        }
                        sel_SSS_screen(sss_pointer);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (sss_pointer < (cSSS_n_opt-1)) {
                            sss_pointer++;
                        }
                        sel_SSS_screen(sss_pointer);
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
           case SEL_KN:
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        sel_input_screen(selinput_pointer);
                        estado = SEL_INPUT;
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        sel_SSS_screen(sss_pointer);
                        estado = SEL_SSS;
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        if (sel_K_N==0){
                            if (SSS_K<cK_MAX)SSS_K++;
                        } else { if (SSS_N<cN_MAX)SSS_N++;}
                        print_selkn_screen(SSS_K, SSS_N, sel_K_N);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (sel_K_N==0){
                            if (SSS_K>2)SSS_K--;
                        } else { if (SSS_N>3)SSS_N--;}
                        print_selkn_screen(SSS_K, SSS_N, sel_K_N);
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        if (sel_K_N==1)sel_K_N=0;
                        print_selkn_screen(SSS_K, SSS_N, sel_K_N);
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        if (sel_K_N==0)sel_K_N=1;
                        print_selkn_screen(SSS_K, SSS_N, sel_K_N);
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
           case SEL_K:
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        sel_input_screen(selinput_pointer);
                        estado = SEL_INPUT;
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        sel_SSS_screen(sss_pointer);
                        estado = SEL_SSS;
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        if (SSS_K<cK_MAX)SSS_K++;
                        print_selk_screen(SSS_K);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (SSS_K>2)SSS_K--;
                        print_selk_screen(SSS_K);
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
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
                        print_word_number_top(word_number, xor_merge_words_available, main_pointer,  word_number_text);
                        print_previous_confirmed_word(word_number, word_number_text);
                        print_keyboard_with_validation(lt_idx, found_bool, word);
                    case BACK_BT://no return here

                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        if (selected_share_id<cN_MAX)selected_share_id++;
                        print_sel_share_screen(selected_share_id);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (selected_share_id>1)selected_share_id--;
                        print_sel_share_screen(selected_share_id);
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;

            case SEL_NBITS_SHIFT:
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        sel_input_screen(selinput_pointer);
                        estado = SEL_INPUT;
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        if(obfuscation_pointer==cOBFUS_ADD){
                            sel_add_screen(add_pointer);
                            estado = SEL_ADD_SUB;
                        }else{
                            sel_shift_screen(shift_pointer);
                            estado = SEL_SHIFT;
                        }

                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        shift_nbits++;
                        print_nbits_screen(shift_nbits);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        if (shift_nbits > 1) {
                            shift_nbits--;
                        }
                        print_nbits_screen(shift_nbits);
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
            case TMR_INPUT:
                switch (pulsed_bt) {
                    case OK_BT:
                        pulsed_bt = NONE;
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
                                black_screen();
                                sel_sd_block_screen_generic(SDblock_pointer);
                                estado = SEL_SD_BLOCK;
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
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
            case ROLL_DICE1:  /////  ROLL DICE   or COIN/////////////
                switch (pulsed_bt) {
                    case OK_BT:
                        pulsed_bt = NONE;
                        if (seed_pointer == cSEED_dice) {
                            append_entropy_bits("11", 2);
                            if (check_dice_count_end()) break;
                            //rectan(0, 35, 159, 43, BLACK); 
                            draw_shared_entropy_building();
                            update_dice_bit_count_display(bit_count_dice);
                        }
                        break;
                    case BACK_BT:
                        pulsed_bt = NONE;
                        if (seed_pointer == cSEED_dice) {
                            append_entropy_bits("01", 2);
                            if (check_dice_count_end()) break;
                            //rectan(0, 35, 159, 43, BLACK); 
                            draw_shared_entropy_building();
                            update_dice_bit_count_display(bit_count_dice);
                        } else if (seed_pointer == cSEED_coin) {
                            if (bit_count_dice > 0) {
                                bit_count_dice--;
                                set_bit(data_array_256b, bit_count_dice, 0);
                                last_input_len = 0; // Clear purple highlight on delete
                                //rectan(0, 35, 159, 43, BLACK); 
                                draw_shared_entropy_building();
                                update_dice_bit_count_display(bit_count_dice);
                            }
                        }
                        break;
                    case UP_BT:
                        pulsed_bt = NONE;
                        if (seed_pointer == cSEED_dice) {
                            append_entropy_bits("10", 2);
                            if (check_dice_count_end()) break;
                            //rectan(0, 35, 159, 43, BLACK); 
                            draw_shared_entropy_building();
                            update_dice_bit_count_display(bit_count_dice);
                        }
                        break;
                    case DOWN_BT:
                        pulsed_bt = NONE;
                        if (seed_pointer == cSEED_dice) {
                            append_entropy_bits("1", 1);
                        } else {
                            append_entropy_bits("1", 1);
                        }
                        if (check_dice_count_end()) break;
                        //rectan(0, 35, 159, 43, BLACK); 
                        draw_shared_entropy_building();
                        update_dice_bit_count_display(bit_count_dice);
                        break;
                    case LEFT_BT:
                        pulsed_bt = NONE;
                        if (seed_pointer == cSEED_dice) {
                            append_entropy_bits("0", 1);
                        } else {
                            append_entropy_bits("0", 1);
                        }
                        if (check_dice_count_end()) break;
                        //rectan(0, 35, 159, 43, BLACK); 
                        draw_shared_entropy_building();
                        update_dice_bit_count_display(bit_count_dice);
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
                        if (seed_pointer == cSEED_dice) {
                            append_entropy_bits("00", 2);
                            if (check_dice_count_end()) break;
                            //rectan(0, 35, 159, 43, BLACK); 
                            draw_shared_entropy_building();
                            update_dice_bit_count_display(bit_count_dice);
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
                                // 1. Añadimos al buffer
                                add_char_dice(dice_string_buf, dice_input_idx + 1, char_hash_limit);
                                // 2. Delta update: pintamos el nuevo caracter en pantalla
                                update_dice_string_char(len, new_char, false);
                                // 3. Actualizamos el contador
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
                        pulsed_bt = NONE;
                        break;
                    }
                    case BACK_BT: {
                        int target = (size_pointer == cSIZE_12) ? 50 : 100;
                        int len = strlen(dice_string_buf);
                        
                        if (len > 0) {
                            // 1. Delta update: borramos el último caracter de la pantalla
                            update_dice_string_char(len - 1, ' ', true);
                            // 2. Borramos del buffer
                            remove_last_char(dice_string_buf);
                            // 3. Actualizamos el contador
                            print_dice_string_counter(len - 1, target);
                            
                            // Prevent cursor from being stuck on DONE if length falls below target
                            if (len - 1 < target && dice_input_idx == 6) {
                                dice_input_idx = 5;
                            }
                            print_dice_string_keyboard(dice_input_idx, len - 1, target);
                            
                        } else {
                            black_screen();
                            print_selsize_screen(size_pointer);
                            estado = SEL_SIZE;
                        }
                        pulsed_bt = NONE;
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
                        pulsed_bt = NONE;
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
                        pulsed_bt = NONE;
                        break;
                    }
                    case UP_BT:
                    case DOWN_BT:
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
            case CARD_INPUT:
                switch (pulsed_bt) {
                    case OK_BT:
                        pulsed_bt = NONE;
                        if (append_selected_card_entropy()) {
                            if (!check_dice_count_end()) {
                                print_card_input_screen();
                            }
                        } else {
                            print_card_input_screen();
                        }
                        break;
                    case BACK_BT:
                        pulsed_bt = NONE;
                        if (card_history_count > 0) {
                            remove_last_card_entropy();
                            print_card_input_screen();
                        } else {
                            black_screen();
                            print_selsize_screen(size_pointer);
                            estado = SEL_SIZE;
                        }
                        break;
                    case UP_BT:
                        pulsed_bt = NONE;                        
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
                        pulsed_bt = NONE;                        
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
                        pulsed_bt = NONE;                        
                        card_field_pointer = 0;
                        print_card_input_screen();
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;                        
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
                               word = add_char(word, lt_idx, 32);
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
                                        pulsed_bt = NONE;
                                        break;
                                    }
                                    if (main_pointer !=cMAIN_create) { // check checksum
                                        if(!matches_last_word_checksum(data_array_256b,result,size_pointer)){
                                            if ((main_pointer==cMAIN_XOR) || ((main_pointer==cMAIN_SSS) & (sss_pointer==cMERGE))) {
                                                show_word_list_retry_error();
                                                estado = WORD_LIST_ERROR;
                                            } else {
                                                black_screen();
                                                drawtext(10,10, INCORRECT_MSG, ST7735_RED, ST7735_BLACK, 1);
                                                estado = END_MODE;
                                            }
                                            pulsed_bt = NONE;
                                            break;
                                        }
                                    }
                                    if (main_pointer==cMAIN_OBFUS) {
                                        if (obfuscation_pointer==cOBFUS_SHIFT){
                                            if (shift_pointer== cLEFT){
                                                for (int i = 0; i < shift_nbits; i++) {
                                                    shift_left(data_array_256b,16 + size_pointer*16);
                                                }
                                            } else {
                                                for (int i = 0; i < shift_nbits; i++) {
                                                    shift_right(data_array_256b,16  + size_pointer*16);
                                                }
                                            }
                                        } else if (obfuscation_pointer==cOBFUS_NOT){
                                            not_operator(data_array_256b,16 +size_pointer*16);
                                        } else if (obfuscation_pointer==cOBFUS_ADD){
                                            addsub_11bit_groups(16 + size_pointer*16, shift_nbits, add_pointer);
                                        }
                                    } else if ((main_pointer==cMAIN_SSS) & (sss_pointer==cSPLIT)){
                                        sss_split_kofm(data_array_256b /* c0 */,
                                            coeffs, SSS_K /* k threshold */,
                                            LEN,
                                            cN_MAX /* total shares */, // always kept at max capacity
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
                                                pulsed_bt = NONE;
                                                break;
                                            }
                                            for (int i = 0; i < 32; i++) data_array_256b[i] = SSS_result[i]; // Copy the result into the data buffer
                                            redraw_show_seed_with_offset();
                                            pulsed_bt = NONE;
                                            break;
                                        }
                                        // The merge is not complete yet
                                        black_screen();
                                        print_sel_share_screen(selected_share_id);
                                        estado = SEL_SHARE;
                                        pulsed_bt = NONE;
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
                                            print_word_number_top(word_number, xor_merge_words_available, main_pointer,  word_number_text);
                                            print_previous_confirmed_word(word_number, word_number_text);
                                            print_keyboard_with_validation(lt_idx, found_bool, word);
                                            estado = WRITE_WORD;
                                            pulsed_bt = NONE;
                                            break;
                                        } else { // All XOR inputs are already loaded
                                            for (int i = 0; i < 16 + size_pointer*16 ; i++) {
                                                data_array_256b[i] = data_array_256b[i] ^ xor_merge_word1[i]^ xor_merge_word2[i]^ xor_merge_word3[i];
                                            }
                                        }
                                    }

                                    if (main_pointer == cMAIN_create) {
                                        print_checksum_screen();
                                        estado = SHOW_CHECKSUM_DETAILS;
                                        pulsed_bt = NONE;
                                        break;
                                    }

                                    // Finally show the full result for non-create paths
                                    redraw_show_seed_with_offset();
                                    pulsed_bt = NONE;
                                    break;
                                }

                                // More words remain after confirming this one.
                                word_number +=1;
                                // Reset the word buffer before entering the next word.
                                lt_idx=0;
                                found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                                print_word_number_top(word_number, xor_merge_words_available, main_pointer,  word_number_text);
                                print_previous_confirmed_word(word_number, word_number_text);
                                print_keyboard_with_validation(lt_idx, found_bool, word);
                            }
                        }
                        pulsed_bt = NONE;
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
                            print_word_number_top(word_number, xor_merge_words_available, main_pointer,  word_number_text);
                            print_previous_confirmed_word(word_number, word_number_text);
                            lt_idx=0;
                            print_keyboard_with_validation(lt_idx, found_bool, word);

                        }else{ // Normal backspace
                            remove_last_char(word);
                            found = refresh_word_input_preview(word, result, sizeof(result), &found_bool);
                            print_keyboard_with_validation(lt_idx, found_bool, word);
                        }
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        lt_idx = get_next_valid_key(lt_idx, -9, word, found_bool);
                        print_word_number_top(word_number, xor_merge_words_available, main_pointer,  word_number_text);
                        print_keyboard_with_validation(lt_idx, found_bool, word);
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        lt_idx = get_next_valid_key(lt_idx, 9, word, found_bool);
                        print_word_number_top(word_number, xor_merge_words_available, main_pointer,  word_number_text);
                        print_keyboard_with_validation(lt_idx, found_bool, word);
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        lt_idx = get_next_valid_key(lt_idx, -1, word, found_bool);
                        print_word_number_top(word_number, xor_merge_words_available, main_pointer,  word_number_text);
                        print_keyboard_with_validation(lt_idx, found_bool, word);
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        lt_idx = get_next_valid_key(lt_idx, 1, word, found_bool);
                        print_word_number_top(word_number, xor_merge_words_available, main_pointer,  word_number_text);
                        print_keyboard_with_validation(lt_idx, found_bool, word);
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
            case SHOW_CHECKSUM_DETAILS:
                switch (pulsed_bt) {
                    case OK_BT:
                        redraw_show_seed_with_offset();
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                    case UP_BT:
                    case DOWN_BT:
                    case LEFT_BT:
                    case RIGTH_BT:
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
                break;
            case QR_TUTORIAL:
                switch (pulsed_bt) {
                    case OK_BT:
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        black_screen();
                        main_screen(main_pointer);
                        estado = MAIN;
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
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
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        pulsed_bt = NONE;
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
                        pulsed_bt = NONE;
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
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        black_screen();
                        sel_sd_block_screen_wr(SDblock_pointer);
                        estado=SEL_SD_BLOCK_WR;
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT: //compact QR
                        white_screen();
                        draw_compactqr_code(16 + size_pointer*16, data_array_256b);
                        print_camera(2,50,cNOTSAFE);
                        print_camera(2,80,cNOTSAFE);
                        print_camera(145,50,cNOTSAFE);
                        print_camera(145,80,cNOTSAFE);
                        print_left_arrow_black(5,123);
                        estado = SHOW_QRSEED;

                        pulsed_bt = NONE;
                        break;
                    default:
                        break;
                }
           case SHOW_QRSEED:
                switch (pulsed_bt) {
                    case OK_BT:
                        pulsed_bt = NONE;
                        break;
                    case BACK_BT:
                        redraw_show_seed_with_offset();
                        pulsed_bt = NONE;
                        break;
                    case UP_BT:
                        pulsed_bt = NONE;
                        break;
                    case DOWN_BT:
                        pulsed_bt = NONE;
                        break;
                    case LEFT_BT:
                        redraw_show_seed_with_offset();
                        pulsed_bt = NONE;
                        break;
                    case RIGTH_BT:
                        pulsed_bt = NONE;
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
                    print_word_number_top(word_number, xor_merge_words_available, main_pointer,  word_number_text);
                    print_previous_confirmed_word(word_number, word_number_text);
                    print_keyboard_with_validation(lt_idx, found_bool, word);
                    estado = WRITE_WORD;
                    pulsed_bt = NONE;
                }
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
                pulsed_bt = NONE;
                break;
            }

            case SHOW_TRIPLE_CHKSUM_12:
                switch (pulsed_bt) {
                    case OK_BT:
                        black_screen();
                        print_triple_checksum(24);
                        estado = SHOW_TRIPLE_CHKSUM_24;
                        pulsed_bt = NONE;
                        break;
                    default:
                        pulsed_bt = NONE;
                        break;
                }
                break;

            case SHOW_TRIPLE_CHKSUM_24:
                switch (pulsed_bt) {
                    case OK_BT:
                        triple_view_state = 0;
                        refresh_triple_view();
                        pulsed_bt = NONE;
                        break;
                    default:
                        pulsed_bt = NONE;
                        break;
                }
                break;
            case END_MODE:
                switch (pulsed_bt) {
                    case OK_BT:
                    case BACK_BT:
                        black_screen();
                        main_screen(main_pointer);
                        estado = MAIN;
                        pulsed_bt = NONE;
                        break;
                    default:
                        pulsed_bt = NONE;
                        break;
                }
                break;
            default:
                break;
        }
    }

    /* Execution should not come here during normal operation */

    return ( EXIT_FAILURE );
}









/*******************************************************************************
 End of File
*/