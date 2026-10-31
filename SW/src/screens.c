/*******************************************************************************
 * Project:     SeedMate
 * File:        screens.c
 *
 * Summary:
 *   TFT screen and menu drawing routines.
 *
 * Description:
 *   Contains the bitmap tables, menu text tables and every function that only
 *   draws on the TFT (grids, arrows, menus, QR views, input screens).
 *   Moved verbatim out of main.c; application state is still owned by main.c
 *   and shared through app_state.h.
 *
 * License:     MIT, same as main.c
 ******************************************************************************/

#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include "definitions.h"
#include "TFT.h"
#include "QRCode-master/src/qrcode.h"
#include "app_defs.h"
#include "app_state.h"
#include "screens.h"

// ============================================================================
// BITMAP GRAPHICS REPLACEMENT
// ============================================================================
const uint16_t bmp_camera[11]      = { 0x0700, 0x0880, 0xF078, 0x8708, 0x8888, 0x9048, 0x9048, 0x8888, 0x8708, 0x8008, 0xFFF8 };
const uint16_t bmp_arrow_up[6]     = { 0x2000, 0x7000, 0xF800, 0x2000, 0x2000, 0x2000 };
const uint16_t bmp_arrow_down[6]   = { 0x2000, 0x2000, 0x2000, 0xF800, 0x7000, 0x2000 };
const uint16_t bmp_arrow_left[5]   = { 0x2000, 0x6000, 0xFC00, 0x6000, 0x2000 };
const uint16_t bmp_arrow_right[5]  = { 0x1000, 0x1800, 0xFC00, 0x1800, 0x1000 };
const uint16_t bmp_add_symbol[7]   = { 0x1000, 0x1000, 0x1000, 0xFE00, 0x1000, 0x1000, 0x1000 };

// ============================================================================
// Global Menus (Forces the compiler to store pointers strictly in ROM)
// ============================================================================
const char* const menu_main[]     = {"CREATE NEW SEED WORDS", "LOAD SEED WORDS", "BIP85 CHILD SEED", "SHAMIR SECRET SHARE", "SEED WORD XOR", "OBFUSCATION", "MNEMONIC TO CARDS", "ERASE SD", "RESOURCES", "SETTINGS"};
const char* const menu_create[]   = {"THROW COINS", "ROLL DICE", "RANDOM WORD PICK", "DRAW CARDS", "STOPWATCH TEST ONLY", "TRIPLE MNEMONIC"};
const char* const menu_dice[]     = {"RAW ENTROPY BITS", "STRING HASH"};
const char* const menu_hash[]     = {"1-6 MODE", "0-5 MODE (KEYSTONE)"};
const char* const menu_size[]     = {"12 WORDS", "24 WORDS"};
const char* const menu_qr[]       = {"STANDARD", "COMPACT"};
const char* const menu_xor[]      = {"A XOR B = C", "A XOR B XOR C = D", "A XOR B XOR C XOR D = E"};
const char* const menu_sss[]      = {"SPLIT", "MERGE"};
const char* const menu_resource[] = {"TUTORIAL", "BACKUP TOOL", "DICE TESTER", "PRINT WORDLIST", "BINARY WORDLIST"};
const char* const menu_obfus[]    = {"CIRCULAR SHIFT", "NOT OPERATOR", "WORDS ADD/SUB","1 WORD XOR","BYTE SWAP","HOW TO"};
const char* const menu_erase[]    = {"ERASE SECTOR", "WIPE ALL CARD"};
const char* const menu_bip84[] = {"ADDRESSES", "SEEDQR", "FINGERPRINT", "XPUB", "PASSPHRASE", "SIGN", "ACCOUNT", "MODE: SINGLE SIG"};
const char* const menu_addresses[] = {"RECEIVE ADDRESS", "CHANGE ADDRESS", "SCAN ADDRESS"};
const char* const menu_bip84_multi[] = {"SEEDQR", "FINGERPRINT", "XPUB", "PASSPHRASE", "SIGN", "IMPORT DESCRIPTOR", "ACCOUNT", "MODE: MULTI SIG"};
const char* const menu_sign[]     = {"FROM QR", "FROM SD"};
const char* const menu_input[]    = {"FROM KEYBOARD", "FROM SD", "QR SCAN"};

void draw_hex16(unsigned int x, unsigned int y, uint16_t numero, int N, unsigned int color, unsigned int bg, unsigned int size) {
    char hex_text[5]; // 4 hex digits plus null terminator

    for (int i = 0; i < N; i++) {
        u16_to_hex4(numero, hex_text); // Convert the value to hexadecimal text
        drawtext(x + i * (12 * size), y, hex_text, color, bg, size); // Adjust spacing for the current size
    }
}

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

void print_up_arrow(int x, int y,uint16_t color) {
    draw_bitmap(x, y - 6, 5, 6, bmp_arrow_up, color);
}

void print_add_symbol(int x, int y) {
    draw_bitmap(x, y - 7, 7, 7, bmp_add_symbol, WHITE);
}

void print_down_arrow(int x, int y, uint16_t color) {
    draw_bitmap(x, y - 6, 5, 6, bmp_arrow_down, color);
}

void print_left_arrow(int x, int y, uint16_t color) {
    draw_bitmap(x, y - 5, 6, 5, bmp_arrow_left, color);
}

void print_left_arrow_black(int x, int y) {
    draw_bitmap(x, y - 5, 6, 5, bmp_arrow_left, BLACK);
}

void print_rigth_arrow(int x, int y, uint16_t color) {
    draw_bitmap(x, y - 5, 6, 5, bmp_arrow_right, color);
}

void print_camera(int x, int y, int safe) {
    uint16_t color = (safe == cSAFE) ? ST7735_GREEN : ST7735_RED;
    draw_bitmap(x, y - 10, 13, 11, bmp_camera, color);
}

// ============================================================================



void print_cursor_grid(){
    drawFastHLine(63,105,90,WHITE);
    drawFastHLine(63,115,90,WHITE);
    drawFastHLine(63,125,90,WHITE);
    drawFastVLine(63,105,20,WHITE);
    drawFastVLine(93,105,20,WHITE);
    drawFastVLine(123,105,20,WHITE);
    drawFastVLine(153,105,20,WHITE);
}

void print_minus_symbol(int x,int y){
    drawFastHLine(x,y-3,7,WHITE);
}

void print_ok(){
    drawtext(133,107, OK_MSG, ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_menu1(){
    print_cursor_grid();
    print_up_arrow(106,114, ST7735_WHITE);
    print_down_arrow(106,123, ST7735_WHITE);
    print_ok();
}

void grid_menuwr(){
    print_cursor_grid();
    print_up_arrow(106,114, ST7735_WHITE);
    print_down_arrow(106,123, ST7735_WHITE);
    print_ok();
    drawtext(67,107, "LIST", ST7735_WHITE, ST7735_WHITE, 1);
    drawtext(125,117, "PAGE+", ST7735_WHITE, ST7735_WHITE, 1);
    drawtext(65,117, "PAGE-", ST7735_WHITE, ST7735_WHITE, 1);
}

void print_back(){
    drawtext(67,107, "BACK", ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_menu2(){
    print_cursor_grid();
    print_up_arrow(106,114, ST7735_WHITE);
    print_down_arrow(106,123, ST7735_WHITE);
    print_ok();
    print_back();

}

void grid_menuSD(){
    print_cursor_grid();
    print_up_arrow(106,114, ST7735_WHITE);
    print_down_arrow(106,123, ST7735_WHITE);
    print_ok();
    print_back();
    drawtext(125,117, "PAGE+", ST7735_WHITE, ST7735_WHITE, 1);
    drawtext(65,117, "PAGE-", ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_menu2_merge(){
    print_cursor_grid();
    print_up_arrow(106,114, ST7735_WHITE);
    print_down_arrow(106,123, ST7735_WHITE);
    print_ok();
    print_back();
    drawtext(128,117, "ID++", ST7735_WHITE, ST7735_WHITE, 1);
    drawtext(67,117, "ID--", ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_nbits(){
    print_cursor_grid();
    print_add_symbol(106,114);
    print_minus_symbol(106,123);
    print_ok();
    print_back();
}

void grid_nbits_noback(){
    print_cursor_grid();
    print_add_symbol(106,114);
    print_minus_symbol(106,123);
    print_ok();
}

void grid_nbits_LR(){
    print_cursor_grid();
    print_add_symbol(106,114);
    print_minus_symbol(106,123);
    print_ok();
    print_back();
    print_left_arrow(76,123, ST7735_WHITE);
    print_rigth_arrow(136,123, ST7735_WHITE);
}

void grid_keyboard(){
    print_cursor_grid();
    print_up_arrow(106,114, ST7735_WHITE);
    print_down_arrow(106,123, ST7735_WHITE);
    print_left_arrow(76,123, ST7735_WHITE);
    print_rigth_arrow(136,123, ST7735_WHITE);
    print_ok();
    drawtext(70,107, "DEL", ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_keyboard_dice_hash(){
    print_cursor_grid();
    print_left_arrow(76,123, ST7735_WHITE);
    print_rigth_arrow(136,123, ST7735_WHITE);
    print_ok();
    drawtext(70,107, "DEL", ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_bip85(){
    print_cursor_grid();
    print_up_arrow(106,114, ST7735_WHITE);
    print_down_arrow(106,123, ST7735_WHITE);
    print_left_arrow(76,123, ST7735_WHITE);
    print_rigth_arrow(136,123, ST7735_WHITE);
    print_ok();
    print_back();
}

void draw_mini_dice(int x, int y, int value) {
    // Draw the background of the dice filled with white
    rectan(x, y, x + 6, y + 6, ST7735_WHITE);

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
    draw_mini_dice(65, 107, 1);
    drawtext(74, 107, "=01", ST7735_WHITE, ST7735_BLACK, 1);

    draw_mini_dice(95, 107, 2);
    drawtext(104, 107, "=10", ST7735_WHITE, ST7735_BLACK, 1);

    draw_mini_dice(125, 107, 3);
    drawtext(134, 107, "=11", ST7735_WHITE, ST7735_BLACK, 1);

    // Row 2: Dice 4, 5, 6
    draw_mini_dice(68, 117, 4);
    drawtext(77, 117, "=0", ST7735_WHITE, ST7735_BLACK, 1);

    draw_mini_dice(98, 117, 5);
    drawtext(107, 117, "=1", ST7735_WHITE, ST7735_BLACK, 1);

    draw_mini_dice(125, 117, 6);
    drawtext(134, 117, "=00", ST7735_WHITE, ST7735_BLACK, 1);
}

void grid_coins(){              // Heads tails
    print_cursor_grid();
    drawtext(67,117, "HEAD", ST7735_WHITE, ST7735_WHITE, 1);
    drawtext(97,117, "TAIL", ST7735_WHITE, ST7735_WHITE, 1);
    // Added DEL button logic to grid representation for coins
    drawtext(70,107, "DEL", ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_OK_only(){
    print_cursor_grid();
    print_ok();
}

void version_display(){

    drawtext(5,117, cVersion, ST7735_WHITE, ST7735_WHITE, 1);    // Left of the button grid

}

// ============================================================================
// Generic Menu Renderer
// ============================================================================
// Title of a menu, from its table (the strings of other menus are reused);
// NULL for a menu without one
static const char *menu_title(const char* const *options) {
    if (options == menu_create)       return menu_main[cMAIN_create];
    if (options == menu_xor)          return menu_main[cMAIN_XOR];
    if (options == menu_sss)          return menu_main[cMAIN_SSS];
    if (options == menu_obfus)        return menu_main[cMAIN_OBFUS];
    if (options == menu_erase)        return menu_main[cMAIN_ERASESD];
    if (options == menu_resource)     return menu_main[cMAIN_QR];
    if (options == menu_addresses)    return menu_bip84[0];
    if (options == menu_bip84)        return "SINGLE SIG WALLET";
    if (options == menu_bip84_multi)  return "MULTISIG WALLET";
    if (options == menu_input)        return "LOAD SEED FROM";
    if (options == menu_size)         return "SEED SIZE";
    if (options == menu_dice)         return "DICE MODE";
    if (options == menu_hash)         return "DICE NUMBERING";
    return NULL;
}

void print_generic_menu(const char* const *options, int n_opt, int sel) {
    print_titled_menu(menu_title(options), options, n_opt, sel);
}

// Menu with a title on the top line (NULL: none) and the options below it
void print_titled_menu(const char *title, const char* const *options, int n_opt, int sel) {
    int top = 10;
    if (title != NULL) {
        drawtext(1, 1, (char*)title, ST7735_WHITE, ST7735_BLACK, 1);
        top = 13;
    }
    for (int i = 0; i < n_opt; i++) {
        uint16_t color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, top + i * 10, (char*)options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
}


void main_screen(int sel) {
    for (int i = 0; i < cMAIN_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 5 + i * 10, (char*)menu_main[i], color, ST7735_BLACK, 1);
    }
    if(SD_ready)drawtext(10, 118, "SD OK", ST7735_GREEN, ST7735_BLACK, 1);
    grid_menu1();
}

void u16_to_hex4(uint16_t value, char *buf) {
    static const char hex[] = "0123456789ABCDEF";
    buf[0] = hex[(value >> 12) & 0x0F];
    buf[1] = hex[(value >> 8) & 0x0F];
    buf[2] = hex[(value >> 4) & 0x0F];
    buf[3] = hex[value & 0x0F];
    buf[4] = '\0';
}

// Minimal base-10 itoa without dependencies
size_t u16_to_str(unsigned int n, char *buf) {
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

size_t u16_to_str_pad(unsigned int n, char *buf, unsigned int width) {
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

void draw_bip84_wrapped_text(const char *text, int x, int y,
                                    int line_length, int line_count)
{
    char line[32];
    size_t text_length = strlen(text);
    size_t offset = 0;

    for (int line_index = 0; line_index < line_count && offset < text_length; line_index++) {
        size_t remaining = text_length - offset;
        size_t copy_length = (remaining < (size_t)line_length) ? remaining : (size_t)line_length;

        memcpy(line, &text[offset], copy_length);
        line[copy_length] = '\0';
        drawtext(x, y + (line_index * 9), line, ST7735_WHITE, ST7735_BLACK, 1);
        offset += copy_length;
    }
}

// Button grid with a short text label (up to 4 characters) centered in each
// cell, NULL for a button that does nothing. Top row: BACK, UP, OK; bottom
// row: LEFT, DOWN, RIGHT.
void grid_labels(const char *back, const char *up, const char *ok,
                 const char *left, const char *down, const char *right) {
    const char *labels[6] = {back, up, ok, left, down, right};
    char text[6];

    print_cursor_grid();
    for (int i = 0; i < 6; i++) {
        if (labels[i] == NULL) continue;
        size_t n = strlen(labels[i]);
        if (n > 4) n = 4;
        memcpy(text, labels[i], n);
        text[n] = '\0';
        int x = GRID_X + (i % 3) * 30 + 1 + (29 - 6 * (int)n) / 2;
        drawtext(x, (i < 3) ? 107 : 117, text, ST7735_WHITE, ST7735_WHITE, 1);
    }
}

// BACK as the only action (cancel a running operation, leave an error)
void grid_back_only(void) {
    print_cursor_grid();
    print_back();
}

// BACK cancels, OK does 'ok_label' ("SIGN", "LOAD"...)
void grid_confirm(const char *ok_label) {
    grid_labels("BACK", NULL, ok_label, NULL, NULL, NULL);
}

// Pages: UP previous, DOWN next, OK does 'ok_label', BACK leaves
void grid_pager(const char *ok_label) {
    grid_labels("BACK", NULL, ok_label, NULL, NULL, NULL);
    print_up_arrow(106, 114, ST7735_WHITE);
    print_down_arrow(106, 123, ST7735_WHITE);
}

void grid_OK_back(void) {
    print_cursor_grid();
    print_ok();
    print_back();
}

// Button grid of the QR seed scan screen: BACK, and SCAN on the OK button
void grid_scan_back(void) {
    print_cursor_grid();
    print_back();
    drawtext(126, 107, "SCAN", ST7735_WHITE, ST7735_WHITE, 1);
}

void print_update_fw_warning(void) {
    black_screen();
    drawtext(20, 25, "SYSTEM UPDATE", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(10, 45, "1. INSERT SD CARD", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(10, 60, "   WITH UPDATE.HEX FILE", ST7735_WHITE, ST7735_BLACK, 1);    
    grid_OK_back();
}

uint8_t get_selected_card_index(void) {
    return (uint8_t)(card_suit_pointer * 13 + card_rank_pointer);
}

void draw_card_bit_counter(void) {
    char current_bits[4];
    char counter_text[16];
    const char *target_bit_count = (size_pointer == cSIZE_24) ? "256 bits" : "128 bits";

    u16_to_str_pad((unsigned int)bit_count_dice, current_bits, 3);
    memcpy(counter_text, current_bits, 3);
    counter_text[3] = '/';
    memcpy(&counter_text[4], target_bit_count, strlen(target_bit_count) + 1);
    drawtext(45, 15, counter_text, ST7735_WHITE, ST7735_BLACK, 1);

}

void draw_card_selection(void) {
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

void print_card_input_screen(void) {
    drawtext(1, 5, (size_pointer == cSIZE_24) ? "DRAW CARDS UP TO 256 BITS" : "DRAW CARDS UP TO 128 BITS", ST7735_WHITE, ST7735_BLACK, 1);
    draw_card_bit_counter();
    draw_card_selection();
    
    draw_shared_entropy_building();
    grid_keyboard();
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
    drawtext(1,5, "STOP TIMER TO SET ENTROPY", ST7735_WHITE, ST7735_BLACK, 1);
    char *text_TMR_SEED = size_TMR ? "000/256 bits" : "000/128 bits";
    drawtext(45,15, text_TMR_SEED, ST7735_WHITE, ST7735_BLACK, 1);
    grid_OK_only();
}

void print_child_config_screen(void) {
    drawtext(1, 1, (char*)menu_main[cMAIN_BIP85], ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(1, 13, "CHILD SIZE:", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(80, 13, "BIP85 INDEX:", ST7735_WHITE, ST7735_BLACK, 1);

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

void print_obfus_config_screen(void) {
    drawtext(1, 1, (char*)menu_obfus[obfuscation_pointer], ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(1, 13, "OPERATION:", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(100, 13, "AMOUNT:", ST7735_WHITE, ST7735_BLACK, 1);

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

void black_screen(){
    rectan(0,0,159,127,BLACK);
}

void white_screen(){
    rectan(0,0,159,127,WHITE);
}

void draw_seedqr(const char *text) {
    size_t length = strlen(text);
    int version;
    int ecc_level;
    
    // 12-word SeedQR = 48 numeric characters.
    // Version 2 at Q quality (25% recovery) supports EXACTLY up to 48 numbers.
    if (length <= 48) {
        version = 2;
        ecc_level = ECC_QUARTILE; 
    } 
    // 24-word SeedQR = 96 numeric characters.
    // We keep it at Version 3 at M quality (supports up to 101 numbers).
    else if (length <= 101) {
        version = 3;
        ecc_level = ECC_MEDIUM;   
    } else {
        // Safety check: abort if the text is longer than supported.
        return; 
    }

    // Dynamically allocate buffer based on the chosen version
    uint8_t qrcodeData[qrcode_getBufferSize(version)];
    QRCode qrcode;

    // Initialize the QR code with the dynamically chosen version and ECC level
    qrcode_initText(&qrcode, qrcodeData, version, ecc_level, text);

    int qr_size = qrcode.size;
    int img_size = qr_size * QR_SCALE;
    
    // Center the QR code on the screen
    int x_offset = (SCREEN_WIDTH - img_size) / 2;
    int y_offset = (SCREEN_HEIGHT - img_size) / 2;

    // 1. Draw the white background and the required 4-module "Quiet Zone"
    int margin = 4 * QR_SCALE; 
    fillRect(
        x_offset - margin, 
        y_offset - margin, 
        img_size + (2 * margin), 
        img_size + (2 * margin), 
        ST7735_WHITE
    );

    // 2. Iterate and draw ONLY the black modules for maximum SPI performance
    for (int y = 0; y < qr_size; y++) {
        for (int x = 0; x < qr_size; x++) {
            if (qrcode_getModule(&qrcode, x, y)) {
                fillRect(
                    x_offset + (x * QR_SCALE), 
                    y_offset + (y * QR_SCALE), 
                    QR_SCALE, 
                    QR_SCALE, 
                    ST7735_BLACK
                );
            }
        }
    }
}

void draw_url_qr(const char *text) {
    size_t length = strlen(text);
    int version;
    int ecc_level;

    // Screen size limits us to a maximum of Version 3 (29x29 modules).
    // Version 4 (33x33) and higher do not fit on the screen.
    
    if (length <= 26) {
        // Fits easily in Version 2 with good error correction
        version = 2; // 25x25 modules
        ecc_level = ECC_MEDIUM;
    } else if (length <= 42) {
        // Fits in Version 3 with good error correction
        version = 3; // 29x29 modules
        ecc_level = ECC_MEDIUM;
    } else if (length <= 53) {
        // Drop to ECC_LOW to squeeze up to 53 characters into Version 3
        version = 3; // 29x29 modules
        ecc_level = ECC_LOW;
    } else {
        // MAX LIMIT REACHED.
        // A string > 53 characters requires Version 4, which does not fit on screen.
        // Safety check: abort drawing to prevent visual glitches or memory issues.
        return; 
    }

    // Dynamically allocate buffer based on the required version
    uint8_t qrcodeData[qrcode_getBufferSize(version)];
    QRCode qrcode;

    // Initialize the QR code with the dynamically selected version and ECC level
    qrcode_initText(&qrcode, qrcodeData, version, ecc_level, text);

    int qr_size = qrcode.size;
    int img_size = qr_size * QR_SCALE;
    
    // Center the QR code on the screen
    int x_offset = (SCREEN_WIDTH - img_size) / 2;
    int y_offset = (SCREEN_HEIGHT - img_size) / 2;

    // 1. Draw the white background and the required 4-module "Quiet Zone"
    int margin = 4 * QR_SCALE; 
    fillRect(
        x_offset - margin, 
        y_offset - margin, 
        img_size + (2 * margin), 
        img_size + (2 * margin), 
        ST7735_WHITE
    );

    // 2. Iterate and draw ONLY the black modules for maximum SPI performance
    for (int y = 0; y < qr_size; y++) {
        for (int x = 0; x < qr_size; x++) {
            if (qrcode_getModule(&qrcode, x, y)) {
                fillRect(
                    x_offset + (x * QR_SCALE), 
                    y_offset + (y * QR_SCALE), 
                    QR_SCALE, 
                    QR_SCALE, 
                    ST7735_BLACK
                );
            }
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

// Draws text as a QR code of a fixed version, centered, painting every
// module (white and black). Frames of an animated QR therefore replace each
// other without clearing the screen, which avoids flicker. The caller paints
// the white quiet zone once. Returns false if the text does not fit.
bool draw_qr_frame(const char *text, uint8_t version, int scale) {
    uint8_t qrcodeData[qrcode_getBufferSize(version)];
    QRCode qrcode;

    if (qrcode_initText(&qrcode, qrcodeData, version, ECC_LOW, text) < 0) return false;

    int img_size = qrcode.size * scale;
    int x_offset = (SCREEN_WIDTH - img_size) / 2;
    int y_offset = (SCREEN_HEIGHT - img_size) / 2;

    for (int y = 0; y < qrcode.size; y++) {
        for (int x = 0; x < qrcode.size; x++) {
            fillRect(x_offset + x * scale, y_offset + y * scale, scale, scale,
                     qrcode_getModule(&qrcode, x, y) ? ST7735_BLACK : ST7735_WHITE);
        }
    }
    return true;
}

void draw_xpub_qr(const char *text) {
    white_screen();
    
    // Version 8 has 49x49 modules. With a scale of 2, it fits the 160x128 screen.
    int local_scale = 2; 

    // Dynamic buffer allocation for Version 8 (supports up to 132 bytes in ECC_LOW)
    uint8_t qrcodeData[qrcode_getBufferSize(8)];
    QRCode qrcode;

    // Initialize the QR code: Version 8, ECC_LOW (Level L)
    qrcode_initText(&qrcode, qrcodeData, 8, ECC_LOW, text);

    int qr_size = qrcode.size;
    int img_size = qr_size * local_scale;
    
    // Center the QR code on the screen
    int x_offset = (SCREEN_WIDTH - img_size) / 2;
    int y_offset = (SCREEN_HEIGHT - img_size) / 2;

    // Draw the white background and the required margin (Quiet Zone)
    int margin = 8 * local_scale; 
    fillRect(
        x_offset - margin, 
        y_offset - margin, 
        img_size + (2 * margin), 
        img_size + (2 * margin), 
        ST7735_WHITE
    );

    // Iterate and draw ONLY the black modules to maximize SPI performance
    for (int y = 0; y < qr_size; y++) {
        for (int x = 0; x < qr_size; x++) {
            if (qrcode_getModule(&qrcode, x, y)) {
                fillRect(
                    x_offset + (x * local_scale), 
                    y_offset + (y * local_scale), 
                    local_scale, 
                    local_scale, 
                    ST7735_BLACK
                );
            }
        }
    }
}

void show_word_list_retry_error(void) {
    black_screen();
    drawtext(10,10, INCORRECT_MSG, ST7735_RED, ST7735_BLACK, 1);
    drawtext(10,25, "ANY BUTTON: TRY AGAIN", ST7735_WHITE, ST7735_BLACK, 1);
    grid_OK_back();
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

    // FIX: Iterate through lowercase letters
    for (letra = 'a'; letra <= 'z'; letra++) {
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

void update_dice_bit_count_display(int bit_count_dice_local){
    char bit_count_text[4]; // 3 digits plus null terminator
    u16_to_str_pad((unsigned int)bit_count_dice_local, bit_count_text, 3);
    drawtext(45,15, bit_count_text, ST7735_WHITE, ST7735_BLACK, 1);
}

 void   print_logo(){
    drawtext(10,10, "SEEDMATE", ST7735_WHITE, ST7735_BLACK, 3);
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

    draw_seedqr(text_buf);
    print_camera(2,50,cNOTSAFE);
    print_camera(2,80,cNOTSAFE);
    print_camera(145,50,cNOTSAFE);
    print_camera(145,80,cNOTSAFE);
    print_left_arrow_black(5,123);
}

void print_word_number_top(int word_number, char *word_number_text) {
    if (capturing_xor_word) {
        rectan(10, 10, 59, 18, BLACK); // Clear header area
        drawtext(5, 10, "XOR WORD:", ST7735_WHITE, ST7735_BLACK, 1);
        return; // Abort standard drawing
    }
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

void print_selkn_screen(int k, int n, int sel){
    char k_text[3];
    char n_text[3];
    drawtext(1, 1, "SHAMIR SPLIT", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(10,15, "SELECT ( K , N ):", ST7735_WHITE, ST7735_BLACK, 1);
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
    drawtext(1, 1, "SHAMIR MERGE", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(0,15, "N. OF SHARES NEEDED (K):", ST7735_WHITE, ST7735_BLACK, 1);
    u16_to_str((unsigned int)k, k_text);
    drawtext(70,30, k_text, ST7735_ORANGE, ST7735_BLACK, 2);
    grid_nbits();

}

void print_sel_share_screen(int k){
    char k_text[3];
    drawtext(0,15, "SHARE ID:", ST7735_WHITE, ST7735_BLACK, 1);
    u16_to_str((unsigned int)k, k_text);
    drawtext(70,30, k_text, ST7735_ORANGE, ST7735_BLACK, 2);
    grid_nbits_noback();

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

void print_settings_screen(int sel) {
    char* text_seedqr = seedqr_enabled ? "SeedQR ON " : "SeedQR OFF";
    uint16_t color_seedqr = (sel == cSETTINGS_SEEDQR) ? ST7735_ORANGE : ST7735_WHITE;
    
    drawtext(1, 1, (char*)menu_main[cMAIN_SETTINGS], ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(1, 13, text_seedqr, color_seedqr, ST7735_BLACK, 1);

    uint16_t color_serial = (sel == cSETTINGS_MCU_SERIAL) ? ST7735_ORANGE : ST7735_WHITE;
    drawtext(1, 23, "MCU SERIAL NUMBER", color_serial, ST7735_BLACK, 1);
    
    uint16_t color_fw = (sel == cSETTINGS_UPDATE_FW) ? ST7735_ORANGE : ST7735_WHITE;
    drawtext(1, 33, "UPDATE FIRMWARE", color_fw, ST7735_BLACK, 1);
    
    grid_menu2(); 
}

void print_seedqr_warning(void) {
    rectan(0, 0, 159, 127, ST7735_RED); 
    drawtext(20, 30, "SeedQR = seed phrase", ST7735_WHITE, ST7735_RED, 1);
    drawtext(50, 45, "DO NOT SCAN", ST7735_WHITE, ST7735_RED, 1);
    drawtext(50, 60, "WITH PHONE", ST7735_WHITE, ST7735_RED, 1);    
    grid_OK_only(); 
    
}

void print_mcu_serial_screen(void) {
    char hex_buf[5];
    uint16_t parts[4];
    int x_pos = 20;

    black_screen();
    drawtext(10, 30, "MCU SERIAL NUMBER:", ST7735_WHITE, ST7735_BLACK, 1);
    
    // The PIC32MM uses UDID1 to UDID4. We extract 64 bits using UDID2 and UDID1.
    parts[0] = (uint16_t)((UDID2 >> 16) & 0xFFFF);
    parts[1] = (uint16_t)(UDID2 & 0xFFFF);
    parts[2] = (uint16_t)((UDID1 >> 16) & 0xFFFF);
    parts[3] = (uint16_t)(UDID1 & 0xFFFF);
    
    // Draw the chunks consecutively
    for (int i = 0; i < 4; i++) {
        u16_to_hex4(parts[i], hex_buf);
        drawtext(x_pos, 60, hex_buf, ST7735_CYAN, ST7735_BLACK, 1);
        x_pos += 26; // Advance cursor (4 chars * 6px + 2px spacing)
    }
    
    grid_OK_only();
}

void print_card_encoding_screen(void) {
    black_screen();
    drawtext(1, 2, "MNEMONIC TO CARDS", ST7735_WHITE, ST7735_BLACK, 1);
    
    char decks_str[30] = "DECKS NEEDED: ";
    char num[4];
    size_t len = u16_to_str((unsigned int)card_decks_needed, num);
    int pos = 14; // Length of "DECKS NEEDED: "
    
    for (size_t i = 0; i < len; i++) {
        decks_str[pos++] = num[i];
    }
    decks_str[pos] = '\0';
    drawtext(1, 12, decks_str, ST7735_GREEN, ST7735_BLACK, 1);
    
    int cards_per_page = 32; // 8 per line, 4 lines 
    int start_idx = card_view_page * cards_per_page;
    
    int x = 5;
    int y = 28;
    
    for (int i = start_idx; i < card_sequence_len && i < start_idx + cards_per_page; i++) {
        int card_idx = card_sequence[i];
        char card_str[3];
        
        char rank = card_rank_chars[card_idx % 13];
        if (rank >= 'a' && rank <= 'z') rank -= 32; // uppercase
        
        char suit = card_suit_chars[card_idx / 13];
        if (suit >= 'a' && suit <= 'z') suit -= 32; // uppercase
        
        card_str[0] = rank;
        card_str[1] = suit;
        card_str[2] = '\0';
        
        uint16_t color = ST7735_WHITE;
        if ((card_idx / 13) == 1 || (card_idx / 13) == 2) color = ST7735_RED; // Diamonds/Hearts 
        
        drawtext(x, y, card_str, color, ST7735_BLACK, 1);
        x += 20;
        if (x > 145) {
            x = 5;
            y += 18;
        }
    }
    
    // BACK leaves; UP/DOWN only when there is another page
    print_cursor_grid();
    print_back();
    if (card_view_page > 0) print_up_arrow(106, 114, ST7735_WHITE);
    if (start_idx + cards_per_page < card_sequence_len) print_down_arrow(106, 123, ST7735_WHITE);
}
