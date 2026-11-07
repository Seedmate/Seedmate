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
#include "SPI.h"                            // delay_ms()

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
// Names by function id (cMAIN_*), not by position in the menus
const char* const menu_main[]     = {"CREATE NEW SEED WORDS", "LOAD SEED WORDS", "BIP85 CHILD SEED", "SHAMIR SECRET SHARE", "SEED WORD XOR", "OBFUSCATION", "MNEMONIC TO CARDS", "SD CARD", "RESOURCES", "SETTINGS", "OPSEC", "TOOLS"};
const uint8_t main_menu_ids[cMAIN_n_opt] = {cMAIN_create, cMAIN_LOAD, cMAIN_BIP85, cMAIN_OPSEC, cMAIN_TOOLS, cMAIN_ERASESD, cMAIN_QR, cMAIN_SETTINGS};
const char* const menu_opsec[]    = {"SHAMIR SECRET SHARE", "SEED WORD XOR", "OBFUSCATION", "MNEMONIC TO CARDS"};
const uint8_t opsec_menu_ids[cOPSEC_n_opt] = {cMAIN_SSS, cMAIN_XOR, cMAIN_OBFUS, cMAIN_MNEM2CARD};
const char* const menu_tools[]    = {"QR READER", "QR FROM TEXT", "EFF PASSWORD", "REVIEW PSBT"};
const char* const menu_backup[]   = {"SD", "SEEDQR", "COMPACT SEEDQR", "VERIFY TRANSCRIPT"};
const char* const menu_passphrase[] = {"FROM KEYBOARD", "FROM QR", "FROM VAULT"};
const char* const menu_create[]   = {"THROW COINS", "ROLL DICE", "RANDOM WORD PICK", "POKER CARDS", "TRIPLE MNEMONIC", "STOPWATCH TEST ONLY"};
const char* const menu_dice[]     = {"RAW ENTROPY BITS", "STRING HASH"};
const char* const menu_hash[]     = {"1-6 MODE", "0-5 MODE (KEYSTONE)"};
const char* const menu_size[]     = {"12 WORDS", "24 WORDS"};
const char* const menu_qr[]       = {"STANDARD", "COMPACT"};
const char* const menu_xor[]      = {"A XOR B = C", "A XOR B XOR C = D", "A XOR B XOR C XOR D = E"};
const char* const menu_sss[]      = {"SPLIT", "MERGE"};
const char* const menu_resource[] = {"TUTORIAL", "BACKUP TOOL", "DICE TESTER", "PRINT WORDLIST", "BINARY WORDLIST", "SECURITY"};
const char* const menu_obfus[]    = {"CIRCULAR SHIFT", "NOT OPERATOR", "WORDS ADD/SUB","1 WORD XOR","BYTE SWAP","HOW TO"};
const char* const menu_erase[]    = {"ERASE SECTOR", "INITIALIZE CARD", "WIPE ALL CARD"};
const char* const menu_bip84[] = {"SIGN", "ADD PASSPHRASE", "DERIVE", "VAULT", "XPUB/ZPUB", "ADDRESSES", "CONFIG", "UNLOAD SEED"};
const char* const menu_addresses[] = {"RECEIVE ADDRESS", "CHANGE ADDRESS", "SCAN ADDRESS"};
const char* const menu_bip84_multi[] = {"SIGN", "ADD PASSPHRASE", "DERIVE", "VAULT", "XPUB/ZPUB", "IMPORT DESCRIPTOR", "CONFIG", "UNLOAD SEED"};
const char* const menu_sign[]     = {"FROM QR", "FROM SD"};
const char* const menu_import[]   = {"FROM QR", "FROM SD", "FROM VAULT"};
const char* const menu_input[]    = {"FROM KEYBOARD", "FROM SD", "FROM QR"};

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
    drawtext(127,117, "TAIL", ST7735_WHITE, ST7735_WHITE, 1);
    grid_del_back_label(false);     // The screen starts with nothing entered
}

// What BACK does on an entry screen: deletes the last input, or leaves when none is left
void grid_del_back_label(bool can_delete) {
    rectan(64, 106, 92, 114, ST7735_BLACK);
    drawtext(can_delete ? 70 : 67, 107, can_delete ? "DEL" : "BACK", ST7735_WHITE, ST7735_WHITE, 1);
}

void grid_OK_only(){
    print_cursor_grid();
    print_ok();
}

// Title on the top line, centered (light gray; red or green on error or
// success screens)
void draw_title(const char *text, uint16_t color) {
    int x = (SCREEN_WIDTH - 6 * (int)strlen(text)) / 2;
    drawtext(x < 0 ? 0 : x, 1, (char *)text, color, ST7735_BLACK, 1);
}

// Two-part title (e.g. "INPUT 1/3" and the script type), centered as one
void draw_title_pair(const char *a, uint16_t color_a, const char *b, uint16_t color_b) {
    int len_a = (int)strlen(a);
    int len_b = (int)strlen(b);
    int x = (SCREEN_WIDTH - 6 * (len_a + (len_b > 0 ? 1 + len_b : 0))) / 2;
    if (x < 0) x = 0;
    drawtext(x, 1, (char *)a, color_a, ST7735_BLACK, 1);
    if (len_b > 0) drawtext(x + 6 * (len_a + 1), 1, (char *)b, color_b, ST7735_BLACK, 1);
}

void version_display(){
    // Bottom right of the start screen
    drawtext(SCREEN_WIDTH - 1 - 6 * (int)strlen(cVersion), 119, cVersion, ST7735_CYAN, ST7735_BLACK, 1);
}

// ============================================================================
// Generic Menu Renderer
// ============================================================================
// Title of a menu, from its table (the strings of other menus are reused);
// NULL for a menu without one
static const char *menu_title(const char* const *options) {
    if (options == menu_create)       return menu_main[cMAIN_create];
    if (options == menu_opsec)        return menu_main[cMAIN_OPSEC];
    if (options == menu_tools)        return menu_main[cMAIN_TOOLS];
    if (options == menu_backup)       return "SEED BACKUP (SD/QR)";
    if (options == menu_passphrase)   return "PASSPHRASE FROM";
    if (options == menu_xor)          return menu_main[cMAIN_XOR];
    if (options == menu_sss)          return menu_main[cMAIN_SSS];
    if (options == menu_obfus)        return menu_main[cMAIN_OBFUS];
    if (options == menu_erase)        return menu_main[cMAIN_ERASESD];
    if (options == menu_resource)     return menu_main[cMAIN_QR];
    if (options == menu_addresses)    return menu_bip84[5];
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
        draw_title((char*)title, ST7735_LIGHTGREY);
        top = 13;
    }
    for (int i = 0; i < n_opt; i++) {
        uint16_t color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, top + i * 10, (char*)options[i], color, ST7735_BLACK, 1);
    }
    grid_menu2();
}


void main_screen(int sel) {
    draw_title("SEEDMATE", ST7735_LIGHTGREY);
    for (int i = 0; i < cMAIN_n_opt; i++) {
        uint color = (i == sel) ? ST7735_ORANGE : ST7735_WHITE;
        drawtext(1, 13 + i * 10, (char*)menu_main[main_menu_ids[i]], color, ST7735_BLACK, 1);
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

// Rows of options: UP / DOWN the row, LEFT and RIGHT named by what they do on it
// (NULL: nothing there). Only those cells and OK are cleared when called again.
void grid_rows_keys(const char *left, const char *right, const char *ok) {
    rectan(64, 116, 92, 124, ST7735_BLACK);
    rectan(124, 116, 152, 124, ST7735_BLACK);
    rectan(124, 106, 152, 114, ST7735_BLACK);
    grid_labels("BACK", NULL, ok, left, NULL, right);
    print_up_arrow(106, 114, ST7735_WHITE);
    print_down_arrow(106, 123, ST7735_WHITE);
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
    draw_title("SYSTEM UPDATE", ST7735_LIGHTGREY);
    drawtext(10, 45, "1. INSERT SD CARD", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(10, 60, "   WITH UPDATE.HEX AND", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(10, 75, "   UPDATE.SIG FILES", ST7735_WHITE, ST7735_BLACK, 1);
    grid_confirm("UPDT");
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
    draw_title((size_pointer == cSIZE_24) ? "DRAW CARDS UP TO 256 BITS" : "DRAW CARDS UP TO 128 BITS", ST7735_LIGHTGREY);
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
            draw_title(text_coins, ST7735_LIGHTGREY);
            grid_coins();
        } else {
            draw_title(text_dices, ST7735_LIGHTGREY);
            grid_dices();
            draw_dice_back_hint(false);     // The screen starts with no rolls
        }
        drawtext(45,15, text_bits, ST7735_WHITE, ST7735_BLACK, 1);
        draw_shared_entropy_building();
}

// Holding BACK cannot be shown in the grid, where BACK is a die face: a note at its left
void draw_dice_back_hint(bool can_delete) {
    drawtext(1, 107, "HOLD BACK", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(1, 117, can_delete ? "TO DELETE" : "TO LEAVE ", ST7735_WHITE, ST7735_BLACK, 1);
}

void print_TMR_screen(int size_TMR){

    // sel: 0 -> 128 bits, 1 -> 256 bits
    draw_title("STOP TIMER TO SET ENTROPY", ST7735_LIGHTGREY);
    char *text_TMR_SEED = size_TMR ? "000/256 bits" : "000/128 bits";
    drawtext(45,15, text_TMR_SEED, ST7735_WHITE, ST7735_BLACK, 1);
    grid_labels(NULL, NULL, "STOP", NULL, NULL, NULL);
}

void print_child_config_screen(void) {
    draw_title((char*)menu_main[cMAIN_BIP85], ST7735_LIGHTGREY);
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
    draw_title((char*)menu_obfus[obfuscation_pointer], ST7735_LIGHTGREY);
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
    grid_labels(NULL, NULL, "TRY", NULL, NULL, NULL);     // Any key tries again
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

// ============================================================================
// Start screen: the logo (web/img/logo.png) built from its 6 rectangles
// ============================================================================

// The logo is two interlocking S halves, each three bars. Scaled from the
// 432 px square of logo.png to LOGO_SIZE: bars 16 / 7 px, gaps 6 px.
// Coordinates relative to the logo's top left corner, inclusive.
#define LOGO_SIZE       64
#define LOGO_X          ((SCREEN_WIDTH - LOGO_SIZE) / 2)
#define LOGO_Y          10
#define LOGO_ORANGE     0xEC27      // #E8873D, the logo's own color (brand, this screen only)
#define LOGO_FRAMES     26
#define LOGO_TRAVEL     (LOGO_X + LOGO_SIZE)    // From fully outside the screen to the middle

typedef struct { int8_t x0, y0, x1, y1; } logo_rect_t;
static const logo_rect_t logo_left[3] = {   // Slides in from the left
    {0, 0, 63, 15}, {0, 0, 10, 41}, {0, 35, 46, 41}
};
static const logo_rect_t logo_right[3] = {  // Slides in from the right
    {0, 48, 63, 63}, {53, 22, 63, 63}, {17, 22, 63, 28}
};

// rectan() clipped to the screen (the pieces start outside it)
static void fill_clipped(int x0, int y0, int x1, int y1, uint16_t color) {
    if (x0 < 0) x0 = 0;
    if (x1 > SCREEN_WIDTH - 1) x1 = SCREEN_WIDTH - 1;
    if (x0 > x1 || y0 > y1) return;
    rectan((unsigned char)x0, (unsigned char)y0, (unsigned char)x1, (unsigned char)y1, color);
}

// Moves a piece from x 'from' to x 'to': the strip it leaves is cleared and
// the bars are drawn at the new place (no full redraw, no flicker). The two
// pieces never cross while they approach, so a cleared strip is always the
// piece's own.
static void logo_piece_move(const logo_rect_t *r, int from, int to) {
    for (int i = 0; i < 3; i++) {
        int y0 = LOGO_Y + r[i].y0, y1 = LOGO_Y + r[i].y1;
        if (to > from) fill_clipped(from + r[i].x0, y0, to + r[i].x0 - 1, y1, ST7735_BLACK);
        else if (to < from) fill_clipped(to + r[i].x1 + 1, y0, from + r[i].x1, y1, ST7735_BLACK);
        fill_clipped(to + r[i].x0, y0, to + r[i].x1, y1, LOGO_ORANGE);
    }
}

// Black screen, the two halves slide in from the sides and lock in the middle
// (ease out), then the name, the prompt below the logo and the firmware
// version at the bottom right. The start screen has no button grid on purpose.
void print_logo(void) {
    int left = LOGO_X - LOGO_TRAVEL, right = LOGO_X + LOGO_TRAVEL;

    black_screen();
    for (int f = 1; f <= LOGO_FRAMES; f++) {
        // Distance still to go: travel * (1 - t)^3, so the pieces slow down as they meet
        int rest = LOGO_FRAMES - f;
        int off = (int)((long)LOGO_TRAVEL * rest * rest * rest / ((long)LOGO_FRAMES * LOGO_FRAMES * LOGO_FRAMES));
        logo_piece_move(logo_left, left, LOGO_X - off);
        logo_piece_move(logo_right, right, LOGO_X + off);
        left = LOGO_X - off;
        right = LOGO_X + off;
        delay_ms(20);
    }
    delay_ms(250);
    drawtext((SCREEN_WIDTH - 6 * 15) / 2, LOGO_Y + LOGO_SIZE + 8, "S E E D M A T E", ST7735_WHITE, ST7735_BLACK, 1);
    delay_ms(250);
    drawtext((SCREEN_WIDTH - 6 * 16) / 2, LOGO_Y + LOGO_SIZE + 26, "PRESS ANY BUTTON", ST7735_WHITE, ST7735_BLACK, 1);
    version_display();
}

// Text of a SeedQR: the 4 digit index of every word. data is the entropy plus
// the checksum byte, as append_checksum() returns it.
static void seedqr_text(const unsigned char *data, size_t size, char *text, size_t cap) {
    unsigned int group = 0;
    int bits = 0;
    size_t len = 0;

    for (size_t i = 0; i < size * 8; i++) {
        group = (group << 1) | (((unsigned int)data[i / 8] >> (7 - (i % 8))) & 1u);
        if (++bits == 11) {
            if (len + 5 > cap) break;
            len += u16_to_str_pad(group & 0x7FFu, &text[len], 4);
            group = 0;
            bits = 0;
        }
    }
    text[len] = '\0';
}

// Builds the QR of the seed: SeedQR (4 digits per word, version 2 for 12
// words and 3 for 24) or CompactSeedQR (the entropy bytes, binary mode)
static bool seed_qr_make(QRCode *qr, uint8_t *modules, const unsigned char *data, size_t size, bool compact) {
    char text[98];
    size_t len;

    if (compact) {
        return qrcode_initBytes(qr, modules, (size == 17) ? 1 : 2, ECC_LOW,
                                (uint8_t *)data, (uint16_t)(size - 1)) >= 0;
    }
    seedqr_text(data, size, text, sizeof(text));
    len = strlen(text);
    if (len <= 48) return qrcode_initText(qr, modules, 2, ECC_QUARTILE, text) >= 0;
    return len <= 101 && qrcode_initText(qr, modules, 3, ECC_MEDIUM, text) >= 0;
}

// Tiles per side of the zoomed view of a QR of n modules: at most 15 modules
// per tile side (7 px or more each), neighbouring tiles share one module
static int qr_tiles_per_side(int n) {
    return (n + 12) / 14;
}

// Draws a QR on the white screen: whole (tile < 0, the largest scale up to
// QR_SCALE that fits) or one zoomed tile (row major) with grid lines and the
// row / column numbers every 5 modules, to copy it by hand. Returns the
// number of tiles per side.
static int draw_qr_view(QRCode *qr, int tile) {
    int n = qr->size;
    int per = qr_tiles_per_side(n);
    char num[6];

    if (tile < 0) {
        int scale = SCREEN_HEIGHT / (n + 2);
        if (scale > QR_SCALE) scale = QR_SCALE;
        int x0 = (SCREEN_WIDTH - n * scale) / 2;
        int y0 = (SCREEN_HEIGHT - n * scale) / 2;
        for (int y = 0; y < n; y++) {
            for (int x = 0; x < n; x++) {
                if (qrcode_getModule(qr, x, y)) {
                    fillRect(x0 + x * scale, y0 + y * scale, scale, scale, ST7735_BLACK);
                }
            }
        }
        return per;
    }

    int t = (n - 1 + per - 1) / per + 1;        // Modules per tile side
    int gx = (tile % per) * (t - 1);
    int gy = (tile / per) * (t - 1);
    if (gx > n - t) gx = n - t;
    if (gy > n - t) gy = n - t;
    int scale = 118 / t;
    int x0 = 14;                                // Room for the row numbers
    int y0 = 10;                                // Room for the column numbers

    for (int j = 0; j < t; j++) {
        for (int i = 0; i < t; i++) {
            if (qrcode_getModule(qr, gx + i, gy + j)) {
                fillRect(x0 + i * scale, y0 + j * scale, scale, scale, ST7735_BLACK);
            }
        }
    }
    for (int k = 0; k <= t; k++) {              // Grid lines to count modules
        drawFastVLine(x0 + k * scale, y0, t * scale + 1, ST7735_GREY);
        drawFastHLine(x0, y0 + k * scale, t * scale + 1, ST7735_GREY);
    }
    for (int k = 0; k < t; k++) {               // Numbers every 5 modules
        if ((gx + k) % 5 == 0) {
            u16_to_str((unsigned int)(gx + k), num);
            drawtext(x0 + k * scale + (scale - 6 * (int)strlen(num)) / 2, 1, num, ST7735_BLACK, ST7735_WHITE, 1);
        }
        if ((gy + k) % 5 == 0) {
            u16_to_str((unsigned int)(gy + k), num);
            drawtext(1, y0 + k * scale + (scale - 7) / 2, num, ST7735_BLACK, ST7735_WHITE, 1);
        }
    }
    return per;
}

// Seed QR on the screen (data and size as in seedqr_text()), whole or one
// zoomed tile. Returns the tiles per side (0 if the QR could not be built).
int draw_seed_qr_view(const unsigned char *data, size_t size, bool compact, int tile) {
    uint8_t modules[qrcode_getBufferSize(3)];
    QRCode qr;

    white_screen();
    if (!seed_qr_make(&qr, modules, data, size, compact)) {
        drawtext(1, 50, "QR ERROR", ST7735_RED, ST7735_WHITE, 1);
        return 0;
    }
    int per = draw_qr_view(&qr, tile);
    if (tile < 0) {
        print_camera(2, 50, cNOTSAFE);
        print_camera(2, 80, cNOTSAFE);
        print_camera(145, 50, cNOTSAFE);
        print_camera(145, 80, cNOTSAFE);
    }
    return per;
}

// Data codewords of versions 1..11 at error correction L and M (ISO 18004)
static const uint16_t qr_data_bytes[2][11] = {
    {19, 34, 55, 80, 108, 136, 156, 194, 232, 274, 324},    // L
    {16, 28, 44, 64, 86, 108, 124, 154, 182, 216, 254},     // M
};

// Bits the QR library needs for text in a version (it picks numeric,
// alphanumeric or byte mode from the content); the library does not check
// the capacity itself
static uint32_t text_qr_bits(const char *text, int version) {
    uint32_t len = (uint32_t)strlen(text);
    bool numeric = true, alnum = true;
    int range = (version < 10) ? 0 : 1;         // Character count width changes at version 10

    for (uint32_t i = 0; i < len; i++) {
        char c = text[i];
        if (c < '0' || c > '9') numeric = false;
        if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || strchr(" $%*+-./:", c) != NULL)) alnum = false;
    }
    if (numeric) return 4 + (range ? 12 : 10) + 10 * (len / 3) + ((len % 3) == 2 ? 7 : (len % 3) == 1 ? 4 : 0);
    if (alnum) return 4 + (range ? 11 : 9) + 11 * (len / 2) + 6 * (len % 2);
    return 4 + (range ? 16 : 8) + 8 * len;
}

// QR of a text (QR FROM TEXT), whole or one zoomed tile: the smallest version
// up to 11 with error correction M, or L if M does not fit (more robust for a
// QR copied by hand). Returns the tiles per side, 0 if the text does not fit.
int draw_text_qr_view(const char *text, int tile) {
    uint8_t modules[qrcode_getBufferSize(11)];
    QRCode qr;

    white_screen();
    for (int level = 1; level >= 0; level--) {  // 1 = M, 0 = L
        for (int v = 1; v <= 11; v++) {
            if (text_qr_bits(text, v) <= 8u * qr_data_bytes[level][v - 1]) {
                qrcode_initText(&qr, modules, (uint8_t)v, level ? ECC_MEDIUM : ECC_LOW, text);
                return draw_qr_view(&qr, tile);
            }
        }
    }
    drawtext(1, 50, "TEXT TOO LONG", ST7735_RED, ST7735_WHITE, 1);
    return 0;
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
    draw_title("SHAMIR SPLIT", ST7735_LIGHTGREY);
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
    draw_title("SHAMIR MERGE", ST7735_LIGHTGREY);
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
    char title[24] = "SELECT SLOT";
    switch (main_pointer) {
        case cMAIN_XOR:
        {
            char xor_lbl[] = " FOR XOR A";
            xor_lbl[9] = 'A' + xor_merge_words_available;
            strcat(title, xor_lbl);
            break;
        }
        case cMAIN_ERASESD:
            strcat(title, " TO ERASE");
            break;
        default:
            strcat(title, " TO READ");
            break;
    }
    draw_title(title, ST7735_LIGHTGREY);
    print_slots(sel);

    print_SD_preview();
    grid_menuSD();
}

void sel_sd_block_screen_wr(int sel) {

    draw_title("SELECT SLOT TO WRITE", ST7735_LIGHTGREY);
    // Paint 8 lines "SLOT <num>"
    print_slots(sel);
    if (SD_page == 0) drawtext(70, 20, "READ ONLY", ST7735_GREY, ST7735_BLACK, 1);     // Legacy slot
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
    char* text_seedqr = seedqr_enabled ? "SEEDQR ON " : "SEEDQR OFF";
    char* text_sdwrite = sdwrite_enabled ? "SD SEED SAVE ON " : "SD SEED SAVE OFF";
    char* text_decoy = decoy_enabled ? "DECOY GAME ON " : "DECOY GAME OFF";
    char* text_stopwatch = stopwatch_enabled ? "STOPWATCH SEED ON " : "STOPWATCH SEED OFF";
    uint16_t color_seedqr = (sel == cSETTINGS_SEEDQR) ? ST7735_ORANGE : ST7735_WHITE;
    uint16_t color_sdwrite = (sel == cSETTINGS_SDWRITE) ? ST7735_ORANGE : ST7735_WHITE;
    uint16_t color_decoy = (sel == cSETTINGS_DECOY) ? ST7735_ORANGE : ST7735_WHITE;
    uint16_t color_stopwatch = (sel == cSETTINGS_STOPWATCH) ? ST7735_ORANGE : ST7735_WHITE;
    uint16_t color_serial = (sel == cSETTINGS_MCU_SERIAL) ? ST7735_ORANGE : ST7735_WHITE;
    uint16_t color_fw = (sel == cSETTINGS_UPDATE_FW) ? ST7735_ORANGE : ST7735_WHITE;

    draw_title((char*)menu_main[cMAIN_SETTINGS], ST7735_LIGHTGREY);
    drawtext(1, 13, text_seedqr, color_seedqr, ST7735_BLACK, 1);
    drawtext(1, 23, text_sdwrite, color_sdwrite, ST7735_BLACK, 1);
    drawtext(1, 33, text_decoy, color_decoy, ST7735_BLACK, 1);
    drawtext(1, 43, text_stopwatch, color_stopwatch, ST7735_BLACK, 1);
    drawtext(1, 53, "MCU SERIAL NUMBER", color_serial, ST7735_BLACK, 1);
    drawtext(1, 63, "UPDATE FIRMWARE", color_fw, ST7735_BLACK, 1);

    // Versions at the bottom left, next to the button grid: this firmware and
    // the bootloader, whose tag it keeps at a fixed boot flash address
    // ("BOOT 1.0"; an older bootloader has none)
    char text[16];
    const char *tag = (const char *)BOOT_TAG_ADDRESS;
    strcpy(text, "FW ");
    strcat(text, cVersion);
    drawtext(5, 107, text, ST7735_CYAN, ST7735_BLACK, 1);
    strcpy(text, "BOOT ");
    if (memcmp(tag, "BOOT ", 5) == 0 && tag[15] == 0) strcat(text, tag + 5);
    else strcat(text, "?");
    drawtext(5, 117, text, ST7735_CYAN, ST7735_BLACK, 1);

    grid_menu2();
}

// Red warning before a SeedQR is enabled or shown; BACK cancels, OK does ok_label
void print_seedqr_warning(const char *ok_label) {
    rectan(0, 0, 159, 127, ST7735_RED);
    drawtext(1, 10, "SEEDQR EQUALS YOUR SEED", ST7735_WHITE, ST7735_RED, 1);
    drawtext(1, 25, "DO NOT SCAN WITH A PHONE", ST7735_WHITE, ST7735_RED, 1);
    drawtext(1, 40, "DO NOT TAKE PHOTOS", ST7735_WHITE, ST7735_RED, 1);
    drawtext(1, 55, "KEEP IT OFFLINE", ST7735_WHITE, ST7735_RED, 1);
    grid_confirm(ok_label);
}

// Yellow warning before a seed is written to the SD card (or the setting that
// allows it is enabled); BACK cancels, OK does ok_label
void print_sd_warning(const char *ok_label) {
    black_screen();
    drawtext(1, 10, "SEED ON SD: NOT ENCRYPTED", ST7735_YELLOW, ST7735_BLACK, 1);
    drawtext(1, 25, "ERASE IT AFTER USE, OR", ST7735_YELLOW, ST7735_BLACK, 1);
    drawtext(1, 40, "KEEP IT APART FROM THIS", ST7735_YELLOW, ST7735_BLACK, 1);
    drawtext(1, 55, "DEVICE, NEVER IN A PC", ST7735_YELLOW, ST7735_BLACK, 1);
    grid_confirm(ok_label);
}

// A function that is not available, and why (red title, the reason below)
void print_blocked(const char *l1, const char *l2, const char *l3) {
    black_screen();
    drawtext(1, 20, (char*)l1, ST7735_RED, ST7735_BLACK, 1);
    drawtext(1, 40, (char*)l2, ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(1, 50, (char*)l3, ST7735_WHITE, ST7735_BLACK, 1);
    grid_OK_back();
}

// The slot chosen for writing already holds a seed
void print_slot_in_use(int slot) {
    char text[20];
    black_screen();
    strcpy(text, "SLOT ");
    u16_to_str((unsigned int)slot, &text[5]);
    strcat(text, " IS IN USE");
    drawtext(1, 10, text, ST7735_RED, ST7735_BLACK, 1);
    drawtext(1, 30, "THE CURRENT SEED WILL BE", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(1, 40, "LOST IF YOU OVERWRITE IT", ST7735_WHITE, ST7735_BLACK, 1);
    grid_confirm("OVER");
}

// Red warning before the first 1 MB of the card is erased and it is marked as
// ready for seeds (INITIALIZE CARD); BACK cancels
void print_sd_init_warning(void) {
    black_screen();
    draw_title((char*)menu_erase[cERASE_INIT], ST7735_LIGHTGREY);
    drawtext(1, 14, "ERASES THE FIRST 1 MB OF", ST7735_RED, ST7735_BLACK, 1);
    drawtext(1, 24, "THE CARD: ALL SEEDS, THE", ST7735_RED, ST7735_BLACK, 1);
    drawtext(1, 34, "VAULT AND THE FILE SYSTEM", ST7735_RED, ST7735_BLACK, 1);
    drawtext(1, 44, "(FORMAT). CANNOT BE UNDONE", ST7735_RED, ST7735_BLACK, 1);
    drawtext(1, 62, "THEN THE CARD ACCEPTS", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(1, 72, "SEEDS FROM THIS DEVICE", ST7735_WHITE, ST7735_BLACK, 1);
    grid_confirm("INIT");
}

// Red warning before the whole card is overwritten (WIPE ALL CARD); BACK cancels
void print_sd_wipe_warning(uint32_t mb_total) {
    char text[24];
    black_screen();
    draw_title((char*)menu_erase[cERASE_WIPE], ST7735_LIGHTGREY);
    strcpy(text, "CARD SIZE: ");
    u16_to_str((unsigned int)mb_total, &text[11]);
    strcat(text, " MB");
    drawtext(1, 14, text, ST7735_CYAN, ST7735_BLACK, 1);
    drawtext(1, 30, "ERASES THE WHOLE SD CARD:", ST7735_RED, ST7735_BLACK, 1);
    drawtext(1, 40, "ALL SEEDS, THE VAULT AND", ST7735_RED, ST7735_BLACK, 1);
    drawtext(1, 50, "THE FILE SYSTEM (FORMAT)", ST7735_RED, ST7735_BLACK, 1);
    drawtext(1, 60, "THIS CANNOT BE UNDONE", ST7735_RED, ST7735_BLACK, 1);
    grid_confirm("WIPE");
}

// The card was initialized: seeds can be written to it
void print_sd_initialized(void) {
    black_screen();
    drawtext(1, 20, "CARD INITIALIZED", ST7735_GREEN, ST7735_BLACK, 1);
    drawtext(1, 40, "SEEDS CAN BE WRITTEN TO", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(1, 50, "SLOTS 2 TO 200", ST7735_WHITE, ST7735_BLACK, 1);
    grid_OK_back();
}

// Result of DERIVE: which key the child seed comes from (the master
// fingerprint of the seed on screen, with its passphrase if it has one)
void print_derive_info(uint32_t fingerprint) {
    char fgp[9];
    char text[24];

    black_screen();
    draw_title((char*)menu_main[cMAIN_BIP85], ST7735_LIGHTGREY);
    drawtext(1, 22, "DERIVED FROM", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(1, 32, "FINGERPRINT", ST7735_WHITE, ST7735_BLACK, 1);
    u16_to_hex4((uint16_t)(fingerprint >> 16), fgp);
    u16_to_hex4((uint16_t)(fingerprint & 0xFFFF), fgp + 4);
    fgp[8] = '\0';
    drawtext(1, 46, fgp, ST7735_GREEN, ST7735_BLACK, 2);
    strcpy(text, (bip85_size == cSIZE_12) ? "12 WORDS, INDEX " : "24 WORDS, INDEX ");
    u16_to_str((unsigned int)bip85_index, &text[16]);
    drawtext(1, 72, text, ST7735_CYAN, ST7735_BLACK, 1);
    grid_confirm("SHOW");
}

// Red warning before the QR of a text that is a seed (QR FROM TEXT); BACK
// returns to the text, OK shows the QR
void print_text_seed_warning(void) {
    rectan(0, 0, 159, 127, ST7735_RED);
    drawtext(1, 10, "THIS TEXT IS A SEED", ST7735_WHITE, ST7735_RED, 1);
    drawtext(1, 25, "ITS QR EQUALS YOUR SEED", ST7735_WHITE, ST7735_RED, 1);
    drawtext(1, 40, "DO NOT SCAN WITH A PHONE", ST7735_WHITE, ST7735_RED, 1);
    drawtext(1, 55, "DO NOT TAKE PHOTOS", ST7735_WHITE, ST7735_RED, 1);
    drawtext(1, 70, "KEEP IT OFFLINE", ST7735_WHITE, ST7735_RED, 1);
    grid_confirm("SHOW");
}

// Confirmation before the seed and every secret derived from it are wiped
// (UNLOAD SEED in the wallet menu, or BACK on the words screen)
void print_unload_confirm(void) {
    black_screen();
    draw_title("UNLOAD SEED?", ST7735_RED);
    drawtext(1, 20, "WIPES THE SEED, ITS", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(1, 30, "PASSPHRASE, ITS KEYS AND", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(1, 40, "THE WALLET FROM MEMORY", ST7735_WHITE, ST7735_BLACK, 1);
    drawtext(1, 58, "BACK IT UP FIRST IF YOU", ST7735_YELLOW, ST7735_BLACK, 1);
    drawtext(1, 68, "STILL NEED IT", ST7735_YELLOW, ST7735_BLACK, 1);
    grid_confirm("WIPE");
}

// Confirmation of a setting change, which is permanent (row = cSETTINGS_*)
// The six keys at the bottom left, OK and RIGHT pressed (filled): how to skip
// the decoy game at power-on
static void draw_skip_keys(void) {
    for (int i = 0; i < 6; i++) {
        int x0 = 4 + (i % 3) * 17, y0 = 101 + (i / 3) * 12;
        bool pressed = (i % 3) == 2;            // OK above RIGHT, the right column
        drawFastHLine(x0, y0, 16, 0x8410);
        drawFastHLine(x0, y0 + 11, 16, 0x8410);
        drawFastVLine(x0, y0, 12, 0x8410);
        drawFastVLine(x0 + 15, y0, 12, 0x8410);
        if (pressed) rectan(x0 + 1, y0 + 1, x0 + 14, y0 + 10, ST7735_WHITE);
    }
    drawtext(4 + 34 + 2, 103, "OK", ST7735_BLACK, ST7735_WHITE, 1);
    print_rigth_arrow(4 + 34 + 5, 120, ST7735_BLACK);
}

void print_setting_confirm(int row, bool new_on) {
    const char *name, *l1, *l2 = "", *l3 = "";
    uint16_t body = ST7735_WHITE;
    rectan(0, 0, 159, 127, ST7735_BLACK);
    draw_title("SAVE SETTING?", ST7735_LIGHTGREY);
    if (row == cSETTINGS_SEEDQR) {
        name = new_on ? "SEEDQR: ON" : "SEEDQR: OFF";
        l1 = new_on ? "SEEDQR WILL SHOW YOUR" : "SEEDQR WILL BE";
        l2 = new_on ? "SEED AS A QR CODE" : "DISABLED";
        l3 = new_on ? "IN THE SEED BACKUP MENU" : "";
    } else if (row == cSETTINGS_SDWRITE) {
        name = new_on ? "SD SEED SAVE: ON" : "SD SEED SAVE: OFF";
        l1 = new_on ? "SEEDS CAN BE WRITTEN TO" : "SEEDS CANNOT BE";
        l2 = new_on ? "THE SD CARD (NOT" : "WRITTEN TO THE SD CARD";
        l3 = new_on ? "ENCRYPTED)" : "";
    } else if (row == cSETTINGS_STOPWATCH) {
        name = new_on ? "STOPWATCH SEED: ON" : "STOPWATCH SEED: OFF";
        l1 = new_on ? "THE ORIGIN OF ITS ENTROPY" : "";
        l2 = new_on ? "CANNOT BE VERIFIED" : "";
        if (new_on) body = ST7735_YELLOW;
    } else {
        name = new_on ? "DECOY GAME: ON" : "DECOY GAME: OFF";
        l1 = new_on ? "IT STARTS AS A SNAKE GAME" : "IT STARTS DIRECTLY AS";
        l2 = new_on ? "TO SKIP IT HOLD THESE TWO" : "SEEDMATE";
        l3 = new_on ? "KEYS WHILE TURNING ON" : "";
    }
    drawtext(5, 14, (char*)name, ST7735_CYAN, ST7735_BLACK, 1);
    drawtext(1, 30, "PERMANENT SETTING:", ST7735_YELLOW, ST7735_BLACK, 1);
    drawtext(1, 40, "KEPT AFTER POWER OFF AND", ST7735_YELLOW, ST7735_BLACK, 1);
    drawtext(1, 50, "AFTER FIRMWARE UPDATES", ST7735_YELLOW, ST7735_BLACK, 1);
    drawtext(1, 68, (char*)l1, body, ST7735_BLACK, 1);
    drawtext(1, 78, (char*)l2, body, ST7735_BLACK, 1);
    drawtext(1, 88, (char*)l3, body, ST7735_BLACK, 1);
    if (row == cSETTINGS_DECOY && new_on) draw_skip_keys();
    grid_confirm("SAVE");
}

void print_mcu_serial_screen(void) {
    char hex_buf[5];
    uint16_t parts[4];
    int x_pos = 29;                 // 4 groups of 4 digits, centered

    black_screen();
    draw_title("MCU SERIAL NUMBER", ST7735_LIGHTGREY);
    
    // The PIC32MM uses UDID1 to UDID4. We extract 64 bits using UDID2 and UDID1.
    parts[0] = (uint16_t)((UDID2 >> 16) & 0xFFFF);
    parts[1] = (uint16_t)(UDID2 & 0xFFFF);
    parts[2] = (uint16_t)((UDID1 >> 16) & 0xFFFF);
    parts[3] = (uint16_t)(UDID1 & 0xFFFF);
    
    // Draw the chunks consecutively
    for (int i = 0; i < 4; i++) {
        u16_to_hex4(parts[i], hex_buf);
        drawtext(x_pos, 13, hex_buf, ST7735_CYAN, ST7735_BLACK, 1);
        x_pos += 26; // Advance cursor (4 chars * 6px + 2px spacing)
    }
    
    grid_OK_back();                 // Either key returns to SETTINGS
}

void print_card_encoding_screen(void) {
    black_screen();
    draw_title("MNEMONIC TO CARDS", ST7735_LIGHTGREY);
    
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
