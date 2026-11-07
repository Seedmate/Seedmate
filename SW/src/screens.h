/*******************************************************************************
 * Project:     SeedMate
 * File:        screens.h
 *
 * Summary:
 *   Public interface of the TFT screen/menu drawing module (screens.c).
 ******************************************************************************/

#ifndef SCREENS_H
#define SCREENS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define QR_SCALE 4 // Size of each module in pixels
#define ST7735_LIGHTGREY 0xC618     // Titles and fixed messages the user cannot interact with (rule 7)
#define SCREEN_WIDTH 160
#define SCREEN_HEIGHT 128
#define GRID_X 63           // Left line of the button grid (x 63-153, y 105-125)

// Menu text tables (stored in flash)
extern const char* const menu_main[];
extern const uint8_t main_menu_ids[];
extern const char* const menu_opsec[];
extern const uint8_t opsec_menu_ids[];
extern const char* const menu_tools[];
extern const char* const menu_backup[];
extern const char* const menu_passphrase[];
extern const char* const menu_create[];
extern const char* const menu_dice[];
extern const char* const menu_hash[];
extern const char* const menu_size[];
extern const char* const menu_qr[];
extern const char* const menu_xor[];
extern const char* const menu_sss[];
extern const char* const menu_resource[];
extern const char* const menu_obfus[];
extern const char* const menu_erase[];
extern const char* const menu_bip84[];
extern const char* const menu_bip84_multi[];
extern const char* const menu_addresses[];
extern const char* const menu_sign[];
extern const char* const menu_import[];
extern const char* const menu_input[];

// Drawing functions
void draw_hex16(unsigned int x, unsigned int y, uint16_t numero, int N, unsigned int color, unsigned int bg, unsigned int size);
void draw_bitmap(int x, int y, int w, int h, const uint16_t *bitmap, uint16_t color);
void print_up_arrow(int x, int y,uint16_t color);
void print_add_symbol(int x, int y);
void print_down_arrow(int x, int y, uint16_t color);
void print_left_arrow(int x, int y, uint16_t color);
void print_left_arrow_black(int x, int y);
void print_rigth_arrow(int x, int y, uint16_t color);
void print_camera(int x, int y, int safe);
void print_cursor_grid(void);
void print_minus_symbol(int x,int y);
void print_ok(void);
void grid_menu1(void);
void grid_menuwr(void);
void print_back(void);
void grid_menu2(void);
void grid_menuSD(void);
void grid_menu2_merge(void);
void grid_nbits(void);
void grid_nbits_noback(void);
void grid_nbits_LR(void);
void grid_keyboard(void);
void grid_keyboard_dice_hash(void);
void grid_bip85(void);
void draw_mini_dice(int x, int y, int value);
void grid_dices(void);
void grid_coins(void);
void grid_rows_keys(const char *left, const char *right);
void grid_coins_back_label(bool can_delete);
void grid_OK_only(void);
void version_display(void);
void print_generic_menu(const char* const *options, int n_opt, int sel);
void print_titled_menu(const char *title, const char* const *options, int n_opt, int sel);
void black_screen(void);
void white_screen(void);
void print_logo(void);
void grid_OK_back(void);
void grid_labels(const char *back, const char *up, const char *ok,
                 const char *left, const char *down, const char *right);
void grid_back_only(void);
void grid_confirm(const char *ok_label);
void grid_pager(const char *ok_label);
void grid_scan_back(void);
void print_update_fw_warning(void);
void print_diceroll_screen(int sel, int sel2);
void draw_dice_back_hint(bool can_delete);
void print_TMR_screen(int size_TMR);
void print_dice_string_counter(int current_len, int target);
void print_dice_string_keyboard(int sel, int current_len, int target);
void init_dice_string_input_screen(int sel, const char* str, int target);
void show_word_list_retry_error(void);
void clear_write_word_current_display(void);
void clear_write_word_previous_display(void);
void update_dice_bit_count_display(int bit_count_dice_local);
void print_selkn_screen(int k, int n, int sel);
void print_selk_screen(int k);
void print_sel_share_screen(int k);
void sel_sd_block_screen_wr(int sel);
void sel_sd_block_screen_merge(int sel,int id);
void print_seedqr_warning(const char *ok_label);
void print_setting_confirm(int row, bool new_on);
void print_mcu_serial_screen(void);
void print_keyboard(int index, bool word_found, bool *valid_letters);
void draw_url_qr(const char *text);
void draw_xpub_qr(const char *text);
bool draw_qr_frame(const char *text, uint8_t version, int scale);
int draw_seed_qr_view(const unsigned char *data, size_t size, bool compact, int tile);
int draw_text_qr_view(const char *text, int tile);
void print_text_seed_warning(void);
void print_sd_warning(const char *ok_label);
void print_blocked(const char *l1, const char *l2, const char *l3);
void print_slot_in_use(int slot);
void print_sd_init_warning(void);
void print_sd_wipe_warning(uint32_t mb_total);
void print_sd_initialized(void);
void print_derive_info(uint32_t fingerprint);
void print_unload_confirm(void);
void draw_title(const char *text, uint16_t color);
void draw_title_pair(const char *a, uint16_t color_a, const char *b, uint16_t color_b);
void draw_bip84_wrapped_text(const char *text, int x, int y, int line_length, int line_count);
void main_screen(int sel);
void draw_card_bit_counter(void);
void draw_card_selection(void);
uint8_t get_selected_card_index(void);
void print_card_input_screen(void);
void print_child_config_screen(void);
void print_obfus_config_screen(void);
void update_dice_string_char(int index, char c, bool is_delete);
void print_word_number_top(int word_number, char *word_number_text);
void print_slots(int sel);
void sel_sd_block_screen_generic(int sel);
void print_settings_screen(int sel);
void print_card_encoding_screen(void);
void u16_to_hex4(uint16_t value, char *buf);
size_t u16_to_str(unsigned int n, char *buf);
size_t u16_to_str_pad(unsigned int n, char *buf, unsigned int width);
void draw_shared_entropy_building(void);
void print_SD_preview(void);

#endif // SCREENS_H
