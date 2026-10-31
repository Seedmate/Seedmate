/*******************************************************************************
  Bootloader screen (minimal). See boot_ui.h.

  TFT.c of the app is compiled into this file: only the functions used here
  are linked (-ffunction-sections, --gc-sections), and the linker script puts
  this whole object in the boot flash (.boot_ui).
 *******************************************************************************/

#include "../../SW/src/TFT.c"
#include "boot_ui.h"

#define LED_LCD     PORTBbits.RB10  // Backlight, as in the app

#define GRID_X      63              // Same button grid position as the app
#define BAR_Y       92              // Progress bar above the grid

// Same sequence as the app's main() before the LCD
void ui_init(void) {
    R_LCD = 1;
    LED_LCD = 1;
    A0_LCD = 0;
    SPI1CON = 0x10000120;           // Off, master, 8-bit
    SPI1CON = 0x10008120;           // On
    SPI1BRG = 1;
    PORTBbits.RB5 = 1;              // SD card deselected
    LCDinit1();
    rectan(0, 0, 159, 127, ST7735_BLACK);
    LCDinit2();
}

void ui_screen(const char *title) {
    rectan(0, 0, 159, 127, ST7735_BLACK);
    drawtext(1, 1, (char *)title, ST7735_WHITE, ST7735_BLACK, 1);
}

void ui_text(int y, const char *text, uint16_t color) {
    rectan(0, (unsigned char)y, 159, (unsigned char)(y + 8), ST7735_BLACK);
    drawtext(5, (unsigned int)y, (char *)text, color, ST7735_BLACK, 1);
}

void ui_progress(uint32_t done, uint32_t total) {
    static uint32_t drawn;
    uint32_t fill = (total != 0) ? (140u * (done > total ? total : done)) / total : 0;
    if (done == 0) {
        rectan(9, BAR_Y, 151, BAR_Y + 5, ST7735_WHITE);
        rectan(10, BAR_Y + 1, 150, BAR_Y + 4, ST7735_BLACK);
        drawn = 0;
    }
    if (fill > drawn) {
        rectan(10 + drawn, BAR_Y + 1, 10 + fill, BAR_Y + 4, ST7735_GREEN);
        drawn = fill;
    }
}

void ui_grid(bool back, bool ok) {
    rectan(GRID_X, 105, GRID_X + 90, 125, ST7735_BLACK);
    if (!back && !ok) return;
    for (int r = 0; r < 3; r++) drawFastHLine(GRID_X, 105 + r * 10, 90, ST7735_WHITE);
    for (int c = 0; c < 4; c++) drawFastVLine(GRID_X + c * 30, 105, 20, ST7735_WHITE);
    if (back) drawtext(GRID_X + 4, 107, "BACK", ST7735_WHITE, ST7735_BLACK, 1);
    if (ok) drawtext(GRID_X + 70, 107, "OK", ST7735_WHITE, ST7735_BLACK, 1);
}

// =========================================================================
// UPDATE FLOW HELPERS (here, in the boot flash, to keep the main 8 KB free)
// =========================================================================

#define LED                     PORTAbits.RA2       // As in main.c
#define BTN_BACK                PORTBbits.RB2
#define BTN_OK                  PORTCbits.RC1
#define USER_APP_RESET_ADDRESS  0x9D002000

void JumpToApp(void);           // main.c

// The app area holds no program: factory state (only the bootloader was
// programmed) or an update that failed after erasing
bool app_missing(void) {
    return *(volatile uint32_t *)USER_APP_RESET_ADDRESS == 0xFFFFFFFF;
}

// Restarts the chip (and so the bootloader)
void software_reset(void) {
    SYSKEY = 0x00000000;
    SYSKEY = 0xAA996655;
    SYSKEY = 0x556699AA;
    RSWRSTSET = 1;
    (void)RSWRST;
    while (true);
}

// Waits until no key is held, then for OK (true) or, if allowed, BACK (false)
bool wait_ok_back(bool back_allowed) {
    while (BTN_OK == 0 || BTN_BACK == 0);
    delay_ms(30);
    while (true) {
        if (BTN_OK == 0) {
            delay_ms(30);
            if (BTN_OK == 0) return true;
        }
        if (back_allowed && BTN_BACK == 0) {
            delay_ms(30);
            if (BTN_BACK == 0) return false;
        }
    }
}

// Reason of a failed step, in plain words (codes as in process_hex_file)
const char *error_text(int code) {
    switch (code) {
        case 3:  return "UPDATE.HEX NOT FOUND";
        case 4:  return "SD READ ERROR";
        case 5:  return "FILE DAMAGED";
        case 6:  return "FLASH WRITE FAILED";
        default: return "UPDATE ERROR";
    }
}

// Shows the result and blinks its code on the LED (in case the screen does
// not work), then waits for OK and starts the app
void finish(int blinks, const char *what, uint16_t color, const char *detail, uint16_t detail_color) {
    ui_text(40, what, color);
    if (detail != NULL) ui_text(52, detail, detail_color);
    ui_grid(false, true);

    LED = 0;
    delay_ms(500);
    for (int i = 0; i < blinks; i++) {
        LED = 1;
        delay_ms(200);
        LED = 0;
        delay_ms(200);
    }
    (void)wait_ok_back(false);
    if (app_missing()) software_reset();    // Nothing to start: OK tries the update again
    JumpToApp();
}

// The update failed before the flash was touched (there may be no app yet)
void fail_app_intact(int code, const char *what) {
    if (app_missing()) finish(code, what, UI_RED, "NO APP: OK RETRIES", UI_YELLOW);
    finish(code, what, UI_RED, "APP NOT TOUCHED", UI_GREEN);
}

// The update failed after the app was erased: OK retries (see finish)
void fail_app_erased(int code, const char *what) {
    finish(code, what, UI_RED, "APP ERASED: OK RETRIES", UI_YELLOW);
}
