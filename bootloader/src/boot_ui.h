/*******************************************************************************
  Bootloader screen (minimal)

  Summary:
    Title, text lines, a progress bar and a simplified button grid on the
    ST7735 display, so the update can be followed and confirmed.

  Description:
    The display driver is the app's own TFT.c, compiled here (shared, not
    copied) and placed with this module in the boot flash area that the
    linker script reserves for the debug executive (.boot_ui, free in
    production builds), so the 8 KB of main flash are not used for it.
 *******************************************************************************/

#ifndef BOOT_UI_H
#define BOOT_UI_H

#include <stdint.h>
#include <stdbool.h>

#define UI_WHITE    0xFFFF
#define UI_YELLOW   0xFFE0
#define UI_GREEN    0x07E0
#define UI_RED      0xF800
#define UI_CYAN     0x07FF

// SPI1 and the LCD as the app sets them up, black screen, backlight on
void ui_init(void);

// Clears the screen and writes the title on the top line
void ui_screen(const char *title);

// One text line at y (cleared first)
void ui_text(int y, const char *text, uint16_t color);

// Progress bar above the button grid: outline when done == 0
void ui_progress(uint32_t done, uint32_t total);

// Button grid with BACK and/or OK labels (none: the grid area is cleared)
void ui_grid(bool back, bool ok);

// Update flow helpers
bool app_missing(void);                 // The app area holds no program
void software_reset(void);
bool wait_ok_back(bool back_allowed);   // true OK, false BACK
const char *error_text(int code);       // Failure reason in plain words
// Result on screen and as LED blinks, then OK: the app starts, or the
// update starts again when there is no app
void finish(int blinks, const char *what, uint16_t color, const char *detail, uint16_t detail_color);
void fail_app_intact(int code, const char *what);
void fail_app_erased(int code, const char *what);

#endif // BOOT_UI_H
