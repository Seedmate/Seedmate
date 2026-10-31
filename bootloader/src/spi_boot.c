/*******************************************************************************
  SPI1 helpers of the display for the bootloader.

  The app's SPI.c is compiled here (shared, not copied). It also provides
  delay_ms(), used by the bootloader. The linker script places it in the
  boot flash next to boot_ui.c (cached KSEG0 alias: same speed).
 *******************************************************************************/

// SPI() must stay a real call, as in the app: when the compiler inlines it
// into command() and send_data() (it does here), the bytes and the A0 line
// change too close together and the LCD ignores the commands (black screen)
unsigned char SPI(unsigned char val) __attribute__((noinline));
#include "../../SW/src/SPI.c"
