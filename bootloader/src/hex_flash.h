/*******************************************************************************
  Intel HEX to PIC32MM flash writer (Bootloader)

  Summary:
    Programs the application flash area from Intel HEX records.

  Description:
    PIC32MM flash is written in 64-bit double-words protected by ECC, and a
    double-word must never be programmed twice without erasing its page: the
    ECC bits become invalid and reading it later raises a bus exception.
    XC32 does not emit HEX records sorted by address, so the same double-word
    can be reached twice from records that are far apart in the file.

    This module keeps a bitmap of programmed double-words. When a double-word
    that is already programmed receives more data, its 2 KB page is read into
    RAM, merged, erased and programmed again. Any record order is therefore
    safe and every double-word is written at most once per erase.
 *******************************************************************************/

#ifndef HEX_FLASH_H
#define HEX_FLASH_H

#include <stdint.h>
#include <stdbool.h>

// Application flash area handled by the writer (physical addresses)
#define HEXFLASH_APP_PHYS_BASE  0x1D002000u
#define HEXFLASH_APP_PHYS_END   0x1D040000u     // Exclusive
#define HEXFLASH_PAGE_SIZE      2048u           // PIC32MM erase page

// Status values double as LED blink codes in main.c
typedef enum {
    HEXFLASH_OK = 0,
    HEXFLASH_ERR_RECORD = 5,    // Bad checksum or malformed record
    HEXFLASH_ERR_NVM = 6        // Flash controller reported an error
} hexflash_status_t;

// Erases the whole application area and resets the writer state.
hexflash_status_t hexflash_begin(void);

// Programs one binary HEX record: length, address (2 bytes), type, data,
// checksum. Records outside the application area are ignored.
hexflash_status_t hexflash_write_record(const uint8_t *rec);

// Flash access layer. Implemented in hex_flash.c for the PIC32MM; a host
// test build (HEXFLASH_HOST_TEST) provides its own versions.
bool nvm_erase_page(uint32_t phys_addr);
bool nvm_write_dw(uint32_t phys_addr, uint32_t word0, uint32_t word1);
void nvm_read(uint32_t phys_addr, uint8_t *dst, uint32_t len);

#endif // HEX_FLASH_H
