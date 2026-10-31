/*******************************************************************************
  Main Source File (Bootloader)

  Summary:
    Main entry point for the bootloader.

  Description:
    Initializes system modules, checks for SD card firmware updates using 
    Petit FatFs, parses Intel Hex records, programs PIC32MM flash, and 
    provides visual LED debugging before jumping to the app.
 *******************************************************************************/

#include <stddef.h>                     
#include <stdbool.h>                    
#include <stdlib.h>                     
#include <string.h>
#include "definitions.h"                
#include <xc.h>
#include "pff.h"
#include "diskio.h"
#include "hex_flash.h"
#include "boot_ui.h"

// --- Pin mapping for LED activity ---
#define LED       PORTAbits.RA2
#define LED_TRIS  TRISAbits.TRISA2

// --- Memory Boundaries (Shifted by 8KB for Bootloader) ---
#define USER_APP_RESET_ADDRESS  0x9D002000
#define APP_FLASH_BASE_ADDRESS  0x9D002000
#define APP_FLASH_END_ADDRESS   0x9D03FFFF  // 256KB total flash limit
#define FLASH_PAGE_SIZE         2048        // 2KB pages on PIC32MM

// --- Intel Hex Record Types ---
#define DATA_RECORD             0x00
#define END_OF_FILE_RECORD      0x01
#define EXT_SEG_ADRS_RECORD     0x02
#define EXT_LIN_ADRS_RECORD     0x04

// --- Memory Boundaries (Shifted by 8KB for Bootloader) ---
#define USER_APP_RESET_ADDRESS  0x9D002000
#define APP_FLASH_BASE_ADDRESS  0x9D002000
#define APP_FLASH_END_ADDRESS   0x9D03FFFF  // 256KB total flash limit
#define FLASH_PAGE_SIZE         2048        // 2KB pages on PIC32MM

// --- Bootloader Shared Memory Flags ---
#define UPDATE_FLAG_ADDR ((volatile uint32_t *)0x80007F00)
#define MAGIC_WORD_UPDATE 0x55AA1234

// --- Forced update buttons: same pins as the app (active low, pull-ups set
// by SYS_Initialize): BACK = RB2 (BT1), OK = RC1 (BT_OK) ---
#define BTN_BACK  PORTBbits.RB2
#define BTN_OK    PORTCbits.RC1

// --- Hex Parser Structures ---
typedef enum {
    REC_NOT_FOUND,
    REC_FOUND_BUT_NOT_FLASHED,
    REC_FLASHED
} T_REC_STATUS;

typedef struct {
    uint8_t *start;
    uint32_t len;
    T_REC_STATUS status;
} T_REC;

// --- Global Variables for Parser ---
FATFS fs;
uint8_t asciiBuffer[2048]; // Increased buffer for safety
uint8_t hexRec[200];

// --- Function Prototypes ---
void delay_ms(unsigned int milliseconds);   // From the app's SPI.c (spi_boot.c)
void JumpToApp(void);
void ConvertAsciiToHex(uint8_t* asciiRec, uint8_t* hexRec);

// =========================================================================
// BASIC HARDWARE CONTROL FUNCTIONS
// =========================================================================

void JumpToApp(void)
{
    // 1. Disable bootloader interrupts to avoid crashing the main app
    __builtin_disable_interrupts();
    
    // 2. Shut down peripherals used by Bootloader
    LATBbits.LATB5 = 1;
    SPI3CON = 0; 
    
    // 3. Turn off LED before leaving
    LED = 0;
    
    // 4. Jump using microMIPS address format (Address | 1)
    void (*fptr)(void);
    fptr = (void (*)(void))(USER_APP_RESET_ADDRESS | 1);
    fptr(); 
}

// OK and BACK held together at power-on force an update from the SD card,
// so a missing or broken application (which cannot set the update flag)
// can still be replaced without a programmer. Checked twice, 50 ms apart.
static bool forced_update_requested(void) {
    delay_ms(20);                   // Let the pull-ups settle
    if (BTN_BACK != 0 || BTN_OK != 0) return false;
    delay_ms(50);
    return BTN_BACK == 0 && BTN_OK == 0;
}

// A complete record: its checksum is right and it is as long as it claims
// ('hex_chars' = characters after the ':')
static bool record_is_valid(const uint8_t *rec, uint32_t hex_chars) {
    uint32_t bytes = (uint32_t)rec[0] + 5u;
    if (bytes * 2u > hex_chars) return false;
    uint8_t sum = 0;
    for (uint32_t i = 0; i < bytes; i++) sum += rec[i];
    return sum == 0;
}

// Reads UPDATE.HEX from its start. With 'program' false every record is only
// checked (nothing is written); with 'program' true each one goes to the
// flash writer. Returns 0, or the LED blink code of the failure.
static int process_hex_file(bool program) {
    UINT pointer = 0;
    UINT readBytes = 0;
    T_REC record;
    uint32_t led_counter = 0;
    bool end_of_file_found = false;

    if (pf_open("UPDATE.HEX") != FR_OK) return 3;
    record.status = REC_NOT_FOUND;
    ui_progress(0, fs.fsize);

    while (true)
    {
        FRESULT res = pf_read(&asciiBuffer[pointer], 512, &readBytes);
        if (res != FR_OK) return 4;
        if (readBytes == 0) break; // EOF

        for (uint32_t i = 0; i < (readBytes + pointer); i++)
        {
            switch (record.status)
            {
                case REC_FLASHED:
                case REC_NOT_FOUND:
                    if (asciiBuffer[i] == ':') {
                        record.start = &asciiBuffer[i];
                        record.len = 0;
                        record.status = REC_FOUND_BUT_NOT_FLASHED;
                    }
                    break;

                case REC_FOUND_BUT_NOT_FLASHED:
                    // 0x0A is LF, 0x0D is CR
                    if ((asciiBuffer[i] == 0x0A) || (asciiBuffer[i] == 0x0D)) {
                        if (record.len > 0 && record.len < 190) { // Safety bound
                            ConvertAsciiToHex(&record.start[1], hexRec);

                            if (hexRec[3] == END_OF_FILE_RECORD) {
                                end_of_file_found = true;
                            }
                            if (program) {
                                hexflash_status_t st = hexflash_write_record(hexRec);
                                if (st != HEXFLASH_OK) return st;
                            } else if (!record_is_valid(hexRec, record.len - 1)) {
                                return HEXFLASH_ERR_RECORD;
                            }
                        }
                        record.status = REC_FLASHED;
                    }
                    break;
            }
            if (record.status == REC_FOUND_BUT_NOT_FLASHED) record.len++;
        }

        if (record.status == REC_FOUND_BUT_NOT_FLASHED) {
            if (record.len > 1000) return 5;
            memmove(asciiBuffer, record.start, record.len);
            pointer = record.len;
            record.status = REC_NOT_FOUND;
        } else {
            pointer = 0;
        }

        led_counter++;
        if ((led_counter % 2) == 0) LED = !LED;
        ui_progress(fs.fptr, fs.fsize);
    }

    return end_of_file_found ? 0 : 5;
}

// =========================================================================
// MAIN ROUTINE
// =========================================================================

int main(void)
{
    /* Initialize all Harmony modules (Clocks, Pins, Peripherals) */
    SYS_Initialize(NULL);
    
    // CS Pin Configuration 
    TRISBbits.TRISB5 = 0; 
    LATBbits.LATB5 = 1;   

    /* Configure LED pin as digital output */
    LED_TRIS = 0;
    LED = 1; 

    // --- BAREBONE SPI3 INITIALIZATION ---
    SPI3CON = 0x10000120; // Off, Master Mode, 8-bit
    SPI3CON = 0x10008120; // On
    
    // =========================================================================
    // MAGIC WORD CHECK (SHARED MEMORY)
    // =========================================================================
    // Update if the main application requested it, if OK + BACK are held,
    // or if there is no app to start (factory state, failed update)
    bool forced = forced_update_requested();
    bool no_app = app_missing();
    if (!forced && !no_app && *UPDATE_FLAG_ADDR != MAGIC_WORD_UPDATE) {
        // No update requested, jump straight to the application
        JumpToApp();
    }

    // Clear the flag immediately to prevent bootloops in case the update fails
    *UPDATE_FLAG_ADDR = 0;

    // Forced update: 10 fast flickers (unlike the 200 ms result codes), so
    // the buttons can be released
    if (forced) {
        for (int i = 0; i < 10; i++) {
            LED = 0;
            delay_ms(50);
            LED = 1;
            delay_ms(50);
        }
    }

    ui_init();
    ui_screen("FIRMWARE UPDATE");
    if (forced) ui_text(20, "FORCED WITH OK + BACK", UI_CYAN);
    else if (no_app) ui_text(20, "NO APP INSTALLED", UI_YELLOW);
    delay_ms(1000);

    // =========================================================================
    // FIRMWARE UPDATE CHECK WORKFLOW
    // =========================================================================

    ui_text(82, "READING SD CARD", UI_CYAN);
    DSTATUS init_status = disk_initialize();
    if (init_status != 0) fail_app_intact(init_status, "SD CARD NOT READY");
    if (pf_mount(&fs) != FR_OK) fail_app_intact(2, "SD CARD NOT FAT16");

    // Pass 1: read and check the whole file without touching the flash. A
    // damaged card or file is found here, while the current app still works.
    ui_text(82, "CHECKING UPDATE.HEX", UI_CYAN);
    int err = process_hex_file(false);
    if (err != 0) fail_app_intact(err, error_text(err));

    // Confirmation before anything is erased (Rule 4)
    ui_text(40, "FILE OK", UI_GREEN);
    ui_text(52, "ERASE THE APP AND", UI_WHITE);
    ui_text(62, "WRITE THE NEW ONE?", UI_WHITE);
    ui_grid(true, true);
    if (!wait_ok_back(true)) {
        ui_text(52, "", UI_WHITE);
        ui_text(62, "", UI_WHITE);
        if (no_app) finish(1, "UPDATE CANCELLED", UI_YELLOW, "NO APP: OK RETRIES", UI_YELLOW);
        finish(1, "UPDATE CANCELLED", UI_YELLOW, "APP NOT TOUCHED", UI_GREEN);
    }
    ui_text(40, "", UI_WHITE);
    ui_text(52, "", UI_WHITE);
    ui_text(62, "", UI_WHITE);
    ui_grid(false, false);

    // =========================================================================
    // FILE CHECKED AND CONFIRMED: FLASH PROCESS
    // =========================================================================

    // Pass 2: erase the app area and program it from the file
    ui_text(82, "ERASING THE APP", UI_CYAN);
    hexflash_status_t flash_status = hexflash_begin();
    if (flash_status != HEXFLASH_OK) fail_app_erased(flash_status, "FLASH ERASE FAILED");

    ui_text(82, "WRITING THE NEW APP", UI_CYAN);
    err = process_hex_file(true);
    if (err != 0) fail_app_erased(err, error_text(err));

    // Final verification check to ensure Flash is not entirely blank
    if (*(uint32_t *)USER_APP_RESET_ADDRESS == 0xFFFFFFFF) {
        fail_app_erased(8, "FLASH IS EMPTY");
    }

    ui_text(82, "", UI_WHITE);
    finish(7, "UPDATE DONE", UI_GREEN, "OK STARTS THE NEW APP", UI_WHITE);

    return (EXIT_FAILURE);
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

void ConvertAsciiToHex(uint8_t* asciiRec, uint8_t* hexRec)
{
    uint8_t i = 0;
    uint8_t k = 0;
    uint8_t hex;
    
    while ((asciiRec[i] >= 0x30) && (asciiRec[i] <= 0x66))
    {
        if (asciiRec[i] < 0x3A) hex = asciiRec[i] & 0x0F;
        else hex = 0x09 + (asciiRec[i] & 0x0F);                      
    
        k = i % 2;
        if (k) hexRec[i/2] |= hex;
        else hexRec[i/2] = (hex << 4) & 0xF0;
        
        i++;        
    }       
}