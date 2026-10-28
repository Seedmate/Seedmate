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
void delay_ms(unsigned int milliseconds);
void blink_error_and_jump(int blinks);
void JumpToApp(void);
void ConvertAsciiToHex(uint8_t* asciiRec, uint8_t* hexRec);

// =========================================================================
// BASIC HARDWARE CONTROL FUNCTIONS
// =========================================================================

void delay_ms(unsigned int milliseconds) {
    volatile unsigned int count;
    while (milliseconds > 0) {
        count = 3000; 
        while (count > 0) count--;
        milliseconds--;
    }
}

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

void blink_error_and_jump(int blinks) {
    LED = 0;
    delay_ms(500); 
    
    for (int i = 0; i < blinks; i++) {
        LED = 1;
        delay_ms(200);
        LED = 0;
        delay_ms(200);
    }
    
    delay_ms(500); 
    JumpToApp();
}

// =========================================================================
// MAIN ROUTINE
// =========================================================================

int main(void)
{
    UINT pointer = 0;
    UINT readBytes = 0;
    T_REC record;
    
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
    // Check if the main application requested a firmware update
    if (*UPDATE_FLAG_ADDR != MAGIC_WORD_UPDATE) {
        // No update requested, jump straight to the application
        JumpToApp();
    }
    
    // Clear the flag immediately to prevent bootloops in case the update fails
    *UPDATE_FLAG_ADDR = 0;

    delay_ms(1000);

    // =========================================================================
    // FIRMWARE UPDATE CHECK WORKFLOW
    // =========================================================================

    DSTATUS init_status = disk_initialize();
    if (init_status != 0) blink_error_and_jump(init_status); 

    if (pf_mount(&fs) != FR_OK) blink_error_and_jump(2);

    if (pf_open("UPDATE.HEX") != FR_OK) blink_error_and_jump(3);

    // =========================================================================
    // FILE FOUND! STARTING FLASH PROCESS
    // =========================================================================
    
    hexflash_status_t flash_status = hexflash_begin();
    if (flash_status != HEXFLASH_OK) blink_error_and_jump(flash_status);

    record.status = REC_NOT_FOUND;
    uint32_t led_counter = 0;
    bool end_of_file_found = false;

    while (true)
    {
        FRESULT res = pf_read(&asciiBuffer[pointer], 512, &readBytes);
        if (res != FR_OK) blink_error_and_jump(4); 
        
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
                            
                            flash_status = hexflash_write_record(hexRec);
                            if (flash_status != HEXFLASH_OK) blink_error_and_jump(flash_status);
                        }
                        record.status = REC_FLASHED;
                    }
                    break;
            }
            if (record.status == REC_FOUND_BUT_NOT_FLASHED) record.len++;
        }

        if (record.status == REC_FOUND_BUT_NOT_FLASHED) {
            if (record.len > 1000) blink_error_and_jump(5); 
            memmove(asciiBuffer, record.start, record.len);
            pointer = record.len;
            record.status = REC_NOT_FOUND;
        } else {
            pointer = 0;
        }

        led_counter++;
        if ((led_counter % 2) == 0) LED = !LED;
    }

    if (!end_of_file_found) blink_error_and_jump(5); 
    
    // Final verification check to ensure Flash is not entirely blank
    if (*(uint32_t *)USER_APP_RESET_ADDRESS == 0xFFFFFFFF) {
        blink_error_and_jump(8); // Flash is physically empty
    }
    
    blink_error_and_jump(7); // Success indicator (7 blinks)

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