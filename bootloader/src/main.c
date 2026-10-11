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

// Double Word Buffering for PIC32MM Flash
uint32_t ext_addr = 0;     // Extended address from Type 02/04 records
uint32_t dw_addr = 0;
uint32_t dw_data[2] = {0xFFFFFFFF, 0xFFFFFFFF};
bool dw_pending = false;

// --- Function Prototypes ---
void delay_ms(unsigned int milliseconds);
void blink_error_and_jump(int blinks);
void JumpToApp(void);
void EraseFlash(void);
void FlushDoubleWord(void);
void WriteHexRecord2Flash(uint8_t* HexRecord);
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
    
    EraseFlash();

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
                            
                            WriteHexRecord2Flash(hexRec);
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
// NVM / FLASH PROGRAMMING LOGIC (PIC32MM BAREMETAL)
// ============================================================================

void EraseFlash(void)
{
    // Block Erase the program Flash page by page
    for (uint32_t addr = APP_FLASH_BASE_ADDRESS; addr <= APP_FLASH_END_ADDRESS; addr += FLASH_PAGE_SIZE)
    {
        NVMADDR = addr & 0x1FFFFFFF; // Convert Virtual to Physical Address
        NVMCON = 0x4004;             // WREN = 1, Page Erase = 4
        
        __builtin_disable_interrupts();
        NVMKEY = 0xAA996655;         
        NVMKEY = 0x556699AA;
        NVMCONSET = 0x8000;          
        while (NVMCONbits.WR);       
        NVMCONCLR = 0x4000;          
        __builtin_enable_interrupts();
    }
}

void FlushDoubleWord(void)
{
    // Write 64-bits (8 bytes) to flash if data is pending
    if (dw_pending) {
        NVMADDR = dw_addr & 0x1FFFFFFF;
        NVMDATA0 = dw_data[0];
        NVMDATA1 = dw_data[1];
        
        NVMCON = 0x4002;            
        
        __builtin_disable_interrupts();
        NVMKEY = 0xAA996655;         
        NVMKEY = 0x556699AA;
        NVMCONSET = 0x8000;          
        while (NVMCONbits.WR);       
        NVMCONCLR = 0x4000;          
        __builtin_enable_interrupts();
        
        if (NVMCON & 0x3000) blink_error_and_jump(6); // Hardware Error
        
        // Reset buffer
        dw_data[0] = 0xFFFFFFFF;
        dw_data[1] = 0xFFFFFFFF;
        dw_pending = false;
    }
}

void WriteHexRecord2Flash(uint8_t* HexRecord)
{
    uint8_t RecDataLen = HexRecord[0];
    uint32_t RecAddress = (HexRecord[1] << 8) | HexRecord[2];
    uint8_t RecType = HexRecord[3];
    uint8_t* Data = &HexRecord[4];
    
    // Hex Record checksum check
    uint8_t Checksum = 0;
    for (uint8_t i = 0; i < RecDataLen + 5; i++) {
        Checksum += HexRecord[i];
    }   
    if (Checksum != 0) blink_error_and_jump(5); 
    
    if (RecType == DATA_RECORD) 
    {
        uint32_t basePhysAddr = (RecAddress + ext_addr) & 0x1FFFFFFF;
        uint32_t physBase = APP_FLASH_BASE_ADDRESS & 0x1FFFFFFF;
        uint32_t physEnd  = APP_FLASH_END_ADDRESS & 0x1FFFFFFF;
        
        for (int i = 0; i < RecDataLen; i++) 
        {
            uint32_t current_byte_addr = basePhysAddr + i;
            
            if ((current_byte_addr >= physBase) && (current_byte_addr <= physEnd)) 
            {
                if (dw_pending && (current_byte_addr & 0xFFFFFFF8) != dw_addr) {
                    FlushDoubleWord();
                }
                
                if (!dw_pending) {
                    dw_addr = current_byte_addr & 0xFFFFFFF8;
                    dw_pending = true;
                }
                
                uint8_t offset = current_byte_addr & 0x7; 
                
                // CASTEO a uint32_t para evitar Undefined Behavior en el bit de signo
                if (offset < 4) {
                    dw_data[0] &= ~((uint32_t)0xFF << (offset * 8));
                    dw_data[0] |= ((uint32_t)Data[i] << (offset * 8));
                } else {
                    dw_data[1] &= ~((uint32_t)0xFF << ((offset - 4) * 8));
                    dw_data[1] |= ((uint32_t)Data[i] << ((offset - 4) * 8));
                }
                
                if (offset == 7) {
                    FlushDoubleWord();
                }
            }
        }
    }
    else if (RecType == EXT_SEG_ADRS_RECORD) 
    {
        FlushDoubleWord();
        ext_addr = (((uint32_t)Data[0] << 8) | (uint32_t)Data[1]) << 4;
    }
    else if (RecType == EXT_LIN_ADRS_RECORD) 
    {
        FlushDoubleWord();
        // CASTEO para evitar números negativos en memoria alta
        ext_addr = (((uint32_t)Data[0] << 8) | (uint32_t)Data[1]) << 16;
    }
    else if (RecType == END_OF_FILE_RECORD) 
    {
        FlushDoubleWord();
        ext_addr = 0;
    }
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