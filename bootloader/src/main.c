/*******************************************************************************
  Main Source File (Bootloader)

  Company:
    Microchip Technology Inc.

  File Name:
    main.c

  Summary:
    Main entry point for the bootloader.

  Description:
    Initializes system modules, checks for SD card firmware updates using 
    Petit FatFs, and provides visual LED debugging before jumping to the app.
 *******************************************************************************/

#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include "definitions.h"                // SYS function prototypes
#include <xc.h>

// Include Petit FatFs headers
#include "pff.h"
#include "diskio.h"

// Pin mapping for LED activity
#define LED       PORTAbits.RA2
#define LED_TRIS  TRISAbits.TRISA2

// Main app reset address
#define USER_APP_RESET_ADDRESS 0x9D002000

// Simple delay function
void delay_ms(unsigned int milliseconds) {
    volatile unsigned int count;
    while (milliseconds > 0) {
        count = 3000; // Adjust according to processor speed
        while (count > 0) {
            count--;
        }
        milliseconds--;
    }
}

// Executes the jump to the main SeedMate application
void JumpToApp(void)
{
    // 1. Disable bootloader interrupts to avoid crashing the main app
    __builtin_disable_interrupts();
    
    // 2. Turn off LED before leaving
    LED = 0;
    
    // 3. Jump using microMIPS address format (Address | 1)
    void (*fptr)(void);
    fptr = (void (*)(void))(USER_APP_RESET_ADDRESS | 1);
    fptr(); 
}

// Visual Debugging System (Blinks X times, then jumps to app)
void blink_error_and_jump(int blinks) {
    LED = 0;
    delay_ms(500); // Initial pause
    
    for (int i = 0; i < blinks; i++) {
        LED = 1;
        delay_ms(200);
        LED = 0;
        delay_ms(200);
    }
    
    delay_ms(500); // Final pause before jumping
    JumpToApp();
}

int main(void)
{
    FATFS fs;
    
    /* Initialize all Harmony modules (Clocks, Pins, Peripherals) */
    SYS_Initialize(NULL);
    
    TRISBbits.TRISB5 = 0; 
    LATBbits.LATB5 = 1;   

    /* Configure LED pin as digital output */
    LED_TRIS = 0;
    LED = 1; // Turn ON LED solid to indicate bootloader is active and checking SD

    // --- BAREBONE SPI3 INITIALIZATION ---
    // (Matches the configuration from main_2.c for the SD Card)
    SPI3CON = 0x10000120; // Off, Master Mode, 8-bit
    SPI3CON = 0x10008120; // On (ON = 1)
    
    // Give the SD card a moment to stabilize power
    delay_ms(1000);

    // =========================================================================
    // FIRMWARE UPDATE CHECK WORKFLOW (PETIT FATFS)
    // =========================================================================

    // 1. Initialize physical disk (SPI communication)
    DSTATUS init_status = disk_initialize();
    if (init_status != 0) {
        // Blink the exact error code to diagnose the failure
        blink_error_and_jump(init_status); 
    }

    // 2. Mount the FAT16/FAT32 File System
    if (pf_mount(&fs) != FR_OK) {
        // ERROR: File system not recognized
        blink_error_and_jump(2);
    }

    // 3. Try to open the firmware update file
    if (pf_open("UPDATE.HEX") != FR_OK) {
        // ERROR / NORMAL BOOT: File not found. Proceed to main application.
        blink_error_and_jump(3);
    }

    // =========================================================================
    // SUCCESS! FILE FOUND.
    // =========================================================================
    // If we reach this point, UPDATE.HEX exists and is open.
    // For this test, we will blink the LED extremely fast in an infinite loop.
    
    while (true)
    {
        LED = !LED;
        delay_ms(50); // Fast strobe effect
    }

    return (EXIT_FAILURE);
}

/*******************************************************************************
 End of File
*/