/*******************************************************************************
  Main Source File (Bootloader)

  Company:
    Microchip Technology Inc.

  File Name:
    main.c

  Summary:
    Main entry point for the bootloader.

  Description:
    Initializes system modules and provides firmware update handling.
 *******************************************************************************/

#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include "definitions.h"                // SYS function prototypes
#include <xc.h>

// Pin mapping for LED activity
#define LED       PORTAbits.RA2
#define LED_TRIS  TRISAbits.TRISA2

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

// main app reset add
#define USER_APP_RESET_ADDRESS 0x9D000000

void JumpToApp(void)
{
    __builtin_disable_interrupts();
    void (*fptr)(void);
    fptr = (void (*)(void))(USER_APP_RESET_ADDRESS | 1);
    fptr(); // Ejecuta el salto
}

int main(void)
{
    /* Initialize all Harmony modules (Clocks, Pins, Peripherals) */
    SYS_Initialize(NULL);

    /* Configure LED pin as digital output */
    LED_TRIS = 0;
    LED = 0;

    while (true)
    {
        /* Toggle LED to confirm bootloader is running */
        // Reemplaza con tus macros de LED (ej. LED_Toggle();)
    int i, j;
    for(i = 0; i < 6; i++) {
        LED = !LED;
        for(j = 0; j < 1000000; j++) { asm("nop"); } // Retardo simple
    }
        
       

        JumpToApp();
        return 0;
        
    }

    return (EXIT_FAILURE);
}

/*******************************************************************************
 End of File
*/