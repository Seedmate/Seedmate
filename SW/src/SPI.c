#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include "definitions.h"                // SYS function prototypes 
#include "SPI.h"    

//#define SCK       PORTBbits.RB8   //SCL
#define A0_LCD    PORTBbits.RB5   //A0 LCD

//prototypes
//unsigned char SPI(unsigned char val);
//void command(unsigned char cmd);
//void send_data(unsigned char data);

//void delay_ms(unsigned int milliseconds) ;

unsigned char SPI(unsigned char val)		// send character over SPI
{
	SPI1BUF = val;			// load character
    // Wait for the transfer to complete
    while (!SPI1STATbits.SPIRBF) {
        // Loop until the transfer is complete
    }

    
	return SPI1BUF;		// received character
}

void command(unsigned char cmd)
{
	A0_LCD=0;	// Command Mode
	//CS_LCD=0;	// Select the LCD	(active low)
	SPI(cmd);	// set up data on bus
	//CS_LCD=1;	// Deselect LCD (active low)
}

void send_data(unsigned char data)
{
	A0_LCD=1;       // data mode
	//CS_LCD=0;       // chip selected
	SPI(data);      // set up data on bus
	//CS_LCD=1;       // deselect chip
}

void delay_ms(unsigned int milliseconds) {
    volatile unsigned int count;
    while (milliseconds > 0) {
        count = 1000; // Ajusta este valor según la velocidad de tu procesador
            while (count > 0) {
                count--;
            }
        milliseconds--;
    }
}