#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include "definitions.h"                // SYS function prototypes 


//#define SCK       PORTBbits.RB8   //SCL


//prototypes
unsigned char SPI(unsigned char val);
void command(unsigned char cmd);
void send_data(unsigned char data);
void delay_ms(unsigned int milliseconds) ;
