#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include "definitions.h"                // SYS function prototypes 


//#define SCK       PORTBbits.RB8   //SCL
#define _width         160
#define _height        128
#define ST7735_NOP     0x00
#define ST7735_SWRESET 0x01
#define ST7735_RDDID   0x04
#define ST7735_RDDST   0x09
#define ST7735_SLPIN   0x10
#define ST7735_SLPOUT  0x11
#define ST7735_PTLON   0x12
#define ST7735_NORON   0x13
#define ST7735_INVOFF  0x20
#define ST7735_INVON   0x21
#define ST7735_DISPOFF 0x28
#define ST7735_DISPON  0x29
#define ST7735_CASET   0x2A
#define ST7735_RASET   0x2B
#define ST7735_RAMWR   0x2C
#define ST7735_RAMRD   0x2E
#define ST7735_PTLAR   0x30
#define ST7735_VSCRDEF 0x33
#define ST7735_COLMOD  0x3A
#define ST7735_MADCTL  0x36
#define ST7735_VSCRSADD 0x37
#define ST7735_FRMCTR1 0xB1
#define ST7735_FRMCTR2 0xB2
#define ST7735_FRMCTR3 0xB3
#define ST7735_INVCTR  0xB4
#define ST7735_DISSET5 0xB6
#define ST7735_PWCTR1  0xC0
#define ST7735_PWCTR2  0xC1
#define ST7735_PWCTR3  0xC2
#define ST7735_PWCTR4  0xC3
#define ST7735_PWCTR5  0xC4
#define ST7735_VMCTR1  0xC5
#define ST7735_RDID1   0xDA
#define ST7735_RDID2   0xDB
#define ST7735_RDID3   0xDC
#define ST7735_RDID4   0xDD
#define ST7735_PWCTR6  0xFC
#define ST7735_GMCTRP1 0xE0
#define ST7735_GMCTRN1 0xE1
// Color definitions
#define ST7735_BLACK   0x0000
#define ST7735_GREY    0x7BEF
#define ST7735_BLUE    0x001F
#define ST7735_RED     0xF800
#define ST7735_GREEN   0x07E0
#define ST7735_CYAN    0x07FF
#define ST7735_TEAL    0x0555
#define ST7735_MAGENTA 0xF81F
#define ST7735_PURPLE  0x8010
#define ST7735_PINK    0xF49A
#define ST7735_YELLOW  0xFFE0
#define ST7735_ORANGE  0xFB40
#define ST7735_WHITE   0xFFFF
#define ST7735_DKGREN  0x0B40
#define ST7735_BROWN   0x82C5
#define ST7735_CRIMSON 0xA004






// Color definitions
#define	BLACK   0x0000
#define	BLUE    0x001F
#define	RED     0xF800
#define	GREEN   0x07E0
#define CYAN    0x07FF
#define MAGENTA 0xF81F
#define YELLOW  0xFFE0  
#define WHITE   0xFFFF
#define fx  90  
#define px  30

#define A0_LCD    PORTBbits.RB5   //A0 LCD
#define R_LCD     PORTBbits.RB4   //RST LCD

//prototypes
void area(unsigned char x0,unsigned char y0, unsigned char x1,unsigned char y1);
void rectan(unsigned char x0,unsigned char y0, unsigned char x1,unsigned char y1, unsigned int color);
void pixel(unsigned char x,unsigned char y, unsigned int color);
void chr(unsigned char x, unsigned char y, unsigned char fig, unsigned int seg_color);
void Rcmd1();
void Rcmd2red();
void Rcmd3();
void LCDinit1();
void LCDinit2();
void drawtext(unsigned int x, unsigned int y, char *_text, unsigned int color, unsigned int bg, unsigned int size);
void drawChar(unsigned int x, unsigned int y, unsigned int c, unsigned int color, unsigned int bg,  unsigned int size);
void drawPixel(unsigned int x, unsigned int y, unsigned int color);
void setAddrWindow(unsigned int x0, unsigned int y0, unsigned int x1, unsigned int y1);
void fillRect(unsigned int x, unsigned int y, unsigned int w, unsigned int h, unsigned int color);
void drawFastVLine(unsigned int x, unsigned int y, unsigned int h, unsigned int color);
void drawFastHLine(unsigned int x, unsigned int y, unsigned int h, unsigned int color);