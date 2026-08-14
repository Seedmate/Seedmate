/*******************************************************************************
 * Project:     SeedMate
 * File:        TFT.c
 *
 * Summary:
 *   Display management
 *
 *
 *
 * Author:      Seedmate
 * Date:        14/8/2026
 * Version:     v1.2
 ******************************************************************************/

// *****************************************************************************
// *****************************************************************************
// Section: Included Files
// *****************************************************************************
// *****************************************************************************

#include <stddef.h>                     // Defines NULL
#include <stdbool.h>                    // Defines true
#include <stdlib.h>                     // Defines EXIT_FAILURE
#include "definitions.h"                // SYS function prototypes 
#include "SPI.h"                        // SPI functions 
#include "TFT.h"   
#include <string.h>


int wrap = 1;
unsigned int colstart = 0, rowstart = 0, _tft_type;

const char Font[] = {
0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x5F, 0x00, 0x00,
0x00, 0x07, 0x00, 0x07, 0x00,
0x14, 0x7F, 0x14, 0x7F, 0x14,
0x24, 0x2A, 0x7F, 0x2A, 0x12,
0x23, 0x13, 0x08, 0x64, 0x62,
0x36, 0x49, 0x56, 0x20, 0x50,
0x00, 0x08, 0x07, 0x03, 0x00,
0x00, 0x1C, 0x22, 0x41, 0x00,
0x00, 0x41, 0x22, 0x1C, 0x00,
0x2A, 0x1C, 0x7F, 0x1C, 0x2A,
0x08, 0x08, 0x3E, 0x08, 0x08,
0x00, 0x80, 0x70, 0x30, 0x00,
0x08, 0x08, 0x08, 0x08, 0x08,
0x00, 0x00, 0x60, 0x60, 0x00,
0x20, 0x10, 0x08, 0x04, 0x02,
0x3E, 0x51, 0x49, 0x45, 0x3E,
0x00, 0x42, 0x7F, 0x40, 0x00,
0x72, 0x49, 0x49, 0x49, 0x46,
0x21, 0x41, 0x49, 0x4D, 0x33,
0x18, 0x14, 0x12, 0x7F, 0x10,
0x27, 0x45, 0x45, 0x45, 0x39,
0x3C, 0x4A, 0x49, 0x49, 0x31,
0x41, 0x21, 0x11, 0x09, 0x07,
0x36, 0x49, 0x49, 0x49, 0x36,
0x46, 0x49, 0x49, 0x29, 0x1E,
0x00, 0x00, 0x14, 0x00, 0x00,
0x00, 0x40, 0x34, 0x00, 0x00,
0x00, 0x08, 0x14, 0x22, 0x41,
0x14, 0x14, 0x14, 0x14, 0x14,
0x00, 0x41, 0x22, 0x14, 0x08,
0x02, 0x01, 0x59, 0x09, 0x06,
0x3E, 0x41, 0x5D, 0x59, 0x4E,
0x7C, 0x12, 0x11, 0x12, 0x7C,
0x7F, 0x49, 0x49, 0x49, 0x36,
0x3E, 0x41, 0x41, 0x41, 0x22,
0x7F, 0x41, 0x41, 0x41, 0x3E,
0x7F, 0x49, 0x49, 0x49, 0x41,
0x7F, 0x09, 0x09, 0x09, 0x01,
0x3E, 0x41, 0x41, 0x51, 0x73,
0x7F, 0x08, 0x08, 0x08, 0x7F,
0x00, 0x41, 0x7F, 0x41, 0x00,
0x20, 0x40, 0x41, 0x3F, 0x01,
0x7F, 0x08, 0x14, 0x22, 0x41,
0x7F, 0x40, 0x40, 0x40, 0x40,
0x7F, 0x02, 0x1C, 0x02, 0x7F,
0x7F, 0x04, 0x08, 0x10, 0x7F,
0x3E, 0x41, 0x41, 0x41, 0x3E,
0x7F, 0x09, 0x09, 0x09, 0x06,
0x3E, 0x41, 0x51, 0x21, 0x5E,
0x7F, 0x09, 0x19, 0x29, 0x46
};
const char Font2[] = {
0x26, 0x49, 0x49, 0x49, 0x32,
0x03, 0x01, 0x7F, 0x01, 0x03,
0x3F, 0x40, 0x40, 0x40, 0x3F,
0x1F, 0x20, 0x40, 0x20, 0x1F,
0x3F, 0x40, 0x38, 0x40, 0x3F,
0x63, 0x14, 0x08, 0x14, 0x63,
0x03, 0x04, 0x78, 0x04, 0x03,
0x61, 0x59, 0x49, 0x4D, 0x43,
0x00, 0x7F, 0x41, 0x41, 0x41,
0x02, 0x04, 0x08, 0x10, 0x20,
0x00, 0x41, 0x41, 0x41, 0x7F,
0x04, 0x02, 0x01, 0x02, 0x04,
0x40, 0x40, 0x40, 0x40, 0x40,
0x00, 0x03, 0x07, 0x08, 0x00,
0x20, 0x54, 0x54, 0x78, 0x40,
0x7F, 0x28, 0x44, 0x44, 0x38,
0x38, 0x44, 0x44, 0x44, 0x28,
0x38, 0x44, 0x44, 0x28, 0x7F,
0x38, 0x54, 0x54, 0x54, 0x18,
0x00, 0x08, 0x7E, 0x09, 0x02,
0x18, 0xA4, 0xA4, 0x9C, 0x78,
0x7F, 0x08, 0x04, 0x04, 0x78,
0x00, 0x44, 0x7D, 0x40, 0x00,
0x20, 0x40, 0x40, 0x3D, 0x00,
0x7F, 0x10, 0x28, 0x44, 0x00,
0x00, 0x41, 0x7F, 0x40, 0x00,
0x7C, 0x04, 0x78, 0x04, 0x78,
0x7C, 0x08, 0x04, 0x04, 0x78,
0x38, 0x44, 0x44, 0x44, 0x38,
0xFC, 0x18, 0x24, 0x24, 0x18,
0x18, 0x24, 0x24, 0x18, 0xFC,
0x7C, 0x08, 0x04, 0x04, 0x08,
0x48, 0x54, 0x54, 0x54, 0x24,
0x04, 0x04, 0x3F, 0x44, 0x24,
0x3C, 0x40, 0x40, 0x20, 0x7C,
0x1C, 0x20, 0x40, 0x20, 0x1C,
0x3C, 0x40, 0x30, 0x40, 0x3C,
0x44, 0x28, 0x10, 0x28, 0x44,
0x4C, 0x90, 0x90, 0x90, 0x7C,
0x44, 0x64, 0x54, 0x4C, 0x44,
0x00, 0x08, 0x36, 0x41, 0x00,
0x00, 0x00, 0x77, 0x00, 0x00,
0x00, 0x41, 0x36, 0x08, 0x00,
0x02, 0x01, 0x02, 0x04, 0x02
};
//unsigned char SPI(unsigned char val);
//void LCDinit(void);


/*void area(unsigned char x0,unsigned char y0, unsigned char x1,unsigned char y1);
void rectan(unsigned char x0,unsigned char y0, unsigned char x1,unsigned char y1, unsigned int color);
void pixel(unsigned char x,unsigned char y, unsigned int color);
void chr(unsigned char x, unsigned char y, unsigned char fig, unsigned int seg_color);
void Rcmd1();
void Rcmd2red();
void Rcmd3();
void LCDinit2();
void drawtext(unsigned int x, unsigned int y, char *_text, unsigned int color, unsigned int bg, unsigned int size);
void drawChar(unsigned int x, unsigned int y, unsigned int c, unsigned int color, unsigned int bg,  unsigned int size);
void drawPixel(unsigned int x, unsigned int y, unsigned int color);
void setAddrWindow(unsigned int x0, unsigned int y0, unsigned int x1, unsigned int y1);*/
// *****************************************************************************
// *****************************************************************************
// Section: Main Entry Point
// *****************************************************************************
// *****************************************************************************

void area(unsigned char x0,unsigned char y0, unsigned char x1,unsigned char y1)
{
  command(0x2A); // Column addr set
  send_data(0x00);
  send_data(x0);     // XSTART 
  send_data(0x00);
  send_data(x1);     // XEND

  command(0x2B); // Row addr set
  send_data(0x00);
  send_data(y0);     // YSTART
  send_data(0x00);
  send_data(y1);     // YEND

  command(0x2C); // write to RAM
} 


void rectan(unsigned char x0,unsigned char y0, unsigned char x1,unsigned char y1, unsigned int color) 
{
 unsigned int i;
  area(x0,y0,x1,y1);
  for(i=(y1 - y0 + 1) * (x1 - x0 + 1); i > 0; i--) {		  

	    A0_LCD=1;       // data mode
		//CS_LCD=0;
		SPI(color >> 8);
		SPI(color);
		//CS_LCD=1;
  }
}



void chr(unsigned char x, unsigned char y, unsigned char fig, unsigned int seg_color)
{
	switch (fig) {
        case 0: rectan(x,y+3,x+2,y+13,seg_color);	//d
        		rectan(x+1,y,x+13,y+2,seg_color);	//e
				rectan(x+15,y,x+27,y+2,seg_color);	//f
        		rectan(x+26,y+3,x+28,y+13,seg_color);	//a
				rectan(x+15,y+14,x+27,y+16,seg_color);	//b
        		rectan(x+1,y+14,x+13,y+16,seg_color);	//c
        		break;
        case 1: rectan(x+15,y+14,x+27,y+16,seg_color);	//b
        		rectan(x+1,y+14,x+13,y+16,seg_color);	//c
        		break;			
        case 2: rectan(x,y+3,x+2,y+13,seg_color);	//d
        		rectan(x+13,y+3,x+15,y+13,seg_color);	//g
        		rectan(x+26,y+3,x+28,y+13,seg_color);	//a
				rectan(x+15,y+14,x+27,y+16,seg_color);	//b
        		rectan(x+1,y,x+13,y+2,seg_color);	//e
        		break;		
        case 3: rectan(x,y+3,x+2,y+13,seg_color);	//d
        		rectan(x+13,y+3,x+15,y+13,seg_color);	//g
        		rectan(x+26,y+3,x+28,y+13,seg_color);	//a
				rectan(x+15,y+14,x+27,y+16,seg_color);	//b
        		rectan(x+1,y+14,x+13,y+16,seg_color);	//c
        		break;
        case 4: rectan(x+15,y,x+27,y+2,seg_color);	//f
        		rectan(x+13,y+3,x+15,y+13,seg_color);	//g
        		rectan(x+15,y+14,x+27,y+16,seg_color);	//b
        		rectan(x+1,y+14,x+13,y+16,seg_color);	//c
        		break;
        case 5: rectan(x+15,y,x+27,y+2,seg_color);	//f
        		rectan(x+13,y+3,x+15,y+13,seg_color);	//g
        		rectan(x+26,y+3,x+28,y+13,seg_color);	//a
				rectan(x,y+3,x+2,y+13,seg_color);	//d
        		rectan(x+1,y+14,x+13,y+16,seg_color);	//c
        		break;		
        case 6: rectan(x,y+3,x+2,y+13,seg_color);	//d
        		rectan(x+13,y+3,x+15,y+13,seg_color);	//g
        		rectan(x+15,y,x+27,y+2,seg_color);	//f
				rectan(x+1,y,x+13,y+2,seg_color);	//e
        		rectan(x+1,y+14,x+13,y+16,seg_color);	//c
                rectan(x+26,y+3,x+28,y+13,seg_color);	//a
        		break;				
        case 7: rectan(x+26,y+3,x+28,y+13,seg_color);	//a
				rectan(x+15,y+14,x+27,y+16,seg_color);	//b
        		rectan(x+1,y+14,x+13,y+16,seg_color);	//c
        		break;
        case 8: rectan(x,y+3,x+2,y+13,seg_color);	//d
                rectan(x+15,y,x+27,y+2,seg_color);	//f
        		rectan(x+13,y+3,x+15,y+13,seg_color);	//g
        		rectan(x+26,y+3,x+28,y+13,seg_color);	//a
				rectan(x+15,y+14,x+27,y+16,seg_color);	//b
        		rectan(x+1,y,x+13,y+2,seg_color);	//e
        		rectan(x+1,y+14,x+13,y+16,seg_color);	//c
        		break;		
        case 9: rectan(x+1,y+14,x+13,y+16,seg_color);	//c
        		rectan(x+13,y+3,x+15,y+13,seg_color);	//g
        		rectan(x+26,y+3,x+28,y+13,seg_color);	//a
				rectan(x+15,y+14,x+27,y+16,seg_color);	//b
        		rectan(x+15,y,x+27,y+2,seg_color);	//f 
                rectan(x,y+3,x+2,y+13,seg_color);	//d
        		break;
        case 10: rectan(x+1,y+1,x+5,y+3,seg_color);	//,
        		rectan(x,y,x+1,y+1,seg_color);	//
				break;        
        case 11: rectan(x,y,x+16,y+2,seg_color);	//H
        		rectan(x,y+8,x+16,y+10,seg_color);	//
        		rectan(x+7,y+2,x+9,y+8,seg_color);	//
				break;		
        case 12: rectan(x,y,x+2,y+8,seg_color);	//z
        		rectan(x+10,y,x+12,y+8,seg_color);	//		
        		rectan(x+2,y,x+4,y+2,seg_color);	//
        		rectan(x+4,y+2,x+6,y+4,seg_color);	//
        		rectan(x+6,y+4,x+8,y+6,seg_color);	//
        		rectan(x+8,y+6,x+10,y+8,seg_color);	//
				break;
		case 13: rectan(x,y+2,x+2,y+7,seg_color);	//S
        		rectan(x+6,y+2,x+8,y+7,seg_color);	//		
        		rectan(x+12,y+2,x+14,y+7,seg_color);	//
        		rectan(x+1,y,x+3,y+2,seg_color);	//
        		rectan(x+8,y,x+13,y+2,seg_color);	//
        		rectan(x+1,y+7,x+6,y+9,seg_color);	//
        		rectan(x+11,y+7,x+13,y+9,seg_color);	//
				break;
		case 14: rectan(x,y,x+11,y+2,seg_color);	//n
        		rectan(x+7,y+2,x+9,y+4,seg_color);	//		
        		rectan(x+9,y+4,x+11,y+8,seg_color);	//
        		rectan(x,y+7,x+9,y+9,seg_color);	//
				break;
		case 15: rectan(x,y,x+4,y+2,seg_color);	//u
        		rectan(x+4,y+1,x+14,y+3,seg_color);	//		
        		rectan(x+8,y+3,x+10,y+5,seg_color);	//
        		rectan(x+6,y+5,x+8,y+9,seg_color);	//
        		rectan(x+8,y+8,x+14,y+10,seg_color);	//
				break;		
													
 }
}       

void pixel(unsigned char x,unsigned char y, unsigned int color)
{
	  area(x,y,x+1,y+1);
	  send_data(color >> 8);
	  send_data(color);
}

void Rcmd1(){
  command(ST7735_SWRESET);
  delay_ms(150);
  command(ST7735_SLPOUT);
  delay_ms(500);
  command(ST7735_FRMCTR1);
  send_data(0x01);
  send_data(0x2C);
  send_data(0x2D);
  command(ST7735_FRMCTR2);
  send_data(0x01);
  send_data(0x2C);
  send_data(0x2D);
  command(ST7735_FRMCTR3);
  send_data(0x01); send_data(0x2C); send_data(0x2D);
  send_data(0x01); send_data(0x2C); send_data(0x2D);
  command(ST7735_INVCTR);
  send_data(0x07);
  command(ST7735_PWCTR1);
  send_data(0xA2);
  send_data(0x02);
  send_data(0x84);
  command(ST7735_PWCTR2);
  send_data(0xC5);
  command(ST7735_PWCTR3);
  send_data(0x0A);
  send_data(0x00);
  command(ST7735_PWCTR4);
  send_data(0x8A);
  send_data(0x2A);
  command(ST7735_PWCTR5);
  send_data(0x8A);
  send_data(0xEE);
  command(ST7735_VMCTR1);
  send_data(0x0E);
  command(ST7735_INVOFF);
  command(ST7735_MADCTL);
  send_data(0xC8);
  command(ST7735_COLMOD);
  send_data(0x05); 
}
void Rcmd2red(){
  command(ST7735_CASET);
  send_data(0x00); send_data(0x00);
  send_data(0x00); send_data(0x7F);
  command(ST7735_RASET);
  send_data(0x00); send_data(0x00);
  send_data(0x00); send_data(0x9F);
}
void Rcmd3(){
  command(ST7735_GMCTRP1);
  send_data(0x02); send_data(0x1C); send_data(0x07); send_data(0x12);
  send_data(0x37); send_data(0x32); send_data(0x29); send_data(0x2D);
  send_data(0x29); send_data(0x25); send_data(0x2B); send_data(0x39);
  send_data(0x00); send_data(0x01); send_data(0x03); send_data(0x10);
  command(ST7735_GMCTRN1);
  send_data(0x03); send_data(0x1D); send_data(0x07); send_data(0x06);
  send_data(0x2E); send_data(0x2C); send_data(0x29); send_data(0x2D);
  send_data(0x2E); send_data(0x2E); send_data(0x37); send_data(0x3F);
  send_data(0x00); send_data(0x00); send_data(0x02); send_data(0x10);
  command(ST7735_NORON);
  delay_ms(10);
  command(ST7735_DISPON);
  delay_ms(100);
}

void LCDinit1(){
    R_LCD=1;			//hardware reset
    delay_ms(10);
    R_LCD=0;
    delay_ms(100);
    R_LCD=1;
    delay_ms(200);
    A0_LCD=0;
    Rcmd1();
    command(ST7735_MADCTL);
    send_data(0x074);// GIRO OK!  
}

void LCDinit2(){


    Rcmd2red();
    Rcmd3();  
    command(ST7735_MADCTL);
    send_data(0x074);// GIRO OK!  


}

void drawFastVLine(unsigned int x, unsigned int y, unsigned int h, unsigned int color){
  unsigned int hi, lo;
  if((x >= _width) || (y >= _height))
    return;
  if((y + h - 1) >= _height)
    h = _height - y;
  hi = color >> 8; lo = color;
  setAddrWindow(x, y, x, y + h - 1);

  while (h--) {
    send_data(hi);
    send_data(lo);
  }
 
}

void drawFastHLine(unsigned int x, unsigned int y, unsigned int l, unsigned int color){
  unsigned int hi, lo;
  if((x >= _width) || (y >= _height))
    return;
  if((x + l - 1) >= _width)
    l = _width - x;
  hi = color >> 8; lo = color;
  setAddrWindow(x, y, x + l -1, y);

  while (l--) {
    send_data(hi);
    send_data(lo);
  }
 
}

void fillRect(unsigned int x, unsigned int y, unsigned int w, unsigned int h, unsigned int color) {
  signed int i;
  // Update in subclasses if desired!
  for (i = x; i < x + w; i++) {
    drawFastVLine(i, y, h, color);
  }
}

void drawChar(unsigned int x, unsigned int y, unsigned int c, unsigned int color, unsigned int bg,  unsigned int size)
    {
      int i, j;
      if((x >= _width) || (y >= _height))
        return;
      if(size < 1) size = 1;
      if((c < ' ') || (c > '~'))
        c = '?';
      for(i=0; i<5; i++ ) {
        unsigned int line;
        if(c < 'S')
          line = Font[(c - 32)*5 + i];
        else
          line = Font2[(c - 'S')*5 + i];
        for(j=0; j<7; j++, line >>= 1) {
          if(line & 0x01) {
            if(size == 1) drawPixel(x+i, y+j, color);
            else          fillRect(x+(i*size), y+(j*size), size, size, color);
          }
          else if(bg != color) {
               if(size == 1) drawPixel(x+i, y+j, bg);
               else          fillRect(x+i*size, y+j*size, size, size, bg);
            }
        }
      }
    }
 
void drawtext(unsigned int x, unsigned int y, char *_text, unsigned int color, unsigned int bg, unsigned int size)
    {
      unsigned int cursor_x, cursor_y;
      unsigned int textsize, i;
      cursor_x = x, cursor_y = y;
      textsize = strlen(_text);
      for(i = 0; i < textsize; i++){
        if(wrap && ((cursor_x + size * 5) > _width)){
          cursor_x = 0;
          cursor_y = cursor_y + size * 7 + 3 ;
          if(cursor_y > _height) cursor_y = _height;
          if(_text[i] == 0x20) goto _skip; }
        drawChar(cursor_x, cursor_y, _text[i], color, bg, size);
        cursor_x = cursor_x + size * 6;
        if(cursor_x > _width) cursor_x = _width;
        _skip:;}
    }
 



void setAddrWindow(unsigned int x0, unsigned int y0, unsigned int x1, unsigned int y1)
    {
      command(ST7735_CASET);
      send_data(0);
      send_data(x0 + colstart);
      send_data(0);
      send_data(x1 + colstart);
      command(ST7735_RASET);
      send_data(0);
      send_data(y0 + rowstart);
      send_data(0);
      send_data(y1 + rowstart);
      command(ST7735_RAMWR); // Write to RAM
    }
void drawPixel(unsigned int x, unsigned int y, unsigned int color)
    {
      if((x >= _width) || (y >= _height)) 
        return;
      setAddrWindow(x,y,x+1,y+1);
      send_data(color >> 8);
      send_data(color & 0xFF);
    }



void LCDinit(void)
{
	unsigned char i;
	R_LCD=1;			//hardware reset
	delay_ms(10);
	R_LCD=0;
	delay_ms(10);
    
	R_LCD=1;
	delay_ms(200);
    
	
	command(0x01); // sw reset
	delay_ms(150);
    

  	command(0x11); // Sleep out
 	delay_ms(100);
   
	  
	command(0x3A); //color mode
	send_data(0x05);	//16 bits
	    
	  //command(0x36); //Memory access ctrl (directions)
	  //send_data(0x40);
	  //command(0x21); //inversion on
	  
	command(0x2D);	//color look up table
	send_data(0); for(i=1;i<32;i++){send_data(i*2);}
	for(i=0;i<64;i++){send_data(i);}	
	send_data(0); for(i=1;i<32;i++){send_data(i*2);}	 
	  
	command(0x13); //Normal display on
	command(0x29); //Main screen turn on
}	  
/*******************************************************************************
 End of File
*/

