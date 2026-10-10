/*-----------------------------------------------------------------------*/
/* Low level disk I/O module for Petit FatFs - Adapted for PIC32MM       */
/*-----------------------------------------------------------------------*/

#include <xc.h>
#include <stdbool.h>
#include "diskio.h"

// --- PIN CONFIGURATION ---
// Atomic macros for Chip Select on RB5
#define SD_CS_LOW()  (LATBCLR = (1 << 5))
#define SD_CS_HIGH() (LATBSET = (1 << 5))

static bool is_sdhc = false;

// -----------------------------------------------------------------------
// BAREBONE SPI ROUTINES (Bulletproof Version)
// -----------------------------------------------------------------------

static void spi_send(uint8_t data) {
    SPI3BUF = data;                  
    while (!SPI3STATbits.SPIRBF);    
    (void)SPI3BUF;                   // Dummy read to clear RX buffer
    SPI3STATCLR = 0x40;              // Clear SPIROV (Overflow flag) just in case
}

static uint8_t spi_recv(void) {
    SPI3BUF = 0xFF;                  
    while (!SPI3STATbits.SPIRBF);    
    uint8_t data = SPI3BUF;
    SPI3STATCLR = 0x40;              // Clear SPIROV
    return data;                  
}

static void sd_send_cmd(uint8_t cmd, uint32_t arg, uint8_t crc) {
    spi_send(0x40 | cmd);
    spi_send((arg >> 24) & 0xFF);
    spi_send((arg >> 16) & 0xFF);
    spi_send((arg >> 8)  & 0xFF);
    spi_send(arg & 0xFF);
    spi_send(crc);
}

static uint8_t sd_get_response(void) {
    uint8_t r;
    uint32_t timeout = 40000; 
    while (timeout > 0) {
        r = spi_recv();
        if (r != 0xFF) return r; 
        timeout--;
    }
    return 0xFF; // Timeout
}

/*-----------------------------------------------------------------------*/
/* Initialize Disk Drive                                                 */
/*-----------------------------------------------------------------------*/
DSTATUS disk_initialize (void)
{
    // 1. Force hardware pins to digital and correct directions
    ANSELBCLR = (1 << 5) | (1 << 7) | (1 << 13);
    ANSELCCLR = (1 << 9);
    TRISBCLR = (1 << 5);  // CS = Output
    
    // 2. ULTRA SLOW SPEED FOR INIT (Maximum reliability)
    SPI3BRG = 0x003F; 
    
    SD_CS_HIGH();
    
    // 3. Give 200 clocks (25 bytes) with CS high to stabilize SD card
    for (int i = 0; i < 25; i++) spi_send(0xFF); 

    // ---- CMD0: GO_IDLE_STATE (With Retry Loop) ----
    uint8_t r1;
    int retries = 10;
    do {
        SD_CS_LOW();
        sd_send_cmd(0, 0x00000000, 0x95);
        r1 = sd_get_response();               
        SD_CS_HIGH(); 
        spi_send(0xFF); // Extra clock
        
        if (r1 == 0x01) break;
        
        // Small delay between retries
        for(volatile int j=0; j<10000; j++); 
        
    } while (--retries > 0);
    
    if (r1 != 0x01) return 5; // ERROR 5: CMD0 Failed (Card dead or deaf)

    // ---- CMD8: SEND_IF_COND ----
    SD_CS_LOW();
    sd_send_cmd(8, 0x000001AA, 0x87);             
    r1 = sd_get_response();
    uint8_t cmd8_extra[4];
    cmd8_extra[0] = spi_recv();
    cmd8_extra[1] = spi_recv();
    cmd8_extra[2] = spi_recv();
    cmd8_extra[3] = spi_recv();
    SD_CS_HIGH(); 
    spi_send(0xFF);

    bool v2_card = (r1 == 0x01);                  

    // ---- Loop: CMD55 + ACMD41 ----
    uint32_t tries = 20000; 
    do {
        // CMD55
        SD_CS_LOW();
        sd_send_cmd(55, 0x00000000, 0x65);
        r1 = sd_get_response();
        SD_CS_HIGH(); 
        spi_send(0xFF);

        // ACMD41
        SD_CS_LOW();
        uint32_t arg = v2_card ? 0x40000000 : 0x00000000; 
        sd_send_cmd(41, arg, 0x77);
        r1 = sd_get_response();
        SD_CS_HIGH(); 
        spi_send(0xFF);

        if (r1 == 0x00) break; // Ready
    } while (--tries);

    if (r1 != 0x00) return 6; // ERROR 6: ACMD41 Timeout

    // ---- CMD58: READ_OCR ----
    SD_CS_LOW();
    sd_send_cmd(58, 0x00000000, 0xFD);
    r1 = sd_get_response();
    uint8_t ocr[4];
    ocr[0] = spi_recv(); 
    ocr[1] = spi_recv();
    ocr[2] = spi_recv();
    ocr[3] = spi_recv(); 
    SD_CS_HIGH(); 
    spi_send(0xFF);

    if (r1 != 0x00) return 7; // ERROR 7: CMD58 Failed

    is_sdhc = (ocr[0] & 0x40) != 0;

    // ---- CMD16: SET_BLOCKLEN ----
    if (!is_sdhc) {
        SD_CS_LOW();
        sd_send_cmd(16, 512, 0x15);
        r1 = sd_get_response();
        SD_CS_HIGH(); 
        spi_send(0xFF);
        if (r1 != 0x00) return 8; // ERROR 8: CMD16 Failed
    }
    
    // Initialization complete, switch back to high speed
    SPI3BRG = 0x0001; 

    return 0; // Success (RES_OK)
}

/*-----------------------------------------------------------------------*/
/* Read Partial Sector                                                   */
/*-----------------------------------------------------------------------*/
DRESULT disk_readp (
    BYTE* buff,     
    DWORD sector,   
    UINT offset,    
    UINT count      
)
{
    uint32_t arg = is_sdhc ? sector : (sector * 512);

    SD_CS_LOW();
    sd_send_cmd(17, arg, 0xFF); // CMD17: READ_SINGLE_BLOCK
    
    uint8_t r1;
    uint32_t timeout_r1 = 40000;
    do {
        r1 = spi_recv();
    } while (r1 == 0xFF && --timeout_r1);
    
    if (r1 != 0x00) { SD_CS_HIGH(); spi_send(0xFF); return RES_ERROR; }

    // Wait for data start token 0xFE
    uint32_t wait = 100000;
    uint8_t token;
    do {
        token = spi_recv();
        if (token == 0xFE) break;
    } while (--wait);

    if (token != 0xFE) { SD_CS_HIGH(); spi_send(0xFF); return RES_ERROR; }

    for (UINT i = 0; i < offset; i++) spi_recv();

    if (buff) {
        for (UINT i = 0; i < count; i++) buff[i] = spi_recv();
    } else {
        for (UINT i = 0; i < count; i++) spi_recv();
    }

    for (UINT i = 0; i < 512 - offset - count; i++) spi_recv();

    spi_recv(); spi_recv();

    SD_CS_HIGH();
    spi_send(0xFF);
    return RES_OK;
}

/*-----------------------------------------------------------------------*/
/* Write Partial Sector (Not used)                                       */
/*-----------------------------------------------------------------------*/
DRESULT disk_writep (
    const BYTE* buff,     
    DWORD sc              
)
{
    return RES_OK;
}