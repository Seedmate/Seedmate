/*******************************************************************************
  GPIO PLIB

  Company:
    Microchip Technology Inc.

  File Name:
    plib_gpio.h

  Summary:
    GPIO PLIB Header File

  Description:
    This library provides an interface to control and interact with Parallel
    Input/Output controller (GPIO) module.

*******************************************************************************/

/*******************************************************************************
* Copyright (C) 2019 Microchip Technology Inc. and its subsidiaries.
*
* Subject to your compliance with these terms, you may use Microchip software
* and any derivatives exclusively with Microchip products. It is your
* responsibility to comply with third party license terms applicable to your
* use of third party software (including open source software) that may
* accompany Microchip software.
*
* THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
* EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
* WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
* PARTICULAR PURPOSE.
*
* IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT, SPECIAL, PUNITIVE,
* INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE OF ANY KIND
* WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF MICROCHIP HAS
* BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE FORESEEABLE. TO THE
* FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL LIABILITY ON ALL CLAIMS IN
* ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED THE AMOUNT OF FEES, IF ANY,
* THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR THIS SOFTWARE.
*******************************************************************************/

#ifndef PLIB_GPIO_H
#define PLIB_GPIO_H

#include <device.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// DOM-IGNORE-BEGIN
#ifdef __cplusplus  // Provide C++ Compatibility

    extern "C" {

#endif
// DOM-IGNORE-END

// *****************************************************************************
// *****************************************************************************
// Section: Data types and constants
// *****************************************************************************
// *****************************************************************************


/*** Macros for BT1 pin ***/
#define BT1_Set()               (LATBSET = (1<<2))
#define BT1_Clear()             (LATBCLR = (1<<2))
#define BT1_Toggle()            (LATBINV= (1<<2))
#define BT1_OutputEnable()      (TRISBCLR = (1<<2))
#define BT1_InputEnable()       (TRISBSET = (1<<2))
#define BT1_Get()               ((PORTB >> 2) & 0x1)
#define BT1_GetLatch()          ((LATB >> 2) & 0x1)
#define BT1_PIN                  GPIO_PIN_RB2

/*** Macros for BT4 pin ***/
#define BT4_Set()               (LATBSET = (1<<3))
#define BT4_Clear()             (LATBCLR = (1<<3))
#define BT4_Toggle()            (LATBINV= (1<<3))
#define BT4_OutputEnable()      (TRISBCLR = (1<<3))
#define BT4_InputEnable()       (TRISBSET = (1<<3))
#define BT4_Get()               ((PORTB >> 3) & 0x1)
#define BT4_GetLatch()          ((LATB >> 3) & 0x1)
#define BT4_PIN                  GPIO_PIN_RB3

/*** Macros for BT2 pin ***/
#define BT2_Set()               (LATCSET = (1<<0))
#define BT2_Clear()             (LATCCLR = (1<<0))
#define BT2_Toggle()            (LATCINV= (1<<0))
#define BT2_OutputEnable()      (TRISCCLR = (1<<0))
#define BT2_InputEnable()       (TRISCSET = (1<<0))
#define BT2_Get()               ((PORTC >> 0) & 0x1)
#define BT2_GetLatch()          ((LATC >> 0) & 0x1)
#define BT2_PIN                  GPIO_PIN_RC0

/*** Macros for BT3 pin ***/
#define BT3_Set()               (LATCSET = (1<<1))
#define BT3_Clear()             (LATCCLR = (1<<1))
#define BT3_Toggle()            (LATCINV= (1<<1))
#define BT3_OutputEnable()      (TRISCCLR = (1<<1))
#define BT3_InputEnable()       (TRISCSET = (1<<1))
#define BT3_Get()               ((PORTC >> 1) & 0x1)
#define BT3_GetLatch()          ((LATC >> 1) & 0x1)
#define BT3_PIN                  GPIO_PIN_RC1

/*** Macros for BT5 pin ***/
#define BT5_Set()               (LATCSET = (1<<2))
#define BT5_Clear()             (LATCCLR = (1<<2))
#define BT5_Toggle()            (LATCINV= (1<<2))
#define BT5_OutputEnable()      (TRISCCLR = (1<<2))
#define BT5_InputEnable()       (TRISCSET = (1<<2))
#define BT5_Get()               ((PORTC >> 2) & 0x1)
#define BT5_GetLatch()          ((LATC >> 2) & 0x1)
#define BT5_PIN                  GPIO_PIN_RC2

/*** Macros for LED pin ***/
#define LED_Set()               (LATASET = (1<<2))
#define LED_Clear()             (LATACLR = (1<<2))
#define LED_Toggle()            (LATAINV= (1<<2))
#define LED_OutputEnable()      (TRISACLR = (1<<2))
#define LED_InputEnable()       (TRISASET = (1<<2))
#define LED_Get()               ((PORTA >> 2) & 0x1)
#define LED_GetLatch()          ((LATA >> 2) & 0x1)
#define LED_PIN                  GPIO_PIN_RA2

/*** Macros for R_LCD pin ***/
#define R_LCD_Set()               (LATBSET = (1<<4))
#define R_LCD_Clear()             (LATBCLR = (1<<4))
#define R_LCD_Toggle()            (LATBINV= (1<<4))
#define R_LCD_OutputEnable()      (TRISBCLR = (1<<4))
#define R_LCD_InputEnable()       (TRISBSET = (1<<4))
#define R_LCD_Get()               ((PORTB >> 4) & 0x1)
#define R_LCD_GetLatch()          ((LATB >> 4) & 0x1)
#define R_LCD_PIN                  GPIO_PIN_RB4

/*** Macros for BT6 pin ***/
#define BT6_Set()               (LATASET = (1<<4))
#define BT6_Clear()             (LATACLR = (1<<4))
#define BT6_Toggle()            (LATAINV= (1<<4))
#define BT6_OutputEnable()      (TRISACLR = (1<<4))
#define BT6_InputEnable()       (TRISASET = (1<<4))
#define BT6_Get()               ((PORTA >> 4) & 0x1)
#define BT6_GetLatch()          ((LATA >> 4) & 0x1)
#define BT6_PIN                  GPIO_PIN_RA4

/*** Macros for UART_RX pin ***/
#define UART_RX_Get()               ((PORTA >> 9) & 0x1)
#define UART_RX_GetLatch()          ((LATA >> 9) & 0x1)
#define UART_RX_PIN                  GPIO_PIN_RA9

/*** Macros for A0_LCD pin ***/
#define A0_LCD_Set()               (LATCSET = (1<<3))
#define A0_LCD_Clear()             (LATCCLR = (1<<3))
#define A0_LCD_Toggle()            (LATCINV= (1<<3))
#define A0_LCD_OutputEnable()      (TRISCCLR = (1<<3))
#define A0_LCD_InputEnable()       (TRISCSET = (1<<3))
#define A0_LCD_Get()               ((PORTC >> 3) & 0x1)
#define A0_LCD_GetLatch()          ((LATC >> 3) & 0x1)
#define A0_LCD_PIN                  GPIO_PIN_RC3

/*** Macros for SD_CS pin ***/
#define SD_CS_Set()               (LATBSET = (1<<5))
#define SD_CS_Clear()             (LATBCLR = (1<<5))
#define SD_CS_Toggle()            (LATBINV= (1<<5))
#define SD_CS_OutputEnable()      (TRISBCLR = (1<<5))
#define SD_CS_InputEnable()       (TRISBSET = (1<<5))
#define SD_CS_Get()               ((PORTB >> 5) & 0x1)
#define SD_CS_GetLatch()          ((LATB >> 5) & 0x1)
#define SD_CS_PIN                  GPIO_PIN_RB5

/*** Macros for SD_MISO pin ***/
#define SD_MISO_Get()               ((PORTB >> 7) & 0x1)
#define SD_MISO_GetLatch()          ((LATB >> 7) & 0x1)
#define SD_MISO_PIN                  GPIO_PIN_RB7

/*** Macros for SCK_LCD pin ***/
#define SCK_LCD_Get()               ((PORTB >> 8) & 0x1)
#define SCK_LCD_GetLatch()          ((LATB >> 8) & 0x1)
#define SCK_LCD_PIN                  GPIO_PIN_RB8

/*** Macros for SDA_LCD pin ***/
#define SDA_LCD_Get()               ((PORTB >> 9) & 0x1)
#define SDA_LCD_GetLatch()          ((LATB >> 9) & 0x1)
#define SDA_LCD_PIN                  GPIO_PIN_RB9

/*** Macros for SD_MOSI pin ***/
#define SD_MOSI_Get()               ((PORTC >> 9) & 0x1)
#define SD_MOSI_GetLatch()          ((LATC >> 9) & 0x1)
#define SD_MOSI_PIN                  GPIO_PIN_RC9

/*** Macros for LED_LCD pin ***/
#define LED_LCD_Set()               (LATBSET = (1<<10))
#define LED_LCD_Clear()             (LATBCLR = (1<<10))
#define LED_LCD_Toggle()            (LATBINV= (1<<10))
#define LED_LCD_OutputEnable()      (TRISBCLR = (1<<10))
#define LED_LCD_InputEnable()       (TRISBSET = (1<<10))
#define LED_LCD_Get()               ((PORTB >> 10) & 0x1)
#define LED_LCD_GetLatch()          ((LATB >> 10) & 0x1)
#define LED_LCD_PIN                  GPIO_PIN_RB10

/*** Macros for SD_SCK pin ***/
#define SD_SCK_Get()               ((PORTB >> 13) & 0x1)
#define SD_SCK_GetLatch()          ((LATB >> 13) & 0x1)
#define SD_SCK_PIN                  GPIO_PIN_RB13

/*** Macros for CS_LCD pin ***/
#define CS_LCD_Get()               ((PORTB >> 15) & 0x1)
#define CS_LCD_GetLatch()          ((LATB >> 15) & 0x1)
#define CS_LCD_PIN                  GPIO_PIN_RB15

/*** Macros for UART_TX pin ***/
#define UART_TX_Get()               ((PORTA >> 1) & 0x1)
#define UART_TX_GetLatch()          ((LATA >> 1) & 0x1)
#define UART_TX_PIN                  GPIO_PIN_RA1


// *****************************************************************************
/* GPIO Port

  Summary:
    Identifies the available GPIO Ports.

  Description:
    This enumeration identifies the available GPIO Ports.

  Remarks:
    The caller should not rely on the specific numbers assigned to any of
    these values as they may change from one processor to the next.

    Not all ports are available on all devices.  Refer to the specific
    device data sheet to determine which ports are supported.
*/
#define    GPIO_PORT_A   (0U)
#define    GPIO_PORT_B   (1U)
#define    GPIO_PORT_C   (2U)
typedef uint32_t GPIO_PORT;

typedef enum
{
    GPIO_INTERRUPT_ON_MISMATCH,
    GPIO_INTERRUPT_ON_RISING_EDGE,
    GPIO_INTERRUPT_ON_FALLING_EDGE,
    GPIO_INTERRUPT_ON_BOTH_EDGES,
}GPIO_INTERRUPT_STYLE;

// *****************************************************************************
/* GPIO Port Pins

  Summary:
    Identifies the available GPIO port pins.

  Description:
    This enumeration identifies the available GPIO port pins.

  Remarks:
    The caller should not rely on the specific numbers assigned to any of
    these values as they may change from one processor to the next.

    Not all pins are available on all devices.  Refer to the specific
    device data sheet to determine which pins are supported.
*/
#define    GPIO_PIN_RA0   (0U)
#define    GPIO_PIN_RA1   (1U)
#define    GPIO_PIN_RA1   (1U)
#define    GPIO_PIN_RA2   (2U)
#define    GPIO_PIN_RA3   (3U)
#define    GPIO_PIN_RA4   (4U)
#define    GPIO_PIN_RA9   (9U)
#define    GPIO_PIN_RB0   (16U)
#define    GPIO_PIN_RB0   (16U)
#define    GPIO_PIN_RB1   (17U)
#define    GPIO_PIN_RB1   (17U)
#define    GPIO_PIN_RB2   (18U)
#define    GPIO_PIN_RB3   (19U)
#define    GPIO_PIN_RB4   (20U)
#define    GPIO_PIN_RB5   (21U)
#define    GPIO_PIN_RB6   (22U)
#define    GPIO_PIN_RB7   (23U)
#define    GPIO_PIN_RB8   (24U)
#define    GPIO_PIN_RB9   (25U)
#define    GPIO_PIN_RB10   (26U)
#define    GPIO_PIN_RB11   (27U)
#define    GPIO_PIN_RB13   (29U)
#define    GPIO_PIN_RB14   (30U)
#define    GPIO_PIN_RB15   (31U)
#define    GPIO_PIN_RC0   (32U)
#define    GPIO_PIN_RC1   (33U)
#define    GPIO_PIN_RC2   (34U)
#define    GPIO_PIN_RC3   (35U)
#define    GPIO_PIN_RC8   (40U)
#define    GPIO_PIN_RC9   (41U)

    /* This element should not be used in any of the GPIO APIs.
       It will be used by other modules or application to denote that none of the GPIO Pin is used */
#define    GPIO_PIN_NONE   (-1)

typedef uint32_t GPIO_PIN;


void GPIO_Initialize(void);

// *****************************************************************************
// *****************************************************************************
// Section: GPIO Functions which operates on multiple pins of a port
// *****************************************************************************
// *****************************************************************************

uint32_t GPIO_PortRead(GPIO_PORT port);

void GPIO_PortWrite(GPIO_PORT port, uint32_t mask, uint32_t value);

uint32_t GPIO_PortLatchRead ( GPIO_PORT port );

void GPIO_PortSet(GPIO_PORT port, uint32_t mask);

void GPIO_PortClear(GPIO_PORT port, uint32_t mask);

void GPIO_PortToggle(GPIO_PORT port, uint32_t mask);

void GPIO_PortInputEnable(GPIO_PORT port, uint32_t mask);

void GPIO_PortOutputEnable(GPIO_PORT port, uint32_t mask);

// *****************************************************************************
// *****************************************************************************
// Section: GPIO Functions which operates on one pin at a time
// *****************************************************************************
// *****************************************************************************

static inline void GPIO_PinWrite(GPIO_PIN pin, bool value)
{
    GPIO_PortWrite((GPIO_PORT)(pin>>4), (uint32_t)(0x1) << (pin & 0xFU), (uint32_t)(value) << (pin & 0xFU));
}

static inline bool GPIO_PinRead(GPIO_PIN pin)
{
    return (bool)(((GPIO_PortRead((GPIO_PORT)(pin>>4))) >> (pin & 0xFU)) & 0x1U);
}

static inline bool GPIO_PinLatchRead(GPIO_PIN pin)
{
    return (bool)((GPIO_PortLatchRead((GPIO_PORT)(pin>>4)) >> (pin & 0xFU)) & 0x1U);
}

static inline void GPIO_PinToggle(GPIO_PIN pin)
{
    GPIO_PortToggle((GPIO_PORT)(pin>>4), 0x1UL << (pin & 0xFU));
}

static inline void GPIO_PinSet(GPIO_PIN pin)
{
    GPIO_PortSet((GPIO_PORT)(pin>>4), 0x1UL << (pin & 0xFU));
}

static inline void GPIO_PinClear(GPIO_PIN pin)
{
    GPIO_PortClear((GPIO_PORT)(pin>>4), 0x1UL << (pin & 0xFU));
}

static inline void GPIO_PinInputEnable(GPIO_PIN pin)
{
    GPIO_PortInputEnable((GPIO_PORT)(pin>>4), 0x1UL << (pin & 0xFU));
}

static inline void GPIO_PinOutputEnable(GPIO_PIN pin)
{
    GPIO_PortOutputEnable((GPIO_PORT)(pin>>4), 0x1UL << (pin & 0xFU));
}


// DOM-IGNORE-BEGIN
#ifdef __cplusplus  // Provide C++ Compatibility

    }

#endif
// DOM-IGNORE-END
#endif // PLIB_GPIO_H
