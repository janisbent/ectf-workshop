/**
 * @file host_uart.c
 * @brief Functions to read/write to UART, raw
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#include "host_uart.h"

#include <uart.h>

#define MXC_UARTn MXC_UART_GET_UART(CONSOLE_UART)
#define UART_FIFO MXC_UART_GET_FIFO(CONSOLE_UART)

/**
 * @brief Write a byte to UART, blocking.
 *
 * @param data byte to write
 */
void uart_writebyte(uint8_t data) {
    // Wait until there's room in the FIFO
    while (MXC_UART_GetTXFIFOAvailable(MXC_UARTn) == 0) {}

    MXC_UART_WriteCharacter(MXC_UARTn, data);
}

/**
 * @brief Read a byte from UART, blocking.
 *
 * @return byte read
 */
uint8_t uart_readbyte(void) {
    uint8_t data = MXC_UART_ReadCharacter(MXC_UARTn);
    return data;
}
