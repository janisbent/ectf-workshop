/**
 * @file host_uart.h
 * @brief Functions to read/write to UART, raw
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#pragma once

#include <stdint.h>

/**
 * @brief UART instance to use for console
 */
#define CONSOLE_UART (0)

/**
 * @brief Console baud rate
 */
#define CONSOLE_BAUD ((uint32_t)115200)

void uart_writebyte(uint8_t data);

uint8_t uart_readbyte(void);
