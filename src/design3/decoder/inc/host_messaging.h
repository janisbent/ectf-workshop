/**
 * @file host_messaging.h
 * @brief Functions to read/write to UART using the eCTF-specified protocol
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#pragma once

#include "common.h"

#include <stddef.h>
#include <stdint.h>

#define HEADER_SIZE 4      // bytes
#define MSG_CHUNK_SIZE 256 // bytes

typedef enum : char {
    DECODE_MSG = 'D',    // 0x44
    SUBSCRIBE_MSG = 'S', // 0x53
    LIST_MSG = 'L',      // 0x4C
    ACK_MSG = 'A',       // 0x41
    ERROR_MSG = 'E',     // 0x45
    DEBUG_MSG = 'G',     // 0x47
    MAGIC_MSG = '%'      // 0x25
} msg_type_t;

void send_msg(const msg_type_t type, const void* msg_buf, const size_t msg_len);

error_t get_msg(msg_type_t* type, void* msg_buf, uint16_t* msg_len, const size_t buf_len);

#define PRINT_ERROR(msg) send_msg(ERROR_MSG, "" msg "", sizeof(msg) - 1)

#define PRINT_DEBUG(msg) send_msg(DEBUG_MSG, "" msg "", sizeof(msg) - 1)
