/**
 * @file host_messaging.c
 * @brief Functions to read/write to UART using the eCTF-specified protocol
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#include "host_messaging.h"

#include "common.h"
#include "host_uart.h"
#include "util.h"

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Send message body
 *
 * @param buf payload
 * @param len payload length in byte
 */
static void send_body(const void* buf, const size_t len) {
    for (size_t i = 0; i < len; i++) {
        uart_writebyte(((uint8_t*)buf)[i]);
    }
}

/**
 * @brief Receive message body
 *
 * @param buf (out) payload
 * @param len payload length in byte
 * @param buf_remaining remaining buffer length in byte
 */
static void get_body(void* buf, const uint16_t len, const size_t buf_remaining) {
    for (size_t i = 0; i < len; i++) {
        if (i < buf_remaining) {
            ((uint8_t*)buf)[i] = uart_readbyte();
        } else {
            uart_readbyte(); // exceeds buffer size, discard
        }
    }
}

/**
 * @brief Send response header
 *
 * @param type message type
 * @param len payload length in byte
 */
static void send_header(const msg_type_t type, const uint16_t len) {
    uart_writebyte(MAGIC_MSG);
    uart_writebyte(type);
    uart_writebyte(len & 0xFF);
    uart_writebyte((len >> 8) & 0xFF);
}

/**
 * @brief Receive command header
 *
 * @param type (out) message type
 * @param len (out) payload length in byte
 */
static void get_header(msg_type_t* type, uint16_t* len) {
    uint8_t magic = 0;
    while (magic != MAGIC_MSG) {
        magic = uart_readbyte();
    }

    *type = uart_readbyte();

    uint16_t len_lo = (uint16_t)uart_readbyte();
    uint16_t len_hi = (uint16_t)uart_readbyte();
    *len = (len_hi << 8) | len_lo;
}

/**
 * @brief Send Ack
 */
static void send_ack() { send_header(ACK_MSG, 0); }

/**
 * @brief Receive Ack
 *
 * @return OK if ack is received correctly, ERROR otherwise
 */
static error_t get_ack() {
    uint16_t len;
    msg_type_t type;
    get_header(&type, &len);
    if (type == ACK_MSG && len == 0) {
        return OK;
    } else {
        return ERROR;
    }
}

/**
 * @brief Send uart message to host
 *
 * @param type message type
 * @param msg_buf message payload buffer
 * @param msg_len message payload length
 */
void send_msg(const msg_type_t type, const void* msg_buf, const size_t msg_len) {
    UTIL_ASSERT(msg_buf != NULL || msg_len == 0);

    send_header(type, (uint16_t)msg_len);
    if (type != DEBUG_MSG) {
        if (get_ack() != OK) {
            // Protocol violation - fail silently
            return;
        }
    }

    for (size_t offs = 0; offs < msg_len; offs += MSG_CHUNK_SIZE) {
        size_t wlen = msg_len - offs;
        if (wlen > MSG_CHUNK_SIZE) {
            wlen = MSG_CHUNK_SIZE;
        }
        send_body(msg_buf + offs, wlen);
        if (type != DEBUG_MSG) {
            if (get_ack() != OK) {
                // Protocol violation - fail silently
                return;
            }
        }
    }
}

/**
 * @brief Receive uart message from host
 *
 * @param type (out) message type
 * @param msg_buf (out) message payload buffer
 * @param msg_len (out) message payload length
 * @param buf_len length of of msg_buf
 * @return OK if successful, ERROR otherwise (null type, msg_buf, msg_len or read data that has size
 * larger than buf_len)
 */
error_t get_msg(msg_type_t* type, void* msg_buf, uint16_t* msg_len, const size_t buf_len) {
    get_header(type, msg_len);
    send_ack();

    for (size_t offs = 0; offs < *msg_len; offs += MSG_CHUNK_SIZE) {
        size_t buf_remaining = (buf_len < offs) ? 0 : buf_len - offs;
        size_t rlen = *msg_len - offs; // rlen = min(*msg_len-off, MSG_CHUNK_SIZE)
        if (rlen > MSG_CHUNK_SIZE) {
            rlen = MSG_CHUNK_SIZE;
        }

        get_body(msg_buf + offs, rlen, buf_remaining);
        send_ack();
    }

    if (*msg_len <= buf_len) {
        return OK;
    } else {
        return ERROR;
    }
}
