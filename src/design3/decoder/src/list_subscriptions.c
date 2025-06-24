/**
 * @file list_subscriptions.c
 * @brief Functions to list subscribed channels
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#include "list_subscriptions.h"

#include "host_messaging.h"
#include "subscription.h"

#include <stddef.h>
#include <stdint.h>

// start and end are split due to alignment
typedef struct {
    channel_t channel; // 4 bytes
    uint32_t start[2]; // 8 bytes
    uint32_t end[2];   // 8 bytes
} channel_info_t;

static_assert(sizeof(channel_info_t) == 20);

/**
 * @brief "List" command response structure, defined in specification
 */
typedef struct {
    uint32_t n_channels;                                // number of channels 4 bytes
    channel_info_t channel_info[MAX_CHANNEL_COUNT - 1]; // 20 * 8 = 160 bytes
} list_response_t;

/**
 * @brief Reads channel info into a list_response_t.
 *
 * @param msg_buf Response structure to store in
 * @return response length
 */
static size_t get_channel_info(list_response_t* msg_buf) {
    msg_buf->n_channels = 0;

    for (size_t i = 1; i < MAX_CHANNEL_COUNT; i++) { // skip channel 0
        const valid_subscription_t* valid_sub = get_subscription(i);
        if (valid_sub) {
            channel_info_t* next_info = &msg_buf->channel_info[msg_buf->n_channels];
            next_info->channel = valid_sub->channel;
            // Masking and shifting for converting 64 bits to a 32 bit integer
            next_info->start[0] = (uint32_t)(valid_sub->start & 0xFFFFFFFF);
            next_info->start[1] = (uint32_t)((valid_sub->start >> 32));
            next_info->end[0] = (uint32_t)(valid_sub->end & 0xFFFFFFFF);
            next_info->end[1] = (uint32_t)((valid_sub->end >> 32));
            msg_buf->n_channels++;
        }
    }

    // 4 bytes for number of channels + each channel info length * number of channels
    // Also handles the no subscription with length of 4.
    return sizeof(uint32_t) + sizeof(channel_info_t) * msg_buf->n_channels;
}

/**
 * @brief Create a list response packet with the current subscriptions and send it to the host.
 */
void list_subscriptions(void) {
    list_response_t response = {0};

    size_t message_len = get_channel_info(&response);

    send_msg(LIST_MSG, &response, message_len);
}
