/**
 * @file subscription.h
 * @brief Manages storing, retrieving, and updating subscriptions.
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#pragma once

#include "common.h"
#include "crypto_wrappers.h"

#include <stddef.h>
#include <stdint.h>

#define MAX_CHANNEL_COUNT 9

#define MAX_TREE_KEYS 126

// match: gen_subscription.py -> ValidSubscription
typedef struct {
    uint8_t ktree[MAX_TREE_KEYS][TREE_KEY_LEN];
    uint8_t kch[SYMMETRIC_KEY_LEN];
    timestamp_t start;
    timestamp_t end;
    channel_t channel;
    uint32_t key_count;
    uint32_t magic;  // ensures that flash write completed successfully
    uint8_t _pad[4]; // to ensure struct is a multiple of 16 bytes (flash write size)
} valid_subscription_t;

static_assert(sizeof(valid_subscription_t) == 2080);

// match: gen_subscription.py -> SubscriptionUpdate
typedef struct subscription_update {
    // match: gen_subscription.py -> SubscriptionUpdatePayload
    struct {
        decoder_id_t id;
        uint8_t ciphertext[SYMMETRIC_METADATA_LEN + sizeof(valid_subscription_t)];
    } payload;
    uint8_t sig[SIGNATURE_LEN];
} subscription_update_t;

static_assert(sizeof(subscription_update_t) == 2188);

const valid_subscription_t* get_subscription(size_t i);
const valid_subscription_t* get_subscription_by_channel(channel_t ch);

error_t update_subscription(const subscription_update_t* update_package);
