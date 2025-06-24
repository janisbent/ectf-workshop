/**
 * @file subscription.c
 * @brief Manages storing, retrieving, and updating subscriptions.
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#include "subscription.h"

#include "common.h"
#include "crypto_wrappers.h"
#include "fiproc.h"
#include "host_messaging.h"
#include "lockout.h"
#include "secrets.h"
#include "util.h"

#include <flc.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Allocated by linker and patched into binary during build
extern const valid_subscription_t channel0;

#define SUBSCRIPTION_FLASH_ADDR ((size_t)&channel0)
#define SUBSCRIPTION_SIZE 8192        // exactly one flash page
#define SUBSCRIPTION_MAGIC 0x41594E42 // BNYA

/**
 * @brief Calculate address for a particular subscription package
 *
 * @param i Subscription index
 * @return const valid_subscription_t*  Pointer to subscription package
 */
const valid_subscription_t* get_subscription_raw(size_t i) {
    UTIL_ASSERT(i < MAX_CHANNEL_COUNT);
    return (valid_subscription_t*)(SUBSCRIPTION_FLASH_ADDR + i * SUBSCRIPTION_SIZE);
}

/**
 * @brief Returns the subscription at the given flash index, if it exists.
 *
 * @param i index into subscription storage of desired subscription.
 * @return pointer to valid subscription in flash or NULL if none exists at that location.
 */
const valid_subscription_t* get_subscription(size_t i) {
    if (i < MAX_CHANNEL_COUNT) {
        const valid_subscription_t* sub = get_subscription_raw(i);
        if (sub->magic == SUBSCRIPTION_MAGIC) {
            return sub;
        }
    }

    return NULL;
}

/**
 * @brief Finds a valid subscription for the channel if one exists.
 *
 * @param ch channel number to find
 * @return pointer to valid subscription in flash or NULL if none exists
 */
const valid_subscription_t* get_subscription_by_channel(channel_t ch) {
    for (size_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        const valid_subscription_t* sub = get_subscription(i);
        if (sub != NULL && sub->magic == SUBSCRIPTION_MAGIC && sub->channel == ch) {
            return sub;
        }
    }

    return NULL;
}

/**
 * @brief Writes a subscription to a specific index in flash storage
 * YOU MUST HAVE CHECKED THE VALIDITY OF `sub` BEFORE WRITING IT
 *
 * @param i index of subscription
 * @param sub Subscription package
 */
static void write_subscription(size_t i, const valid_subscription_t* sub) {
    UTIL_ASSERT(MXC_FLC_PageErase((uint32_t)get_subscription_raw(i)) == E_NO_ERROR);
    UTIL_ASSERT(MXC_FLC_Write((uint32_t)get_subscription_raw(i), sizeof(*sub), (uint32_t*)sub) ==
                E_NO_ERROR);
}

/**
 * @brief decrypt a subscription packet stored in update_package using the decoder id key(Kid)
 *
 * @param update_package encrypted package
 * @param dec_package decrypted package
 * @return OK if decryption successful, ERROR otherwise
 */
static error_t decrypt_subscription(const uint8_t* update_package,
                                    valid_subscription_t* dec_package) {
    return decrypt_symmetric((uint8_t*)dec_package, update_package, sizeof(*dec_package), ID_KEY);
}

/**
 * @brief verify the signature of the decrypted data packet using encoder public key (Ke)
 *
 * @param dec_package decrypted package
 * @return OK if signature is valid, ERROR otherwise
 */
static error_t validate_signature(const subscription_update_t* signed_package) {
    return verify_asymmetric(signed_package->sig, (const uint8_t*)&signed_package->payload,
                             sizeof(signed_package->payload), ENCODER_PUBLIC_KEY);
}

/**
 * @brief Given an encrypted subscription package, verify its authenticity and validity,
 * and if valid, store it in flash memory.
 *
 * @param update_package the encrypted subscription update package
 * @return OK if subscription was valid and space was available to store it, ERROR otherwise
 */

error_t update_subscription(const subscription_update_t* update_package) {
    // validate the signature of the subscription data
    volatile error_t sig_result = ERROR;
    sig_result = validate_signature(update_package);
    fiproc_delay();
    MULTI_IF_FAILIN(sig_result != OK) {
        // invalid subscription is an attack
        attack_detected();
        return ERROR;
    }

    // decrypt the subscription
    // this inherently checks that the ID is correct - it will fail for wrong key
    valid_subscription_t dec_package = {0};
    fiproc_delay();
    if (decrypt_subscription(update_package->payload.ciphertext, &dec_package) != OK) {
        // failed to decrypt the update_package
        attack_detected();
        return ERROR;
    }

    // check channel 0
    fiproc_delay();
    if (dec_package.channel == 0) {
        // can't update subscription 0 but not an attack per organizers
        return ERROR;
    }

    // check timestamp
    fiproc_delay();
    if (dec_package.end < dec_package.start) {
        // bad subscription, lockout
        attack_detected();
        return ERROR;
    }

    fiproc_delay();
    if (dec_package.magic != SUBSCRIPTION_MAGIC) {
        // corrupted subscription after signature+encrypt, lockout
        attack_detected();
        return ERROR;
    }

    // okay, subscription is valid
    // store it in memory in "subscriptions" for frame decoding

    // skip index 0 in loops below since we never update channel 0

    // first, check to see if there is an existing subscription for this channel and replace it
    for (size_t i = 1; i < MAX_CHANNEL_COUNT; i++) {
        fiproc_delay();
        const valid_subscription_t* old_subscription = get_subscription_raw(i);
        if (old_subscription->magic == SUBSCRIPTION_MAGIC &&
            old_subscription->channel == dec_package.channel) {
            // update this entry
            write_subscription(i, &dec_package);
            send_msg(SUBSCRIBE_MSG, NULL, 0);
            return OK;
        }
    }

    // if no existing subscription, replace an empty subscription
    for (size_t i = 1; i < MAX_CHANNEL_COUNT; i++) {
        fiproc_delay();
        const valid_subscription_t* old_subscription = get_subscription_raw(i);
        if (old_subscription->magic != SUBSCRIPTION_MAGIC) {
            write_subscription(i, &dec_package);
            send_msg(SUBSCRIBE_MSG, NULL, 0);
            return OK;
        }
    }

    // just too many subscriptions, not an attack
    return ERROR;
}
