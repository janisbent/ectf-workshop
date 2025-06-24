/**
 * @file frame.c
 * @brief Frame decoding and key tree navigation
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#include "frame.h"

#include "common.h"
#include "fiproc.h"
#include "host_messaging.h"
#include "lockout.h"
#include "secrets.h"
#include "subscription.h"
#include "util.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Determines the tree vertex and key for a timestamp within a subscription.
 *
 * @param sub The subscription that the timestamp is for
 * @param t The timestamp to find a parent key for
 * @param position Position of parent key is written on success
 * @return SIZE_MAX if t is outside [start, end], index into in sub->tree_keys otherwise
 */
static size_t key_index_for_time(const valid_subscription_t* sub, timestamp_t t,
                                 vertex_t* position) {
    UTIL_ASSERT(sub != NULL);
    UTIL_ASSERT(position != NULL);

    size_t start_idx = 0;
    size_t end_idx = sub->key_count - 1;

    timestamp_t start_prefix = sub->start;
    timestamp_t end_prefix = sub->end;
    int bits = MAX_TREE_HEIGHT;

    volatile bool is_out_of_range = true;
    is_out_of_range = (t < start_prefix) || (end_prefix < t);
    MULTI_IF_FAILIN(is_out_of_range) { return SIZE_MAX; }

    while (true) {
        UTIL_ASSERT(start_prefix <= t);
        UTIL_ASSERT(t <= end_prefix);
        UTIL_ASSERT(start_idx <= end_idx);

        if ((start_prefix & 1) == 0 && (end_prefix & 1) == 1) {
            // move up a level
            start_prefix >>= 1;
            end_prefix >>= 1;
            t >>= 1;
            bits -= 1;
        } else if ((start_prefix & 1) == 1) {
            // start is a packaged key
            if (start_prefix == t) {
                position->prefix = start_prefix;
                position->bits = bits;
                return start_idx;
            } else {
                // start is packaged but we don't need it, discard
                start_prefix += 1;
                start_idx += 1;
            }
        } else { // end & 1 == 0
            // end is a packaged key
            if (end_prefix == t) {
                position->prefix = end_prefix;
                position->bits = bits;
                return end_idx;
            } else {
                // end is packaged but we don't need it, discard
                end_prefix -= 1;
                end_idx -= 1;
            }
        }
    }
}

static void derive_tree_key_helper(const vertex_t* path, const uint8_t* parent_key, uint8_t* key) {
    UTIL_ASSERT(path != NULL);
    UTIL_ASSERT(parent_key != NULL);
    UTIL_ASSERT(key != NULL);
    memcpy(key, parent_key, TREE_KEY_LEN);

    // get the msb of path
    // path    = 0b abcd_...._wxyz
    // bitmask = 0b 1000_...._0000
    for (uint8_t level = 0; level < path->bits; level++) {
        uint8_t bit = path->bits - level - 1;
        uint64_t curr_direction = path->prefix & (1LL << bit);
        if (curr_direction == 0) {
            // key = KDF(key || left)
            kdf_tree_child(key, key, LEFT_TREE_KEY);
        } else {
            // key = KDF(key || right)
            kdf_tree_child(key, key, RIGHT_TREE_KEY);
        }
    }
}

/**
 * @brief derive frame key by timestamp and key tree
 *
 * @param t timestamp
 * @param parent_key parent key (32 bytes)
 * @param parent_position parent position (prefix, bits(tree level))
 * @param key (out) frame key (32 bytes)
 */
static void derive_tree_key(const timestamp_t t, const uint8_t* parent_key,
                            const vertex_t* parent_position, uint8_t* key) {
    UTIL_ASSERT(parent_key != NULL);
    UTIL_ASSERT(parent_position != NULL);
    UTIL_ASSERT(key != NULL);

    if (parent_position->bits == MAX_TREE_HEIGHT) {
        UTIL_ASSERT(parent_position->prefix == t);
        memcpy(key, parent_key, SYMMETRIC_KEY_LEN);
    } else if (parent_position->bits == 0) {
        UTIL_ASSERT(parent_position->prefix == 0);
        const vertex_t path = {.prefix = t, .bits = MAX_TREE_HEIGHT};
        derive_tree_key_helper(&path, parent_key, key);
    } else {
        UTIL_ASSERT((t >> (MAX_TREE_HEIGHT - parent_position->bits)) == parent_position->prefix);

        // e.g. t = 0b1001_abcd_...._wxyz (bits = 64)
        // parent = 0b1001                (bits = 4)
        // path   = 0b0000_abcd_...._wxyz, (60 bits)
        // abcd_...._xwyz is the path we want to follow along with from the parent node down to
        // the leaf
        const vertex_t path = {
            .prefix = t ^ (parent_position->prefix << (MAX_TREE_HEIGHT - parent_position->bits)),
            .bits = MAX_TREE_HEIGHT - parent_position->bits};
        derive_tree_key_helper(&path, parent_key, key);
    }

    kdf_tree_leaf(key, key);
}

static bool received_first_frame = false;
static timestamp_t current_timestamp = 0;

/**
 * @brief Decode a frame packet and send the decoded frame to the host.
 *
 * @param packet Frame packet to decode
 * @return OK if frame was able to be decoded, ERROR if it was not.
 */
error_t decode(const frame_packet_t* packet) {

    // Decoder will only enter the lockout state once it detects an attack.

    const valid_subscription_t* sub = get_subscription_by_channel(packet->payload.channel_id);

    fiproc_delay();
    if (sub == NULL) {
        return ERROR;
    }

    volatile error_t result = ERROR;
    result = verify_asymmetric(packet->signature, (const uint8_t*)&packet->payload,
                               sizeof(packet->payload), ENCODER_PUBLIC_KEY);
    fiproc_delay();
    MULTI_IF_FAILIN(result != OK) { return ERROR; }

    fiproc_delay();
    frame_ch_t timestamped_frame = {};
    if (decrypt_symmetric((uint8_t*)&timestamped_frame, packet->payload.enc_frame,
                          sizeof(timestamped_frame), sub->kch) != OK) {
        // inner decryption is corrupted but signature passes means attack
        attack_detected();
        return ERROR;
    }

    // Check for monotonicity
    fiproc_delay();
    if (!received_first_frame || timestamped_frame.timestamp > current_timestamp) {
        received_first_frame = true;
        current_timestamp = timestamped_frame.timestamp;
    } else {
        // Not an attack just drop the packet and go to the next packet
        return ERROR;
    }

    // obtain position and index of parent key in the tree for this timestamp
    vertex_t v = {};
    size_t index = key_index_for_time(sub, timestamped_frame.timestamp, &v);
    fiproc_delay();
    if (index == SIZE_MAX) {
        // t is outside of the subscription's time range, possibly just expired/recorded (not an
        // attack)
        return ERROR;
    }

    uint8_t kt[SYMMETRIC_KEY_LEN] = {};
    fiproc_delay();
    derive_tree_key(timestamped_frame.timestamp, sub->ktree[index], &v, kt);

    // decrypt enc_frame with kt
    frame_data_t frame_data = {};
    fiproc_delay();
    if (decrypt_symmetric((uint8_t*)&frame_data, timestamped_frame.ciphertext, sizeof(frame_data),
                          kt) == ERROR) {
        // inner decryption corrupted means attack
        attack_detected();
        return ERROR;
    }

    fiproc_delay();
    if (frame_data.length > MAX_FRAME_SIZE) {
        // attacker forged a signature and got through two layers of encryption, definitely an
        // attack
        attack_detected();
        return ERROR;
    }

    // update most recent timestamp
    current_timestamp = timestamped_frame.timestamp;

    send_msg(DECODE_MSG, frame_data.frame, frame_data.length);

    return OK;
}
