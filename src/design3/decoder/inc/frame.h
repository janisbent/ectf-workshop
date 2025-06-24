/**
 * @file frame.h
 * @brief Frame decoding and key tree navigation
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#pragma once

#include "common.h"
#include "crypto_wrappers.h"

#include <stdint.h>

typedef struct {
    uint64_t prefix;
    uint8_t bits;
} vertex_t;

#define MAX_FRAME_SIZE 64

// match: encoder.py -> FrameData
typedef struct {
    uint32_t length;
    uint8_t frame[MAX_FRAME_SIZE];
} frame_data_t;

// length(4 bytes) + frame(up to 64 bytes)
static_assert(sizeof(frame_data_t) == 68);

// match: encoder.py -> FrameCh
typedef struct {
    timestamp_t timestamp;
    uint8_t ciphertext[SYMMETRIC_METADATA_LEN + sizeof(frame_data_t)];
    uint8_t _padding[4];
} frame_ch_t;

static_assert(sizeof(frame_ch_t) == 120);

// match: encoder.py -> FramePacket
typedef struct frame_packet {
    // match: encoder.py -> FramePacketPayload
    struct {
        channel_t channel_id;
        uint8_t enc_frame[SYMMETRIC_METADATA_LEN + sizeof(frame_ch_t)];
    } payload;
    uint8_t signature[SIGNATURE_LEN];
} frame_packet_t;

static_assert(sizeof(frame_packet_t) == 228);

#define MAX_TREE_HEIGHT 64

error_t decode(const frame_packet_t* packet);
