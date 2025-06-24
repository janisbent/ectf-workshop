/**
 * @file common.h
 * @brief Shared types used by decoder
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#pragma once

#include <stdint.h>

/**
 * @brief Unified error handling type
 */
typedef enum : int { OK = 0, ERROR = -1 } error_t;

// Semantic type names for protocol
typedef uint64_t timestamp_t;
typedef uint32_t channel_t;
typedef uint32_t decoder_id_t;
