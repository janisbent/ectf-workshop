/**
 * @file secrets.h
 * @brief Provides access to secrets required by the decoder which are generated at build time
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#pragma once

#include "crypto_wrappers.h"

#include <stdint.h>

extern const uint8_t ENCODER_PUBLIC_KEY[PUBLIC_KEY_LEN];

extern const uint8_t ID_KEY[SYMMETRIC_KEY_LEN];

extern const uint8_t LEFT_TREE_KEY[TREE_LEFT_RIGHT_LEN];

extern const uint8_t RIGHT_TREE_KEY[TREE_LEFT_RIGHT_LEN];
