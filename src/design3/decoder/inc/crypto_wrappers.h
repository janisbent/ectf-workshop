/**
 * @file crypto_wrappers.h
 * @brief Crypto wrappers over Monocypher
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#pragma once

#include "common.h"

#include <stddef.h>
#include <stdint.h>

// Symmetric encryption

#define SYMMETRIC_KEY_LEN 32
#define SYMMETRIC_METADATA_LEN 40 // Length of non-secret metadata added to ciphertext

error_t decrypt_symmetric(uint8_t* plaintext, const uint8_t* ciphertext, size_t length,
                          const uint8_t* sym_key);

// Asymmetric signing

#define PUBLIC_KEY_LEN 32
#define SIGNATURE_LEN 64

error_t verify_asymmetric(const uint8_t* signature, const uint8_t* message, size_t length,
                          const uint8_t* pubkey);

// Hashing and key derivation

#define TREE_KEY_LEN 16
#define TREE_LEFT_RIGHT_LEN 32

void kdf_tree_child(uint8_t* key_out, const uint8_t* parent, const uint8_t* left_right);
void kdf_tree_leaf(uint8_t* key_out, const uint8_t* tree_key);
