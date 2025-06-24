/**
 * @file crypto_wrappers.c
 * @brief Crypto wrappers over Monocypher
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#include "crypto_wrappers.h"

#include "common.h"
#include "fiproc.h"
#include "util.h"

#include <monocypher.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/**
 * @brief Wrapper for symmetric decryption
 *
 * Plaintext will be length bytes long
 * Ciphertext will be length+CC_ENC_SYM_METADATA_LEN bytes long
 * Provides authenticated encryption;
 *
 * @param plaintext pointer to plaintext
 * @param ciphertext pointer to ciphertext
 * @param length length of the plaintext
 * @param sym_key symmetric key
 * @return OK if decrypt succeeds, ERROR if tampering or corruption detected
 */
error_t decrypt_symmetric(uint8_t* plaintext, const uint8_t* ciphertext, size_t length,
                          const uint8_t* sym_key) {

    volatile int res1 = crypto_aead_unlock(plaintext, ciphertext + 0, sym_key, ciphertext + 16,
                                           NULL, 0, ciphertext + 40, length);
    fiproc_delay();

    if (res1 == 0) {
        return OK;
    } else {
        return ERROR;
    }
}

/**
 * @brief Wrapper for asymmetric signature checking
 *
 * @param signature pointer to signature to verify (len 64)
 * @param message pointer to message
 * @param length length of message
 * @param pubkey pointer to public key (len 32)
 * @return OK if the signature is valid, ERROR if the signature is invalid
 */
error_t verify_asymmetric(const uint8_t* signature, const uint8_t* message, size_t length,
                          const uint8_t* pubkey) {
    volatile int res1 = crypto_eddsa_check(signature, pubkey, message, length);
    fiproc_delay();

    if (res1 == 0) {
        return OK;
    } else {
        return ERROR;
    }
}

/**
 * @brief Derives a child tree key
 *
 * @param key_out: output key (16 bytes)
 * @param parent: tree key of the parent node (16 bytes)
 * @param left_right: left or right tree key (32 bytes)
 */
void kdf_tree_child(uint8_t* key_out, const uint8_t* parent, const uint8_t* left_right) {
    UTIL_ASSERT(key_out != NULL);
    UTIL_ASSERT(parent != NULL);
    UTIL_ASSERT(left_right != NULL);

    // match: crypto_wrappers.py -> TreeChildTmp
    struct {
        uint8_t parent[TREE_KEY_LEN];
        uint8_t left_right[TREE_LEFT_RIGHT_LEN];
    } tmp;
    memcpy(tmp.parent, parent, sizeof(tmp.parent));
    memcpy(tmp.left_right, left_right, sizeof(tmp.left_right));

    // no need to do this multiple times as FI would just result in a garbage key that will fail
    // decryption
    crypto_blake2b(key_out, TREE_KEY_LEN, (uint8_t*)&tmp, sizeof(tmp));
    fiproc_delay();
}

/**
 * @brief Derives a symmetric key from a leaf tree key
 *
 * @param key_out: output key (32 bytes)
 * @param tree_key: tree key of a leaf node (16 bytes)
 */
void kdf_tree_leaf(uint8_t* key_out, const uint8_t* tree_key) {
    UTIL_ASSERT(key_out != NULL);
    UTIL_ASSERT(tree_key != NULL);

    // no need to do this multiple times as FI would just result in a garbage key that will fail
    // decryption
    crypto_blake2b(key_out, SYMMETRIC_KEY_LEN, tree_key, TREE_KEY_LEN);
    fiproc_delay();
}
