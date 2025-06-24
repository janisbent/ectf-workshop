/**
 * @file fiproc.c
 * @brief Fault injection protection
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#include "fiproc.h"

#include "rng.h"
#include "util.h"

#include <monocypher.h>
#include <mxc_delay.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define FIPROC_POOL_SIZE 128

// Num bits required to get max range of 30ms
// log2(30 * 10**6 / 30) >= 20
#define LARGE_RANGE_MASK 0x000FFFFF

/**
 * @brief Spins in a busy loop for a specified number of ticks
 *
 * @param ticks number of ticks to delay for
 */
inline static void delay_ticks(int32_t ticks) {
    __asm__ inline volatile("0:\n\t"
                            "subs %0, #1\n\t"
                            "bpl 0b\n\t"
                            : "+r"(ticks)
                            : // marking ticks as in-out already covers this
                            : "cc");
}

// Entropy pool to store pregenerated entropy for time critical usages
static uint8_t entropy_pool[FIPROC_POOL_SIZE];
static uint8_t* next = NULL;

/**
 * @brief check if fiproc pool is empty
 */
bool fiproc_pool_empty() {
    if (next == NULL) {
        return true;
    }

    if ((unsigned long)next - (unsigned long)entropy_pool >= (FIPROC_POOL_SIZE - 1)) {
        return true;
    }

    return false;
}

/**
 * @brief xor output buffer with input buffer
 */
static void xor_bytes(uint8_t* output, const uint8_t* input, size_t length) {
    for (size_t i = 0; i < length; i++) {
        output[i] ^= input[i];
    }
}

/**
 * @brief updates the fiproc pool if necessary
 *
 * Fills pool with FIPROC_POOL_SIZE bytes of random data
 */
void fiproc_update_pool() {
    uint8_t rng_buf[8];
    // get new entropy
    rng_get_unbiased_trng(rng_buf, 8);

    // expand 8 bytes of RNG into 128 bytes
    uint8_t entropy_pool_tmp[FIPROC_POOL_SIZE];
    for (uint32_t i = 0; i < 2; i++) {
        // Expand by using entropy as key and index as message, per HKDF-Expand
        crypto_blake2b_keyed(entropy_pool_tmp + (i * 64), 64, // output
                             rng_buf, sizeof(rng_buf),        // key
                             (uint8_t*)&i, sizeof(i));        // message
    }

    // xor new entropy with any leftover entropy to update pool
    xor_bytes(entropy_pool, entropy_pool_tmp, FIPROC_POOL_SIZE);

    next = &entropy_pool[0];
}

/**
 * @brief max delay of 7us
 */
void fiproc_delay() {
    UTIL_ASSERT(fiproc_pool_empty() == false);
    uint32_t delay = *next;
    next++;
    delay_ticks(delay);
}

/**
 * @brief ranged delay between 2ms ~ 4ms
 */
void fiproc_small_ranged_delay() {
    uint32_t range = rng_get_u16(); // takes approx 2ms
    delay_ticks(range);
}
