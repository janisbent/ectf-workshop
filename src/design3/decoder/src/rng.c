/**
 * @file rng.c
 * @brief True random number generation with Von Neumann whitening
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#include "rng.h"

#include "stdint.h"
#include "string.h"
#include "util.h"

#include <trng.h>

void rng_init() { MXC_TRNG_Init(); }

/**
 * @brief Fill a buffer with Von-Neumann-whitened random data
 *
 * @param output buffer pointer
 * @param length length of the output buffer in bytes
 */
void rng_get_unbiased_trng(uint8_t* output, size_t length) {
    UTIL_ASSERT(output != NULL);

    uint8_t current_byte = 0;
    uint8_t bits_generated = 0;
    size_t buffer_idx = 0;

    while (true) {
        uint32_t stream = MXC_TRNG_RandomInt();

        for (uint32_t bit = 0; bit < 8; bit += 2, stream >>= 2) {
            uint8_t bit1 = (stream >> 1);
            uint8_t bit2 = stream;

            uint8_t diff = (bit1 ^ bit2) & 1;

            if (diff) {
                current_byte <<= 1;
                current_byte |= (bit1 & 1);

                if (++bits_generated == 8) {
                    output[buffer_idx++] = current_byte;
                    current_byte = 0;

                    bits_generated = 0;

                    if (buffer_idx >= length) {
                        return;
                    }
                }
            }
        }
    }
}

uint16_t rng_get_u16() {
    uint16_t result;
    rng_get_unbiased_trng((uint8_t*)&result, sizeof(result));
    return result;
}
