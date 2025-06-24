/**
 * @file rng.h
 * @brief True random number generation with Von Neumann whitening
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

void rng_init();

void rng_get_unbiased_trng(uint8_t* output, size_t length);

uint16_t rng_get_u16();
