/**
 * @file string.h
 * @brief Implementations for libc functions which the compiler expects to be present
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#pragma once

#include <stddef.h>

void* memset(void* b, int c, size_t len);

void* memcpy(void* restrict dst, const void* restrict src, size_t n);

int memcmp(const void* vl, const void* vr, size_t n);
