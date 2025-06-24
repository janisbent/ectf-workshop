/**
 * @file util.h
 * @author Plaid Parliament of Pwning
 * @brief Prototypes for common utility functions
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#pragma once

/**
 * @brief Called when hardware tampering is detected
 *
 * Macro used when the system is detected to be in an unstable state
 * and cannot be recovered. This is only called when a hardware issue
 * or unreachable system state is detected, and should never be
 * possible to reach during normal operation.
 */
#define HALT_AND_CATCH_FIRE()                                                                      \
    FI_PROTECT_0;                                                                                  \
    do_spin_forever();                                                                             \
    FI_PROTECT_2;

/**
 * @brief Assert and HCF if failed
 */
#define UTIL_ASSERT(x)                                                                             \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            HALT_AND_CATCH_FIRE();                                                                 \
        }                                                                                          \
    } while (0)

/**
 * @brief Macros for fault injection prevention
 *
 * Equivalent to a bunch of while(1);
 */
#define FI_PROTECT_0                                                                               \
    __asm volatile("1: ");                                                                         \
    FI_PROTECT_1 FI_PROTECT_1
#define FI_PROTECT_1 FI_PROTECT_2 FI_PROTECT_2
#define FI_PROTECT_2 FI_PROTECT_3 FI_PROTECT_3
#define FI_PROTECT_3 FI_PROTECT_4 FI_PROTECT_4
#define FI_PROTECT_4 FI_PROTECT_5 FI_PROTECT_5
#define FI_PROTECT_5 __asm volatile("b 1b; b 1b;");

void do_spin_forever();
