/**
 * @file util.c
 * @brief Miscellaneous utilities
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#include "util.h"

void do_spin_forever() {
    volatile int tmp = 1;
    while (tmp)
        ;
    __builtin_unreachable();
}
