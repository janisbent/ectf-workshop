/**
 * @file fiproc.h
 * @brief Fault injection protection
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#pragma once

// Macros for redundant checks
// https://www.nccgroup.com/us/research-blog/software-based-fault-injection-countermeasures-part-23/

// passing any one of the conditionals would force entrance into the conditional block
#define MULTI_IF_FAILIN(condition) if (condition || condition || condition)

// failing any one of the conditionals would disallow entrance to conditional block
#define MULTI_IF_FAILOUT(condition) if (condition && condition && condition)

void fiproc_update_pool();

void fiproc_delay();

void fiproc_small_ranged_delay();
