/**
 * @file lockout.h
 * @brief Lockout delay in response to attack, and persist the delay when powered off/reset
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#pragma once

void attack_detected(void);

void lockout_process(void);
