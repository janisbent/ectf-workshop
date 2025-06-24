/**
 * @file lockout.c
 * @brief Lockout delay in response to attack, and persist the delay when powered off/reset
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#include "lockout.h"

#include "util.h"

#include <flc.h>
#include <mxc_delay.h>
#include <stdint.h>

// Lockout state stored in flash (0-initialized by linker)
extern uint32_t lockout_state;
#define LOCKOUT_STATE_ADDR ((uint32_t)&lockout_state)

// Period length (store to flash after each period)
#define LOCKOUT_TIME_PD 60

// Time to delay in microseconds for each period
#define LOCKOUT_PD_US 100000

/**
 * @brief Helper function to perform update on the attack lockout state.
 *
 * @param lockout_time_period lockout time period value to be updated in the flash.
 */
static void flash_helper(uint32_t lockout_time_period) {
    UTIL_ASSERT(MXC_FLC_PageErase(LOCKOUT_STATE_ADDR) == E_NO_ERROR);
    UTIL_ASSERT(MXC_FLC_Write(LOCKOUT_STATE_ADDR, sizeof(lockout_time_period),
                              &lockout_time_period) == E_NO_ERROR);
}

/**
 * @brief Continue sleeping if there is remaining time on the persisted sleep timer
 */
void lockout_process(void) {
    // check the flash value with LOCKOUT_TIME_PD
    uint32_t lockout_time_period = lockout_state;

    // if flash value greater than LOCKOUT_TIME_PD , write to flash LOCKOUT_TIME_PD , as there was a
    // HW attack.
    if (lockout_time_period > LOCKOUT_TIME_PD) {
        lockout_time_period = LOCKOUT_TIME_PD;
        flash_helper(lockout_time_period);
    }

    // read again from flash to check if no hardware attack caused again
    UTIL_ASSERT(lockout_time_period == lockout_state);

    // process the delay and keep looping and updating the flash
    while (lockout_time_period > 0) {
        MXC_Delay(LOCKOUT_PD_US); // delay for time in microseconds
        lockout_time_period--;    // decrement the lockout period variable

        // update the flash with the new lockout value
        flash_helper(lockout_time_period);
    }

    // just making sure that lockout time is written as 0
    UTIL_ASSERT(lockout_time_period == 0);
    flash_helper(lockout_time_period);
}

/**
 * @brief Force a 5 second delay that cannot be skipped by resetting.
 */
void attack_detected() {
    // check the value of attack and either set state to LOCKOUT_TIME_PD and call process
    uint32_t lockout_time_period = LOCKOUT_TIME_PD;
    flash_helper(lockout_time_period);
    lockout_process();
}
