/**
 * @file main.c
 * @brief Main entry point for the Decoder application
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

#include "common.h"
#include "fiproc.h"
#include "frame.h"
#include "hardware_init.h"
#include "host_messaging.h"
#include "list_subscriptions.h"
#include "lockout.h"
#include "subscription.h"

#include <mpu_armv7.h>
#include <string.h>

// Subscription update is the largest valid packet we'll ever receive
#define MAX_BUF_LEN (sizeof(subscription_update_t))

void handle_list_msg(uint16_t msg_len) {
    if (msg_len != 0) {
        PRINT_ERROR("Invalid list msg length.\n");
        return;
    }

    list_subscriptions(); // infallible

    return;
}

void handle_decode_msg(const uint8_t* msg_buf, uint16_t msg_len) {
    if (msg_len != sizeof(frame_packet_t)) {
        PRINT_ERROR("Invalid decode msg length.\n");
        return;
    }

    if (decode((const frame_packet_t*)msg_buf) != OK) {
        PRINT_ERROR("Failed to decode frame.\n");
    }
    return;
}

void handle_subscribe_msg(const uint8_t* msg_buf, uint16_t msg_len) {
    if (msg_len != sizeof(subscription_update_t)) {
        PRINT_ERROR("Invalid subscribe msg length.\n");
        return;
    }

    if (update_subscription((const subscription_update_t*)msg_buf) != OK) {
        PRINT_ERROR("Failed to update subscription.\n");
    }
    return;
}
static void enable_mpu(void) {

    // Whole flash region
    ARM_MPU_SetRegion(
        // 0x1000_0000 to 0x1008_0000 (512KiB)
        ARM_MPU_RBAR(0, 0x10000000),
        // Allow execution, read-only
        ARM_MPU_RASR(0, ARM_MPU_AP_PRO, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000,
                     ARM_MPU_REGION_SIZE_512KB));

    // Whole SRAM space
    ARM_MPU_SetRegion(
        // 0x2000_0000 to 0x2002_0000 (128KB)
        ARM_MPU_RBAR(1, 0x20000000),
        // No-execute, read-write
        ARM_MPU_RASR(1, ARM_MPU_AP_PRIV, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000,
                     ARM_MPU_REGION_SIZE_128KB));

    // Executable SRAM for flashprog: higher region number takes priority
    ARM_MPU_SetRegion(
        // 0x2000_0000 to 0x2000_2000 (8KiB)
        ARM_MPU_RBAR(2, 0x20000000),
        // Execute, read-only
        ARM_MPU_RASR(0, ARM_MPU_AP_PRO, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000,
                     ARM_MPU_REGION_SIZE_8KB));

    // Peripheral space - full read and write
    ARM_MPU_SetRegion(
        // 0x4000_0000 to 0x6000_0000 (512MB)
        ARM_MPU_RBAR(3, 0x40000000),
        // No-execute, read-write
        ARM_MPU_RASR(1, ARM_MPU_AP_PRIV, ARM_MPU_ACCESS_ORDERED, 1, 0, 0, 0b00000000,
                     ARM_MPU_REGION_SIZE_512MB));

    // Clear rest of memory regions
    ARM_MPU_ClrRegion(4);
    ARM_MPU_ClrRegion(5);
    ARM_MPU_ClrRegion(6);
    ARM_MPU_ClrRegion(7);

    ARM_MPU_Enable(MPU_BASE);
}

int main() {
    enable_mpu();
    hardware_init();

    lockout_process();

    msg_type_t msg_type;
    uint8_t msg_buf[MAX_BUF_LEN];
    uint16_t msg_len;

    while (true) {
        fiproc_update_pool();
        memset(msg_buf, 0, MAX_BUF_LEN);
        if (get_msg(&msg_type, msg_buf, &msg_len, MAX_BUF_LEN) != OK) {
            PRINT_ERROR("Failed to get message.\n");
            continue;
        }

        switch (msg_type) {
            case LIST_MSG:
                fiproc_small_ranged_delay();
                handle_list_msg(msg_len);
                break;

            case DECODE_MSG:
                fiproc_small_ranged_delay();
                handle_decode_msg(msg_buf, msg_len);
                break;

            case SUBSCRIBE_MSG:
                fiproc_small_ranged_delay();
                handle_subscribe_msg(msg_buf, msg_len);
                break;

            default:
                fiproc_small_ranged_delay();
                PRINT_ERROR("Invalid message type received.\n");
                break;
        }
    }
}
