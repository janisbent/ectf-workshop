/**
 * @file crt0.S
 * @brief C runtime and interrupt vectors
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2025 Carnegie Mellon University
 */

.syntax unified
.arch armv7e-m
.thumb

.section .vectors

.align 9 // vector table must be aligned to 512
.globl _vectors
_vectors:
    // Cortex-M4 interrupts
    .long __StackTop             // Top of Stack
    .long _reset                 // Reset Handler
    .long _unimplemented_handler // NMI Handler
    .long _unimplemented_handler // Hard Fault Handler
    .long _unimplemented_handler // MPU Fault Handler
    .long _unimplemented_handler // Bus Fault Handler
    .long _unimplemented_handler // Usage Fault Handler
    .long 0                      // Reserved
    .long 0                      // Reserved
    .long 0                      // Reserved
    .long 0                      // Reserved
    .long _unimplemented_handler // SVCall Handler
    .long _unimplemented_handler // Debug Monitor Handler
    .long 0                      // Reserved
    .long _unimplemented_handler // PendSV Handler
    .long _unimplemented_handler // SysTick Handler

    // MAX78000 interrupts
    .long _unimplemented_handler // 0x10  0x0040  16: Power Fail
    .long _unimplemented_handler // 0x11  0x0044  17: Watchdog 0
    .long _unimplemented_handler // 0x12  0x0048  18: Reserved
    .long _unimplemented_handler // 0x13  0x004C  19: RTC
    .long _unimplemented_handler // 0x14  0x0050  20: True Random Number Generator
    .long _unimplemented_handler // 0x15  0x0054  21: Timer 0
    .long _unimplemented_handler // 0x16  0x0058  22: Timer 1
    .long _unimplemented_handler // 0x17  0x005C  23: Timer 2
    .long _unimplemented_handler // 0x18  0x0060  24: Timer 3
    .long _unimplemented_handler // 0x19  0x0064  25: Timer 4 (LP)
    .long _unimplemented_handler // 0x1A  0x0068  26: Timer 5 (LP)
    .long _unimplemented_handler // 0x1B  0x006C  27: Reserved
    .long _unimplemented_handler // 0x1C  0x0070  28: Reserved
    .long _unimplemented_handler // 0x1D  0x0074  29: I2C0
    .long _unimplemented_handler // 0x1E  0x0078  30: UART 0
    .long _unimplemented_handler // 0x1F  0x007C  31: UART 1
    .long _unimplemented_handler // 0x20  0x0080  32: SPI1
    .long _unimplemented_handler // 0x21  0x0084  33: Reserved
    .long _unimplemented_handler // 0x22  0x0088  34: Reserved
    .long _unimplemented_handler // 0x23  0x008C  35: Reserved
    .long _unimplemented_handler // 0x24  0x0090  36: ADC
    .long _unimplemented_handler // 0x25  0x0094  37: Reserved
    .long _unimplemented_handler // 0x26  0x0098  38: Reserved
    .long _unimplemented_handler // 0x27  0x009C  39: Flash Controller
    .long _unimplemented_handler // 0x28  0x00A0  40: GPIO0
    .long _unimplemented_handler // 0x29  0x00A4  41: GPIO1
    .long _unimplemented_handler // 0x2A  0x00A8  42: GPIO2 (LP)
    .long _unimplemented_handler // 0x2B  0x00AC  43: Reserved
    .long _unimplemented_handler // 0x2C  0x00B0  44: DMA0
    .long _unimplemented_handler // 0x2D  0x00B4  45: DMA1
    .long _unimplemented_handler // 0x2E  0x00B8  46: DMA2
    .long _unimplemented_handler // 0x2F  0x00BC  47: DMA3
    .long _unimplemented_handler // 0x30  0x00C0  48: Reserved
    .long _unimplemented_handler // 0x31  0x00C4  49: Reserved
    .long _unimplemented_handler // 0x32  0x00C8  50: UART 2
    .long _unimplemented_handler // 0x33  0x00CC  51: Reserved
    .long _unimplemented_handler // 0x34  0x00D0  52: I2C1
    .long _unimplemented_handler // 0x35  0x00D4  53: Reserved
    .long _unimplemented_handler // 0x36  0x00D8  54: Reserved
    .long _unimplemented_handler // 0x37  0x00DC  55: Reserved
    .long _unimplemented_handler // 0x38  0x00E0  56: Reserved
    .long _unimplemented_handler // 0x39  0x00E4  57: Reserved
    .long _unimplemented_handler // 0x3A  0x00E8  58: Reserved
    .long _unimplemented_handler // 0x3B  0x00EC  59: Reserved
    .long _unimplemented_handler // 0x3C  0x00F0  60: Reserved
    .long _unimplemented_handler // 0x3D  0x00F4  61: Reserved
    .long _unimplemented_handler // 0x3E  0x00F8  62: Reserved
    .long _unimplemented_handler // 0x3F  0x00FC  63: Reserved
    .long _unimplemented_handler // 0x40  0x0100  64: Reserved
    .long _unimplemented_handler // 0x41  0x0104  65: Reserved
    .long _unimplemented_handler // 0x42  0x0108  66: Reserved
    .long _unimplemented_handler // 0x43  0x010C  67: Reserved
    .long _unimplemented_handler // 0x44  0x0110  68: Reserved
    .long _unimplemented_handler // 0x45  0x0114  69: Wakeup Timer
    .long _unimplemented_handler // 0x46  0x0118  70: GPIO and AIN Wakeup
    .long _unimplemented_handler // 0x47  0x011C  71: Reserved
    .long _unimplemented_handler // 0x48  0x0120  72: SPI0
    .long _unimplemented_handler // 0x49  0x0124  73: LP Watchdog
    .long _unimplemented_handler // 0x4A  0x0128  74: Reserved
    .long _unimplemented_handler // 0x4B  0x012C  75: Pulse Train
    .long _unimplemented_handler // 0x4C  0x0130  76: Reserved
    .long _unimplemented_handler // 0x4D  0x0134  77: Reserved
    .long _unimplemented_handler // 0x4E  0x0138  78: I2C2
    .long _unimplemented_handler // 0x4F  0x013C  79: RISC-V
    .long _unimplemented_handler // 0x50  0x0140  80: Reserved
    .long _unimplemented_handler // 0x51  0x0144  81: Reserved
    .long _unimplemented_handler // 0x52  0x0148  82: Reserved
    .long _unimplemented_handler // 0x53  0x014C  83: One Wire Master
    .long _unimplemented_handler // 0x54  0x0150  84: Reserved
    .long _unimplemented_handler // 0x55  0x0154  85: Reserved
    .long _unimplemented_handler // 0x56  0x0158  86: Reserved
    .long _unimplemented_handler // 0x57  0x015C  87: Reserved
    .long _unimplemented_handler // 0x58  0x0160  88: Reserved
    .long _unimplemented_handler // 0x59  0x0164  89: Reserved
    .long _unimplemented_handler // 0x5A  0x0168  90: Reserved
    .long _unimplemented_handler // 0x5B  0x016C  91: Reserved
    .long _unimplemented_handler // 0x5C  0x0170  92: Reserved
    .long _unimplemented_handler // 0x5D  0x0174  93: Reserved
    .long _unimplemented_handler // 0x5E  0x0178  94: Reserved
    .long _unimplemented_handler // 0x5F  0x017C  95: Reserved
    .long _unimplemented_handler // 0x60  0x0180  96: Reserved
    .long _unimplemented_handler // 0x61  0x0184  97: Reserved
    .long _unimplemented_handler // 0x62  0x0188  98: ECC
    .long _unimplemented_handler // 0x63  0x018C  99: DVS
    .long _unimplemented_handler // 0x64  0x0190 100: SIMO
    .long _unimplemented_handler // 0x65  0x0194 101: Reserved
    .long _unimplemented_handler // 0x66  0x0198 102: Reserved
    .long _unimplemented_handler // 0x67  0x019C 103: Reserved
    .long _unimplemented_handler // 0x68  0x01A0 104: UART 3 (LP)
    .long _unimplemented_handler // 0x69  0x01A4 105: Reserved
    .long _unimplemented_handler // 0x6A  0x01A8 106: Reserved
    .long _unimplemented_handler // 0x6B  0x01AC 107: PCIF (Camera)
    .long _unimplemented_handler // 0x6C  0x01B0 108: Reserved
    .long _unimplemented_handler // 0x6D  0x01B4 109: Reserved
    .long _unimplemented_handler // 0x6E  0x01B8 110: Reserved
    .long _unimplemented_handler // 0x6F  0x01BC 111: Reserved
    .long _unimplemented_handler // 0x70  0x01C0 112: Reserved
    .long _unimplemented_handler // 0x71  0x01C4 113: AES
    .long _unimplemented_handler // 0x72  0x01C8 114: Reserved
    .long _unimplemented_handler // 0x73  0x01CC 115: I2S
    .long _unimplemented_handler // 0x74  0x01D0 116: CNN FIFO
    .long _unimplemented_handler // 0x75  0x01D4 117: CNN
    .long _unimplemented_handler // 0x76  0x01D8 118: Reserved
    .long _unimplemented_handler // 0x77  0x01Dc 119: LP Comparator


.section .crt0

.align 2
.thumb_func
.globl _reset
.type _reset, %function
_reset:
    // initialize stack
    ldr     r0, =__StackTop
    mov     sp, r0

    // load .data into sram
    ldr     r1, =_data_load
    ldr     r2, =_data_start
    ldr     r3, =_data_end
    subs    r3, r2
    ble     .L_data_done
.L_data_loop:
    subs    r3, #4
    ldr     r0, [r1, r3]
    str     r0, [r2, r3]
    bgt     .L_data_loop
.L_data_done:

    ldr     r1, =_flashprog_load
    ldr     r2, =_flashprog_start
    ldr     r3, =_flashprog_end
    subs    r3, r2
    ble     .L_flashprog_done
.L_flashprog_loop:
    subs    r3, #4
    ldr     r0, [r1, r3]
    str     r0, [r2, r3]
    bgt     .L_flashprog_loop
.L_flashprog_done:

    // zero out .bss
    ldr     r1, =_bss_start
    ldr     r2, =_bss_end
    movs    r0, 0
.L_bss_loop:
    cmp     r1, r2
    itt     lt
    strlt   r0, [r1], #4
    blt     .L_bss_loop

    // call main()
    ldr     r0, =main
    blx     r0

.L_spin:
    // spin if main ever returns
    b       .L_spin

.thumb_func
.globl _unimplemented_handler
.type _unimplemented_handler, %function
_unimplemented_handler:
    b       _unimplemented_handler
