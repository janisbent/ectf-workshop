/**
 * @file hardware_init.c
 * @brief Hardware initialization functions (simplified from MSDK)
 * @author Plaid Parliament of Pwning
 * @copyright Copyright (c) 2024 Carnegie Mellon University
 */

#include "hardware_init.h"

#include "host_uart.h"
#include "rng.h"

#include <gcr_regs.h>
#include <gpio.h>
#include <icc_regs.h>
#include <lpgcr_regs.h>
#include <max78000.h>
#include <mxc_delay.h>
#include <stddef.h>
#include <stdint.h>
#include <uart.h>

static void disable_irq(void);
static void disable_cache(void);
static void disable_clocks(void);
static void disable_events(void);

static void set_vtor(void);
static void select_ipo(void);
static void update_system_core_clock(void);

static void init_uart(void);

extern void (*const _vectors[])(void);
uint32_t SystemCoreClock;

/**
 * @brief Initializes required hardware peripherals
 */
void hardware_init(void) {
    // Disable unused functionalities
    disable_irq();
    disable_cache();
    disable_clocks();
    disable_events();

    // Setup originally done in SystemInit
    set_vtor();
    select_ipo();
    update_system_core_clock();

    // Setup originally done in Board_Init
    init_uart();

    // Setup RNG
    rng_init();

    // Wait for PMIC 1.8V to become available, about 180ms after power up
    // (originally done in Board_Init)
    MXC_Delay(200000);
}

/**
 * @brief Disables interrupts globally and on NVIC
 */
static void disable_irq(void) {
    // Mask interrupts globally (Reset, NMI, and HardFault are NOT maskable)
    __disable_irq();

    // Disable all interrupts that can be disabled
    for (IRQn_Type irq = 0; irq < MXC_IRQ_EXT_COUNT; irq++) {
        NVIC_DisableIRQ(irq); // irq MUST NOT be negative
    }
}

/**
 * @brief Disables the instruction cache
 */
static void disable_cache(void) {
    // Disable all ICCs
    MXC_ICC0->ctrl &= ~MXC_F_ICC_CTRL_EN;
    MXC_ICC1->ctrl &= ~MXC_F_ICC_CTRL_EN;
}

/**
 * @brief Disables other clocks
 */
static void disable_clocks(void) {
    // Disable regular peripheral clocks
    MXC_GCR->pclkdis0 |=
        MXC_F_GCR_PCLKDIS0_GPIO0 | MXC_F_GCR_PCLKDIS0_GPIO1 | MXC_F_GCR_PCLKDIS0_DMA |
        MXC_F_GCR_PCLKDIS0_SPI1 | MXC_F_GCR_PCLKDIS0_UART0 | MXC_F_GCR_PCLKDIS0_UART1 |
        MXC_F_GCR_PCLKDIS0_I2C0 | MXC_F_GCR_PCLKDIS0_TMR0 | MXC_F_GCR_PCLKDIS0_TMR1 |
        MXC_F_GCR_PCLKDIS0_TMR2 | MXC_F_GCR_PCLKDIS0_TMR3 | MXC_F_GCR_PCLKDIS0_ADC |
        MXC_F_GCR_PCLKDIS0_CNN | MXC_F_GCR_PCLKDIS0_I2C1 | MXC_F_GCR_PCLKDIS0_PT;
    MXC_GCR->pclkdis1 |=
        MXC_F_GCR_PCLKDIS1_UART2 | MXC_F_GCR_PCLKDIS1_TRNG | MXC_F_GCR_PCLKDIS1_SMPHR |
        MXC_F_GCR_PCLKDIS1_OWM | MXC_F_GCR_PCLKDIS1_CRC | MXC_F_GCR_PCLKDIS1_AES |
        MXC_F_GCR_PCLKDIS1_SPI0 | MXC_F_GCR_PCLKDIS1_PCIF | MXC_F_GCR_PCLKDIS1_I2S |
        MXC_F_GCR_PCLKDIS1_I2C2 | MXC_F_GCR_PCLKDIS1_WDT0 | MXC_F_GCR_PCLKDIS1_CPU1;

    // Disable low-power peripheral clocks
    MXC_LPGCR->pclkdis |= MXC_F_LPGCR_PCLKDIS_GPIO2 | MXC_F_LPGCR_PCLKDIS_WDT1 |
                          MXC_F_LPGCR_PCLKDIS_TMR4 | MXC_F_LPGCR_PCLKDIS_TMR5 |
                          MXC_F_LPGCR_PCLKDIS_UART3 | MXC_F_LPGCR_PCLKDIS_LPCOMP;
}

/**
 * @brief Disables events
 */
static void disable_events(void) {
    // Disable all events
    MXC_GCR->eventen &= ~(MXC_F_GCR_EVENTEN_DMA | MXC_F_GCR_EVENTEN_TX);
}

/**
 * @brief Set the vtor object
 */
static void set_vtor(void) {
    // Configure the interrupt controller to use the application vector table in
    // the application space
    SCB->VTOR = (uint32_t)_vectors;
}

/**
 * @brief Updates the system core clock
 */
static void update_system_core_clock(void) {
    const uint32_t div =
        (MXC_GCR->clkctrl & MXC_F_GCR_CLKCTRL_SYSCLK_DIV) >> MXC_F_GCR_CLKCTRL_SYSCLK_DIV_POS;

    SystemCoreClock = IPO_FREQ >> div;
}

/**
 * @brief Select IPO system clock (100MHz)
 */
static void select_ipo() {
    // Enable 100MHz clock (IPO)
    if (!(MXC_GCR->clkctrl & MXC_F_GCR_CLKCTRL_IPO_EN)) {
        MXC_GCR->clkctrl |= MXC_F_GCR_CLKCTRL_IPO_EN;

        while (!(MXC_GCR->clkctrl & MXC_F_GCR_CLKCTRL_IPO_RDY)) {
            ; // wait for IPO clock to be ready
        }
    }

    // Set IPO clock as System Clock
    MXC_GCR->clkctrl = (MXC_GCR->clkctrl & ~MXC_F_GCR_CLKCTRL_SYSCLK_SEL) |
                       (MXC_S_GCR_CLKCTRL_SYSCLK_SEL_IPO & MXC_F_GCR_CLKCTRL_SYSCLK_SEL);

    // Wait for system clock to be ready
    while (!(MXC_GCR->clkctrl & MXC_F_GCR_CLKCTRL_SYSCLK_RDY)) {
        ;
    }
}

/**
 * @brief Initialize UART
 */
static void init_uart(void) {
    MXC_UART_Init(MXC_UART_GET_UART(CONSOLE_UART), CONSOLE_BAUD, MXC_UART_IBRO_CLK);
}
