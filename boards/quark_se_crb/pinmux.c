/* pinmux.c - general pinmux operation */

/*
 * Copyright (c) 2015-2016 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <nanokernel.h>
#include <device.h>
#include <init.h>
#include <pinmux.h>
#include <sys_io.h>
#include "pinmux/pinmux.h"
#include "quark_se_pinmux_common.h"

#define PINMUX_SELECT_OFFSET	0x30

#define PINMUX_SELECT_REGISTER(base, reg_offset) \
	(base + PINMUX_SELECT_OFFSET + (reg_offset << 2))

/*
 * A little decyphering of what is going on here:
 *
 * Each pinmux register rperesents a bank of 16 pins, 2 bits per pin for a total
 * of four possible settings per pin.
 *
 * The first argument to the macro is name of the uint32_t's that is being used
 * to contain the bit patterns for all the configuration registers.  The pin
 * number divided by 16 selects the correct register bank based on the pin
 * number.
 *
 * The pin number % 16 * 2 selects the position within the register bank for the
 * bits controlling the pin.
 *
 * All but the lower two bits of the config values are masked off to ensure
 * that we don't inadvertently affect other pins in the register bank.
 */
#define PIN_CONFIG(A, _pin, _func) \
	(A[((_pin) / 16)] |= ((0x3 & (_func)) << (((_pin) % 16) * 2)))

/*
 * This is the full pinmap that we have available on the board for configuration
 * including the ball position and the various modes that can be set.  In the
 * _pinmux_defaults we do not spend any time setting values that are using mode
 * A as the hardware brings up all devices by default in mode A.
 */

/* pin, ball, mode A, mode B, mode C */
/* 0  F02, gpio_0, ain_0, spi_s_cs */
/* 1  G04, gpio_1, ain_1, spi_s_miso */
/* 2  H05, gpio_2, ain_2, spi_s_sck */
/* 3  J06, gpio_3, ain_3, spi_s_mosi */
/* 4  K06, gpio_4, ain_4, NA */
/* 5  L06, gpio_5, ain_5, NA */
/* 6  H04, gpio_6, ain_6, NA */
/* 7  G03, gpio_7, ain_7, NA */
/* 8  L05, gpio_ss_0, ain_8, uart1_cts */
/* 9  M05, gpio_ss_1, ain_9, uart1_rts */
/* 10 K05, gpio_ss_2, ain_10 */				/* AD0 */
/* 11 G01, gpio_ss_3, ain_11 */				/* AD1 */
/* 12 J04, gpio_ss_4, ain_12 */				/* AD2 */
/* 13 G02, gpio_ss_5, ain_13 */				/* AD3 */
/* 14 F01, gpio_ss_6, ain_14 */				/* AD4 */
/* 15 J05, gpio_ss_7, ain_15 */				/* AD5 */
/* 16 L04, gpio_ss_8, ain_16, uart1_txd */		/* IO1 */
/* 17 M04, gpio_ss_9, ain_17, uart1_rxd */		/* IO0 */
/* 18 K04, uart0_rx, ain_18, NA */
/* 19 B02, uart0_tx, gpio_31, NA */
/* 20 C01, i2c0_scl, NA, NA */
/* 21 C02, i2c0_sda, NA, NA */
/* 22 D01, i2c1_scl, NA, NA */
/* 23 D02, i2c1_sda, NA, NA */
/* 24 E01, i2c0_ss_sda, NA, NA */
/* 25 E02, i2c0_ss_scl, NA, NA */
/* 26 B03, i2c1_ss_sda, NA, NA */
/* 27 A03, i2c1_ss_scl, NA, NA */
/* 28 C03, spi0_ss_miso, NA, NA */
/* 29 E03, spi0_ss_mosi, NA, NA */
/* 30 D03, spi0_ss_sck, NA, NA */
/* 31 D04, spi0_ss_cs0, NA, NA */
/* 32 C04, spi0_ss_cs1, NA, NA */
/* 33 B04, spi0_ss_cs2, gpio_29, NA */
/* 34 A04, spi0_ss_cs3, gpio_30, NA */
/* 35 B05, spi1_ss_miso, NA, NA */
/* 36 C05, spi1_ss_mosi, NA, NA */
/* 37 D05, spi1_ss_sck, NA, NA */
/* 38 E05, spi1_ss_cs0, NA, NA */
/* 39 E04, spi1_ss_cs1, NA, NA */
/* 40 A06, spi1_ss_cs2, uart0_cts, NA */
/* 41 B06, spi1_ss_cs3, uart0_rts, NA */
/* 42 C06, gpio_8, spi1_m_sck, NA */			/* IO13 */
/* 43 D06, gpio_9, spi1_m_miso, NA */			/* IO12 */
/* 44 E06, gpio_10, spi1_m_mosi, NA */			/* IO11 */
/* 45 D07, gpio_11, spi1_m_cs0, NA */			/* IO10 */
/* 46 C07, gpio_12, spi1_m_cs1, NA */
/* 47 B07, gpio_13, spi1_m_cs2, NA */
/* 48 A07, gpio_14, spi1_m_cs3, NA */
/* 49 B08, gpio_15, i2s_rxd, NA */			/* IO5 */
/* 50 A08, gpio_16, i2s_rscki, NA */			/* IO8 */
/* 51 B09, gpio_17, i2s_rws, NA */			/* IO3 */
/* 52 A09, gpio_18, i2s_tsck, NA */			/* IO2 */
/* 53 C09, gpio_19, i2s_twsi, NA */			/* IO4 */
/* 54 D09, gpio_20, i2s_txd, NA */			/* IO7 */
/* 55 D08, gpio_21, spi0_m_sck, NA */
/* 56 E07, gpio_22, spi0_m_miso, NA */
/* 57 E09, gpio_23, spi0_m_mosi, NA */
/* 58 E08, gpio_24, spi0_m_cs0, NA */
/* 59 A10, gpio_25, spi0_m_cs1, NA */
/* 60 B10, gpio_26, spi0_m_cs2, NA */
/* 61 C10, gpio_27, spi0_m_cs3, NA */
/* 62 D10, gpio_28, NA, NA */
/* 63 E10, gpio_ss_10, pwm_0, NA */			/* IO3 */
/* 64 D11, gpio_ss_11, pwm_1, NA */			/* IO5 */
/* 65 C11, gpio_ss_12, pwm_2, NA */			/* IO6 */
/* 66 B11, gpio_ss_13, pwm_3, NA */			/* IO9 */
/* 67 D12, gpio_ss_14, clkout_32khz, NA */
/* 68 C12, gpio_ss_15, clkout_16mhz, NA */

static uint32_t mux_config[PINMUX_MAX_REGISTERS] = { 0, 0, 0, 0, 0};

struct pinmux_config board_pmux = {
	.base_address = CONFIG_PINMUX_BASE,
};

int pinmux_initialize(struct device *port)
{
	int i=0;

	quark_se_pinmux_initialize_common(port, mux_config);

	PIN_CONFIG(mux_config, 10, PINMUX_FUNC_B);
	PIN_CONFIG(mux_config, 42, PINMUX_FUNC_B);
	PIN_CONFIG(mux_config, 43, PINMUX_FUNC_B);
	PIN_CONFIG(mux_config, 44, PINMUX_FUNC_B);
	PIN_CONFIG(mux_config, 46, PINMUX_FUNC_B);
	PIN_CONFIG(mux_config, 47, PINMUX_FUNC_B);
	PIN_CONFIG(mux_config, 55, PINMUX_FUNC_B);
	PIN_CONFIG(mux_config, 56, PINMUX_FUNC_B);
	PIN_CONFIG(mux_config, 57, PINMUX_FUNC_B);

	for (i = 0; i < PINMUX_MAX_REGISTERS; i++) {
		sys_write32(mux_config[i], PINMUX_SELECT_REGISTER(board_pmux.base_address, i));
	}
	return DEV_OK;
}

DEVICE_INIT(pmux,                   /* config name */
			PINMUX_NAME,            /* driver name */
			&pinmux_initialize,     /* init function */
			NULL,
			&board_pmux,            /* config options*/
			SECONDARY,
			CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
