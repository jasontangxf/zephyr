/* quark_se_pinmux_initialize_common.h - the private pinmux driver header */

/*
 * Copyright (c) 2015 Intel Corporation
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
#ifndef __QUARK_SE_PINMUX_COMMON_H
#define __QUARK_SE_PINMUX_COMMON_H

#include <stdint.h>

/*
 * On the QUARK_SE platform there are a minimum of 69 pins that can be possibly
 * set.  This would be a total of 5 registers to store the configuration as per
 * the bit description from above
 */
#define PINMUX_MAX_REGISTERS    5

/**
 * Configure the pinmux of common pins among all boards.
 *
 * @param port: device port address
 * @param mux_config: pointer to array mux_config
 *
 * @return - DRV_RC_OK on success.
 */

int quark_se_pinmux_initialize_common(struct device *port, uint32_t *mux_config);

#endif /* __QUARK_SE_PINMUX_COMMON_H */
