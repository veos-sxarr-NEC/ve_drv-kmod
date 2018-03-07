/*
 * Vector Engine Driver
 *
 * Copyright (C) 2017-2018 NEC Corporation
 * This file is part of VE Driver.
 *
 * VE Driver is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * VE Driver is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with the VE Driver; if not, see
 * <http://www.gnu.org/licenses/>.
 */

/*
 * @file decoder.h
 * @brief VE driver header for sensor decoding functions
 */

#ifndef VE_DECODER_H_INCLUDE_
#define VE_DECODER_H_INCLUDE_


static int64_t sensor_type_a(uint16_t raw_data);
static int64_t sensor_type_b(uint16_t raw_data);
static int64_t sensor_type_c(uint16_t raw_data);
static int64_t sensor_type_d(uint16_t raw_data);
static int64_t sensor_type_e(uint16_t raw_data);
static int64_t sensor_type_f(uint16_t raw_data);
static int64_t sensor_type_g(uint16_t raw_data);
static int64_t sensor_type_h(uint16_t raw_data);
static int64_t sensor_type_i(uint16_t raw_data);
static int64_t sensor_type_j(uint16_t raw_data);
static int64_t sensor_type_k(uint16_t raw_data);
static int64_t sensor_type_l(uint16_t raw_data);
static int64_t sensor_type_m(uint16_t raw_data);
static int64_t sensor_type_n(uint16_t raw_data);

#endif /* VE_DECODER_H_INCLUDE_ */
