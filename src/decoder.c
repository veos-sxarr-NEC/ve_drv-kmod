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
 * @file decoder.c
 * @brief decoder functions for sysfs sensor attributes
 */
#include <linux/types.h>
#include "decoder.h"

/**
 * @brief Decode sensor value (type a)
 *
 * @detail
 * Value[11:0] x 500 uV
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_a(uint16_t raw_data)
{
	uint16_t sensor_val;

	sensor_val = raw_data & 0xFFF;
	return (int64_t)sensor_val * 500;
}

/**
 * @brief Decode sensor value (type b)
 *
 * @detail
 * Value[9:0] x 6250 uV
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_b(uint16_t raw_data)
{
	uint16_t sensor_val;

	sensor_val = raw_data & 0x3FF;
	return  (int64_t)sensor_val * 6250;
}

/**
 * @brief Decode sensor value (type c)
 *
 * @detail
 * Value[9:0] x 2197 uV
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_c(uint16_t raw_data)
{
	uint16_t sensor_val;

	sensor_val = raw_data & 0x3FF;
	return (int64_t)sensor_val * 2197;
}

/**
 * @brief Decode sensor value (type d)
 *
 * @detail
 * Value[9:0] x 62500 uV
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_d(uint16_t raw_data)
{
	uint16_t sensor_val;

	sensor_val = raw_data & 0x3FF;
	return (int64_t)sensor_val * 62500;
}

/**
 * @brief Decode sensor value (type e)
 *
 * @detail
 * Value[9:0] x 172 uV
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_e(uint16_t raw_data)
{
	uint16_t sensor_val;

	sensor_val = raw_data & 0x3FF;
	return (int64_t)sensor_val * 17200;
}

/**
 * @brief Decode sensor value (type f)
 *
 * @detail
 * Value[9:0] x 4394 uV
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_f(uint16_t raw_data)
{
	uint16_t sensor_val;

	sensor_val = raw_data & 0x3FF;
	return (int64_t)sensor_val * 4394;
}

/**
 * @brief Decode sensor value (type g)
 *
 * @detail
 * Value[15:0] x 2 mA
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_g(uint16_t raw_data)
{
	return (int64_t)raw_data * 2;
}

/**
 * @brief Decode sensor value (type h)
 *
 * @detail
 * Value[11] == 1 -> Value[10:0] x 125000 uC
 * Value[11] == 0 -> (~Value[10:0] + 1) * -125000 uC
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_h(uint16_t raw_data)
{
	uint16_t sensor_val;

	sensor_val = raw_data & 0xFFF;
	if (sensor_val & (1 << 11))
		return (int64_t)(~(sensor_val & 0x7FF) + 1) * -125000;
	else
		return (int64_t)(sensor_val & 0x7FF) * 125000;
}

/**
 * @brief Decode sensor value (type i)
 *
 * @detail
 * Value[15:6] x 250000 - 64000000 uC
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_i(uint16_t raw_data)
{
	uint16_t sensor_val;

	sensor_val  = (raw_data >> 6) & 0x3FF;
	return (int64_t)sensor_val * 250000 - 64000000;
}

/**
 * @brief Decode sensor value (type j)
 *
 * @detail
 * Value[9] == 1 -> (Value[8:0] - 512) * -250000 uC
 * Value[9] == 0 -> Value[8:0] * 250000 uC
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_j(uint16_t raw_data)
{
	uint16_t sensor_val;

	sensor_val  = raw_data & 0x3FF;
	if (sensor_val & (1 << 9))
		return (int64_t)((sensor_val & 0x1FF) - 512) * -250000;
	else
		return (int64_t)(sensor_val & 0x1FF) * 250000;
}

/**
 * @brief Decode sensor value (type k)
 *
 * @detail
 * 90000 * 60 / Value[15:0] rpm
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_k(uint16_t raw_data)
{
	if (raw_data)
		return (int64_t)(90000 * 60) / raw_data;
	else
		return 0;
}

/**
 * @brief Decode sensor value (type l)
 *
 * @detail
 * Value[9:0] x 7800 uV
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_l(uint16_t raw_data)
{
	uint16_t sensor_val;

	sensor_val = raw_data & 0x3FF;
	return  (int64_t)sensor_val * 7800;
}

/**
 * @brief Decode sensor value (type m)
 *
 * @detail
 * Value[9:0] x 6250 - 290000 uV
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_m(uint16_t raw_data)
{
	int64_t retval;

	retval = (int64_t)(raw_data & 0x3FF) * 6250;
	if (retval >= 290000)
		retval -= 290000;
	return retval;
}

/**
 * @brief Decode sensor value (type n)
 *
 * @detail
 * No decode
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_n(uint16_t raw_data)
{
	return (int64_t)raw_data;
}

/**
 * @brief Decode sensor value (type n)
 *
 * @detail
 * No decode
 *
 * @param raw_data: RAW sensor value
 *
 * @return decoded sensor value
 */
int64_t ve_drv_sysfs_sensor_type_N(uint32_t raw_data)
{
	return (int64_t)raw_data;
}
