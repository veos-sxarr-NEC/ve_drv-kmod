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
 * @file sysfs_sensor_attr_gen.h
 * @brief Generator macros for sysfs attributes of sensors
 */
#ifndef VE_DRV_SYSFS_SENSOR_ATTR_GEN_H_INCLUDE_
#define VE_DRV_SYSFS_SENSOR_ATTR_GEN_H_INCLUDE_
#include <linux/kernel.h>
#include "internal.h"

#define SENSOR_VALUE_SHOW(SENSOR, DECODER)			\
static ssize_t sensor_##SENSOR##_show(				\
		struct device *dev,				\
		struct device_attribute *attr,			\
		char *buf)					\
{								\
	ssize_t len;						\
	struct ve_dev *vedev = dev_get_drvdata(dev);		\
	struct ve_node *node = vedev->node;			\
	uint32_t sensor_val;					\
	int64_t print_val;					\
								\
	pdev_trace(vedev->pdev);				\
								\
	if( vedev->arch_class->name[2] == '1' )	{		\
		if (node->ve_state != VE_ST_ONLINE)		\
			return -EIO;				\
	}	                                                \
	mutex_lock(&node->sysfs_mutex);				\
	sensor_val = node->sensor_rawdata[SENSOR];		\
	if( vedev->arch_class->name[2] == '1' ?  sensor_val == 0xFFFF : sensor_val == 0xFFFFFFFF ) { \
		len = -EAGAIN;					\
		goto err;					\
	}							\
	print_val = DECODER(vedev->arch_class->name[2] == '1' ?  (uint16_t)sensor_val : sensor_val );\
	len = scnprintf(buf, PAGE_SIZE,				\
			"%lld\n", print_val);			\
err:								\
	mutex_unlock(&node->sysfs_mutex);			\
								\
	return len;						\
}

#define SENSOR_VALUE_STORE(SENSOR)			\
static ssize_t sensor_##SENSOR##_store(			\
		struct device *dev,			\
		struct device_attribute *attr,		\
		const char *buf, size_t count)		\
{							\
	struct ve_dev *vedev = dev_get_drvdata(dev);	\
	struct ve_node *node = vedev->node;		\
	unsigned long sensor_val;			\
							\
	pdev_trace(vedev->pdev);			\
							\
	if( vedev->arch_class->name[2] == '1' )	{	\
		if (node->ve_state != VE_ST_ONLINE)	\
			return -EIO;			\
	}	                                        \
							\
	if (kstrtoul(buf, 0, &sensor_val) < 0)		\
		return -EINVAL;				\
							\
	mutex_lock(&node->sysfs_mutex);			\
	node->sensor_rawdata[SENSOR] =			\
		vedev->arch_class->name[2] == '1' ? (uint16_t)sensor_val : (uint32_t)sensor_val; \
	mutex_unlock(&node->sysfs_mutex);		\
							\
	return count;					\
}

#define SENSOR_DEVICE_ATTR(SENSOR) DEVICE_ATTR_RW(sensor_##SENSOR)
#endif
