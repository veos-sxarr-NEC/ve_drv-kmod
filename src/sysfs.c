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
 * @file sysfs.c
 * @brief VE driver sysfs functions.
 */

#include <linux/kernel.h>

#include "ve_drv.h"
#include "decoder.h"
#include "internal.h"
#include "sensor.h"

/**
 * @brief VE state strings
 */
const char *ve_state_str[] = {
	"UNINITIALIZED",
	"ONLINE",
	"OFFLINE",
	"MAINTENANCE",
	"UNAVAILABLE",
};

/**
 * @brief VEOS state strings
 */
const char *os_state_str[] = {
	"ONLINE",
	"OFFLINE",
	"INITIALIZING",
	"TERMINATING",
};

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
static int64_t sensor_type_a(uint16_t raw_data)
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
static int64_t sensor_type_b(uint16_t raw_data)
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
static int64_t sensor_type_c(uint16_t raw_data)
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
static int64_t sensor_type_d(uint16_t raw_data)
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
static int64_t sensor_type_e(uint16_t raw_data)
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
static int64_t sensor_type_f(uint16_t raw_data)
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
static int64_t sensor_type_g(uint16_t raw_data)
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
static int64_t sensor_type_h(uint16_t raw_data)
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
static int64_t sensor_type_i(uint16_t raw_data)
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
static int64_t sensor_type_j(uint16_t raw_data)
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
static int64_t sensor_type_k(uint16_t raw_data)
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
static int64_t sensor_type_l(uint16_t raw_data)
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
static int64_t sensor_type_m(uint16_t raw_data)
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
static int64_t sensor_type_n(uint16_t raw_data)
{
	return (int64_t)raw_data;
}


/**
 * @brief ve_state show attribute
 *
 * @param[in] dev: device structure
 * @param[in] attr: device attribute structure
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t ve_state_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	mutex_lock(&vedev->node->sysfs_mutex);
	len = scnprintf(buf, PAGE_SIZE, "%d\n", vedev->node->ve_state);
	mutex_unlock(&vedev->node->sysfs_mutex);

	return len;
}

static void ve_init_intr_count(struct ve_dev *vedev)
{
	struct ve_node *node = vedev->node;
	int noc = vedev->node->core_fls;
	int core_id;

	/* Init each cores */
	for (core_id = 0; core_id < noc; core_id++)
		node->core[core_id]->count =  0;
}

/**
 * @brief ve_state store attribute
 *
 * @param[in] dev: device structure
 * @param[in] attr: device attribute structure
 * @param[in] buf: Read buffer
 * @param count: number of characters in buffer
 *
 * @return count on success
 */
static ssize_t ve_state_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	int ret;
	int sensor_num;
	struct ve_dev *vedev = dev_get_drvdata(dev);
	unsigned long value;
	unsigned long cur_state;

	ret = kstrtoul(buf, 0, &value);
	if (ret)
		return ret;

	mutex_lock(&vedev->node->sysfs_mutex);
	cur_state = vedev->node->ve_state;
	if (cur_state < VE_ST_UNINITIALIZED || VE_ST_UNAVAILABLE < cur_state) {
		pdev_err(vedev->pdev, "ve_state: current state is invalid\n");
		goto error1;
	}
	switch (value) {
	case VE_ST_UNINITIALIZED:
		if (!(cur_state == VE_ST_MAINTENANCE
		      || cur_state == VE_ST_UNAVAILABLE)) {
			ret = -EINVAL;
			goto error;
		}
		break;
	case VE_ST_ONLINE:
		if (cur_state != VE_ST_OFFLINE) {
			ret = -EINVAL;
			goto error;
		}
		/* Init jiffies */
		vedev->node->online_jiffies = get_jiffies_64();

		/* Init sensor values */
		for (sensor_num = 0; sensor_num < NR_VE_SENSOR; sensor_num++)
			vedev->node->sensor_rawdata[sensor_num] = 0xffff;

		/* Init driver parameters */
		hw_intr_test_param = 0;

		/* Clear Interrupt Vector Register */
		ve_bar2_write64_20(vedev,
				PCI_BAR2_SCR_OFFSET + CREG_INTERRUPT_VECTOR,
				~0ULL);

		/* Clear interrupt count */
		ve_init_intr_count(vedev);

		/* Init EXSRAR */
		(void)ve_init_exsrar(vedev);

		break;
	case VE_ST_OFFLINE:
		vedev->node->online_jiffies = -1;
		break;
	case VE_ST_MAINTENANCE:
		if (cur_state != VE_ST_OFFLINE) {
			ret = -EINVAL;
			goto error;
		}
		break;
	case VE_ST_UNAVAILABLE:
		break;
	default:
		ret = -EINVAL;
		pdev_dbg(vedev->pdev, "ve_state: invalid state is specified\n");
		goto error1;
	}

	vedev->node->ve_state = value;
	sysfs_notify(&dev->kobj, NULL, "ve_state");
	mutex_unlock(&vedev->node->sysfs_mutex);
	return count;

 error:
	pdev_dbg(vedev->pdev,
			"ve_state: transition from %s to %s is prohibited\n",
			ve_state_str[cur_state], ve_state_str[value]);
 error1:
	mutex_unlock(&vedev->node->sysfs_mutex);
	return ret;
}
static DEVICE_ATTR_RW(ve_state);

/**
 * @brief os_state show attribute
 *
 * @param[in] dev: device structure
 * @param[in] attr: device attribute structure
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t os_state_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	mutex_lock(&vedev->node->sysfs_mutex);
	len = scnprintf(buf, PAGE_SIZE, "%d\n", vedev->node->os_state);
	mutex_unlock(&vedev->node->sysfs_mutex);

	return len;
}

/**
 * @brief os_state store attribute
 *
 * @param[in] dev: device structure
 * @param[in] attr: device attribute structure
 * @param[in] buf: Read buffer
 * @param count: number of characters in buffer
 *
 * @return count on success
 */
static ssize_t os_state_store(struct device *dev,
				 struct device_attribute *attr, const char *buf,
				 size_t count)
{
	int ret;
	struct ve_dev *vedev = dev_get_drvdata(dev);
	unsigned long value;
	unsigned long cur_state;

	ret = kstrtoul(buf, 0, &value);
	if (ret)
		return ret;

	mutex_lock(&vedev->node->sysfs_mutex);
	cur_state = vedev->node->os_state;
	if (cur_state < OS_ST_ONLINE || OS_ST_TERMINATING < cur_state) {
		pdev_err(vedev->pdev, "os_state: current state is invalid\n");
		goto error1;
	}
	switch (value) {
	case OS_ST_ONLINE:
		if (cur_state != OS_ST_INITIALIZING) {
			ret = -EINVAL;
			goto error;
		}
		break;
	case OS_ST_OFFLINE:
		if (!(cur_state == OS_ST_INITIALIZING
			|| cur_state == OS_ST_TERMINATING)) {
			ret = -EINVAL;
			goto error;
		}
		break;
	case OS_ST_INITIALIZING:
		if (cur_state != OS_ST_OFFLINE) {
			ret = -EINVAL;
			goto error;
		}
		break;
	case OS_ST_TERMINATING:
		if (cur_state != OS_ST_ONLINE) {
			ret = -EINVAL;
			goto error;
		}
		break;
	default:
		ret = -EINVAL;
		pdev_dbg(vedev->pdev, "os_state: invalid state is specified\n");
		goto error1;
	}

	vedev->node->os_state = value;
	sysfs_notify(&dev->kobj, NULL, "os_state");
	mutex_unlock(&vedev->node->sysfs_mutex);
	return count;

 error:
	pdev_dbg(vedev->pdev,
			"os_state: transition from %s to %s is prohibited\n",
			os_state_str[cur_state], os_state_str[value]);
 error1:
	mutex_unlock(&vedev->node->sysfs_mutex);
	return ret;
}
static DEVICE_ATTR_RW(os_state);

/**
 * @brief partitioning_mode show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t partitioning_mode_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	mutex_lock(&vedev->node->sysfs_mutex);
	len = scnprintf(buf, PAGE_SIZE, "%d\n",
			vedev->node->partitioning_mode);
	mutex_unlock(&vedev->node->sysfs_mutex);

	return len;
}

/**
 * @brief partitioning_mode store attribute
 *
 * @param[in] dev: device structure
 * @param[in] attr: device attribute structure
 * @param[in] buf: Read buffer
 * @param count: number of characters in buffer
 *
 * @return count on success
 */
static ssize_t partitioning_mode_store(struct device *dev,
					  struct device_attribute *attr,
					  const char *buf, size_t count)
{
	unsigned long mode;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	if (kstrtoul(buf, 0, &mode) < 0)
		return -EINVAL;

	if (mode < 0 || 1 < mode)
		return -EINVAL;

	mutex_lock(&vedev->node->sysfs_mutex);
	vedev->node->partitioning_mode = mode;
	mutex_unlock(&vedev->node->sysfs_mutex);

	return count;
}
static DEVICE_ATTR_RW(partitioning_mode);

/**
 * @brief throttling_level show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t throttling_level_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	mutex_lock(&vedev->node->sysfs_mutex);
	len = scnprintf(buf, PAGE_SIZE, "%d\n",
			vedev->node->throttling_level);
	mutex_unlock(&vedev->node->sysfs_mutex);

	return len;
}

/**
 * @brief throttling_level store attribute
 *
 * @param[in] dev: device structure
 * @param[in] attr: device attribute structure
 * @param[in] buf: Read buffer
 * @param count: number of characters in buffer
 *
 * @return count on success
 */
static ssize_t throttling_level_store(struct device *dev,
					  struct device_attribute *attr,
					  const char *buf, size_t count)
{
	unsigned long level;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	if (kstrtoul(buf, 0, &level) < 0)
		return -EINVAL;

	if (level < 0 || 9 < level)
		return -EINVAL;

	mutex_lock(&vedev->node->sysfs_mutex);
	vedev->node->throttling_level = level;
	mutex_unlock(&vedev->node->sysfs_mutex);

	return count;
}
static DEVICE_ATTR_RW(throttling_level);

/**
 * @brief num_of_core show attribute
 *
 * @param[in] dev: device structure
 * @param[in] attr: device attribute structure
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t num_of_core_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%u\n",
			vedev->node->hw_info.num_of_core);

	return len;
}
static DEVICE_ATTR_RO(num_of_core);

/**
 * @brief memory_size show attribute
 *
 * @param[in] dev: device structure
 * @param[in] attr: device attribute structure
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t memory_size_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%u\n",
			vedev->node->hw_info.memory_size);

	return len;
}
static DEVICE_ATTR_RO(memory_size);

/**
 * @brief model show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t model_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%u\n",
			vedev->node->hw_info.model);

	return len;
}
static DEVICE_ATTR_RO(model);

/**
 * @brief type show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t type_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%u\n",
			vedev->node->hw_info.type);

	return len;
}
static DEVICE_ATTR_RO(type);

/**
 * @brief cores_enable show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t cores_enable_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "0x%06x\n",
			vedev->node->hw_info.core_enables);

	return len;
}
static DEVICE_ATTR_RO(cores_enable);

/**
 * @brief chip_id show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t chip_id_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	/* TODO(TBD): print format (HW spec is not defined yet) */
	len = scnprintf(buf, PAGE_SIZE, "%016llx%016llx\n",
			vedev->node->hw_info.chip_sn[0],
			vedev->node->hw_info.chip_sn[1]);

	return len;
}
static DEVICE_ATTR_RO(chip_id);

/**
 * @brief serial show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t serial_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	/* TODO(TBD): print format (HW spec is not defined yet) */
	len = scnprintf(buf, PAGE_SIZE, "%016llx%016llx\n",
			vedev->node->hw_info.board_sn[0],
			vedev->node->hw_info.board_sn[1]);

	return len;
}
static DEVICE_ATTR_RO(serial);

/**
 * @brief fw_version show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t fw_version_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%d\n",
			vedev->node->hw_info.vmcfw_version);

	return len;
}
static DEVICE_ATTR_RO(fw_version);

/**
 * @brief clock_memory show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t clock_memory_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%d\n",
			vedev->node->hw_info.memory_clock);

	return len;
}
static DEVICE_ATTR_RO(clock_memory);

/**
 * @brief clock_chip show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t clock_chip_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%d\n",
			vedev->node->hw_info.core_clock);

	return len;
}
static DEVICE_ATTR_RO(clock_chip);

/**
 * @brief clock_base show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t clock_base_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%d\n",
			vedev->node->hw_info.base_clock);

	return len;
}
static DEVICE_ATTR_RO(clock_base);

/**
 * @brief cache_l1i show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t cache_l1i_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%d\n",
			vedev->node->model_info.i_cache_size);

	return len;
}
static DEVICE_ATTR_RO(cache_l1i);

/**
 * @brief cache_l1d show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t cache_l1d_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%d\n",
			vedev->node->model_info.d_cache_size);

	return len;
}
static DEVICE_ATTR_RO(cache_l1d);

/**
 * @brief cache_l2 show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t cache_l2_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%d\n",
			vedev->node->model_info.l2_cache_size);

	return len;
}
static DEVICE_ATTR_RO(cache_l2);

/**
 * @brief cache_llc show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t cache_llc_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%d\n",
			vedev->node->model_info.l3_cache_size);

	return len;
}
static DEVICE_ATTR_RO(cache_llc);

/**
 * @brief bar0_size show attribute
 *
 * @param[in] dev: device structure
 * @param[in] attr: device attribute structure
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t bar0_size_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "0x%zx\n", vedev->bar_size[0]);

	return len;
}
static DEVICE_ATTR_RO(bar0_size);

/**
 * @brief bar0_addr show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t bar0_addr_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "0x%llx\n", vedev->pbar[0]);

	return len;
}
static DEVICE_ATTR_RO(bar0_addr);

/**
 * @brief bar3_addr show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t bar3_addr_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "0x%llx\n", vedev->pbar[3]);

	return len;
}
static DEVICE_ATTR_RO(bar3_addr);

/**
 * @brief ve_jiffies show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t jiffies_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);
	struct ve_node *node = vedev->node;
	uint64_t jiffies;

	mutex_lock(&node->sysfs_mutex);

	if (node->online_jiffies == -1) {
		len = scnprintf(buf, PAGE_SIZE, "0\n");
		goto out;
	}

	jiffies = get_jiffies_64() - node->online_jiffies;

	len = scnprintf(buf, PAGE_SIZE, "%lld\n", jiffies);
out:
	mutex_unlock(&node->sysfs_mutex);

	return len;
}
static DEVICE_ATTR_RO(jiffies);

/**
 * @brief sysfs show method of all VE task ID on the node
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return length of printed string
 */
static ssize_t task_id_all_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = print_task_info(vedev, buf, 0);

	return len;
}
static DEVICE_ATTR_RO(task_id_all);

/**
 * @brief sysfs show method of dead VE task ID on the node
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return length of printed string
 */
static ssize_t task_id_dead_show(struct device *dev,
				    struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = print_task_info(vedev, buf, 1);

	return len;
}
static DEVICE_ATTR_RO(task_id_dead);

/**
 * @brief abi_version show attribute
 *
 * @param[in] dev: device structure
 * @param[in] attr: device attribute structure
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t abi_version_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", VEDRV_ABI_VERSION);
}
static DEVICE_ATTR_RO(abi_version);

/**
 * @brief sysfs show method of the enable bit map of VE cores to the buffer.
 *		The value is AND of NUMA0_CORES and cores_enable
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: device attribute structure. It isn't used in this function,
 *						but expanded function requires.
 * @param[out] buf: Write buffer
 *
 * @return the number of characters printed
 */
static ssize_t numa0_cores_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct ve_dev *vedev = dev_get_drvdata(dev);

	return scnprintf(buf, PAGE_SIZE, "0x%x\n",
			NUMA0_CORES & vedev->node->hw_info.core_enables);
}
static DEVICE_ATTR_RO(numa0_cores);

/**
 * @brief sysfs show method of the enable bit map of VE cores to the buffer.
 *		The value is AND of NUMA1_CORES and cores_enable
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: device attribute structure. It isn't used in this function,
 *                                              but expanded function requires.
 * @param[out] buf: Write buffer
 *
 * @return the number of characters printed
 */
static ssize_t numa1_cores_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	struct ve_dev *vedev = dev_get_drvdata(dev);

	return scnprintf(buf, PAGE_SIZE, "0x%x\n",
			NUMA1_CORES & vedev->node->hw_info.core_enables);
}
static DEVICE_ATTR_RO(numa1_cores);

/**
 * @brief sysfs show method of the value dividing physical memory into
 *		the NUMA node's memory unit. The value must be 0x4000000.
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: device attribute structure. It isn't used in this function,
 *                                              but expanded function requires.
 * @param[out] buf: Write buffer
 *
 * @return the number of characters printed
 */
static ssize_t numa_mem_block_size_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "0x%x\n", NUMA_MEM_BLOCK_SIZE);
}
static DEVICE_ATTR_RO(numa_mem_block_size);


/**
 * @brief sysfs show method of the number of which NUMA node belongs to
 *		the first physical memory unit.
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: device attribute structure. It isn't used in this function,
 *                                              but expanded function requires.
 * @param[out] buf: Write buffer
 *
 * @return the number of characters printed
 */
static ssize_t first_mem_node_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return scnprintf(buf, PAGE_SIZE, "%d\n", FIRST_MEM_NODE);
}
static DEVICE_ATTR_RO(first_mem_node);

#ifdef VE_DRV_DEBUG
/* for debug */
static ssize_t cond_upper_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%016llx\n", vedev->node->cond.upper);

	return len;
}
static DEVICE_ATTR_RO(cond_upper);

/* for debug */
static ssize_t cond_lower_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%016llx\n", vedev->node->cond.lower);

	return len;
}
static DEVICE_ATTR_RO(cond_lower);

/* for debug */
static ssize_t core_status_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = print_core_info(vedev->node, buf);

	return len;
}
static DEVICE_ATTR_RO(core_status);

/* for debug */
static ssize_t del_all_task_store(struct device *dev,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	unsigned long val;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	if (kstrtoul(buf, 0, &val) < 0)
		return -EINVAL;

	if (val)
		(void)ve_drv_del_all_task(vedev);

	return count;
}
static DEVICE_ATTR_WO(del_all_task);

/* for debug */
static ssize_t vemem_mmap_allow_list_show(struct device *dev,
					     struct device_attribute *attr,
					     char *buf)
{
	struct ve_dev *vedev = dev_get_drvdata(dev);
	struct ve_node *node = vedev->node;
	struct list_head *ptr, *head;
	struct ve_kuid_list *uid_list;
	uid_t uid;
	int ret = 0, len;

	ret = scnprintf(buf, PAGE_SIZE,
			"VEMEM entry %d is allowed to be mapped from UID:\n",
			node->sysfs_pciatb_entry);

	head = &node->mem_map[node->sysfs_pciatb_entry]->list;

	mutex_lock(&node->pcimap_mutex);
	list_for_each(ptr, head) {
		if (unlikely(ret >= PAGE_SIZE)) {
			mutex_unlock(&node->pcimap_mutex);
			return ret;
		}
		uid_list = list_entry(ptr, struct ve_kuid_list, list);
		uid = from_kuid_munged(current_user_ns(), uid_list->kuid);
		len = scnprintf(buf + ret, PAGE_SIZE - ret, "%d ", uid);
		ret += len;
	}
	mutex_unlock(&node->pcimap_mutex);

	if (likely(ret < PAGE_SIZE)) {
		len = scnprintf(buf + ret, PAGE_SIZE - ret, "\n");
		ret += len;
	}

	return ret;
}

/* for debug */
static ssize_t vemem_mmap_allow_list_store(struct device *dev,
					      struct device_attribute *attr,
					      const char *buf, size_t count)
{
	unsigned long entry;
	struct ve_dev *vedev = dev_get_drvdata(dev);
	struct ve_node *node = vedev->node;

	if (kstrtoul(buf, 0, &entry) < 0)
		return -EINVAL;

	if (entry >= node->model_info.num_of_pciatb || entry < 0)
		return -EINVAL;

	node->sysfs_pciatb_entry = (uint16_t)entry;

	return count;
}
static DEVICE_ATTR_RW(vemem_mmap_allow_list);

/* for debug */
static ssize_t vemem_mmap_allow_del_store(struct device *dev,
					     struct device_attribute *attr,
					     const char *buf, size_t count)
{
	unsigned long entry;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	if (kstrtoul(buf, 0, &entry) < 0)
		return -EINVAL;

	ve_drv_unassign_vemem_all(vedev);

	return count;
}
static DEVICE_ATTR_WO(vemem_mmap_allow_del);

/* for debug */
static ssize_t cr_mmap_allow_list_show(struct device *dev,
					  struct device_attribute *attr,
					  char *buf)
{
	struct ve_dev *vedev = dev_get_drvdata(dev);
	struct ve_node *node = vedev->node;
	struct list_head *ptr, *head;
	struct ve_kuid_list *uid_list;
	uid_t uid;
	int ret = 0, len;

	ret = scnprintf(buf, PAGE_SIZE,
			"CR PAGE %d is allowed to be mapped from UID:\n",
			node->sysfs_crpage_entry);

	head = &node->cr_map[node->sysfs_crpage_entry]->list;

	mutex_lock(&node->crmap_mutex);
	list_for_each(ptr, head) {
		if (unlikely(ret >= PAGE_SIZE)) {
			mutex_unlock(&node->crmap_mutex);
			return ret;
		}
		uid_list = list_entry(ptr, struct ve_kuid_list, list);
		uid = from_kuid_munged(current_user_ns(), uid_list->kuid);
		len = scnprintf(buf + ret, PAGE_SIZE - ret, "%d ", uid);
		ret += len;
	}
	mutex_unlock(&node->crmap_mutex);

	if (likely(ret < PAGE_SIZE)) {
		len = scnprintf(buf + ret, PAGE_SIZE - ret, "\n");
		ret += len;
	}

	return ret;
}

/* for debug */
static ssize_t cr_mmap_allow_list_store(struct device *dev,
					   struct device_attribute *attr,
					   const char *buf, size_t count)
{
	unsigned long entry;
	struct ve_dev *vedev = dev_get_drvdata(dev);
	struct ve_node *node = vedev->node;

	if (kstrtoul(buf, 0, &entry) < 0)
		return -EINVAL;

	if (entry >= node->model_info.num_of_crpage || entry < 0)
		return -EINVAL;

	node->sysfs_crpage_entry = (uint8_t)entry;

	return count;
}
static DEVICE_ATTR_RW(cr_mmap_allow_list);

/* for debug */
static ssize_t cr_mmap_allow_del_store(struct device *dev,
					  struct device_attribute *attr,
					  const char *buf, size_t count)
{
	unsigned long entry;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	if (kstrtoul(buf, 0, &entry) < 0)
		return -EINVAL;

	ve_drv_unassign_cr_all(vedev);

	return count;
}
static DEVICE_ATTR_WO(cr_mmap_allow_del);
#endif

/**
 * @brief sysfs attributes
 */
static struct attribute *sysfs_attrs[] = {
	&dev_attr_ve_state.attr,
	&dev_attr_os_state.attr,
	&dev_attr_partitioning_mode.attr,
	&dev_attr_throttling_level.attr,
	&dev_attr_num_of_core.attr,
	&dev_attr_memory_size.attr,
	&dev_attr_model.attr,
	&dev_attr_type.attr,
	&dev_attr_cores_enable.attr,
	&dev_attr_chip_id.attr,
	&dev_attr_serial.attr,
	&dev_attr_fw_version.attr,
	&dev_attr_clock_memory.attr,
	&dev_attr_clock_chip.attr,
	&dev_attr_clock_base.attr,
	&dev_attr_cache_l1i.attr,
	&dev_attr_cache_l1d.attr,
	&dev_attr_cache_l2.attr,
	&dev_attr_cache_llc.attr,
	&dev_attr_bar0_size.attr,
	&dev_attr_bar0_addr.attr,
	&dev_attr_bar3_addr.attr,
	&dev_attr_jiffies.attr,
	&dev_attr_task_id_all.attr,
	&dev_attr_task_id_dead.attr,
	&dev_attr_abi_version.attr,
	&dev_attr_numa0_cores.attr,
	&dev_attr_numa1_cores.attr,
	&dev_attr_numa_mem_block_size.attr,
	&dev_attr_first_mem_node.attr,
#ifdef VE_DRV_DEBUG
	&dev_attr_core_status.attr,
	&dev_attr_cond_upper.attr,
	&dev_attr_cond_lower.attr,
	&dev_attr_del_all_task.attr,
	&dev_attr_vemem_mmap_allow_list.attr,
	&dev_attr_vemem_mmap_allow_del.attr,
	&dev_attr_cr_mmap_allow_list.attr,
	&dev_attr_cr_mmap_allow_del.attr,
#endif
	NULL,
};

/**
 * @brief sysfs attribute group
 */
static struct attribute_group ve_drv_attribute_group = {
	.attrs = sysfs_attrs
};

/**
 * @brief Create sysfs on specified vedev
 *
 * @param[in] vedev: VE device structure
 *
 * @return 0 on success. Negative on failure.
 */
int ve_drv_init_sysfs(struct ve_dev *vedev)
{
	int err;
	struct ve_node *node;

	node = vedev->node;

	/* create sysfs files */
	err = sysfs_create_group(&vedev->device->kobj, &ve_drv_attribute_group);
	if (err) {
		pdev_err(vedev->pdev, "sysfs_create_group failed (%d)\n", err);
		return -1;
	}

	/* create sysfs sensor files */
	err = sysfs_create_group(&vedev->device->kobj, &sensor_attribute_group);
	if (err) {
		pdev_err(vedev->pdev,
				"sensor sysfs_create_group failed (%d)\n", err);
		return -1;
	}

	return 0;
}

/**
 * @brief Remove sysfs from specified vedev
 *
 * @param[in] vedev: VE device structure
 */
void ve_drv_fini_sysfs(struct ve_dev *vedev)
{
	sysfs_remove_group(&vedev->device->kobj, &ve_drv_attribute_group);
	sysfs_remove_group(&vedev->device->kobj, &sensor_attribute_group);
}
