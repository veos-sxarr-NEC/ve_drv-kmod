/*
 * Vector Engine Driver
 *
 * Copyright (C) 2017-2020 NEC Corporation
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
 * @brief VE3 specific sysfs functions.
 */

#include <linux/kernel.h>
#include <linux/user_namespace.h>
#include <linux/cred.h>
#include <linux/sched/signal.h>

#define _VE_ARCH_VE3_ (1)
#include "ve_drv.h"
#include "decoder.h"
#include "internal.h"
#include "hw_ve3.h"
#include "sysfs_sensor_attr_gen.h"
#include "sensor_ve3.h"

/**
 * @brief VE state strings
 */
static const char *ve_state_str[] = {
	"UNDEFINEDSTATE",
	"AVAILABLE",
	"UNDEFINEDSTATE",
	"MAINTENANCE",
	"UNAVAILABLE",
};

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
 * @brief bar4_addr show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t bar4_addr_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);
	/* FIXME: CR SET address? */
	len = scnprintf(buf, PAGE_SIZE, "0x%llx\n", vedev->pbar[4]);

	return len;
}
static DEVICE_ATTR_RO(bar4_addr);

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
	unsigned int numa_cores = 0;
	struct ve_dev *vedev = dev_get_drvdata(dev);
	struct ve_node *node = vedev->node;
	struct ve_hw_info *info = &node->hw_info;

	if( info->model_type.version == 2 ){
		numa_cores = NUMA0_CORES_H2;
	} else {
		numa_cores = NUMA0_CORES;
	}

	return scnprintf(buf, PAGE_SIZE, "0x%llx\n",
			numa_cores & vedev->node->hw_info.core_enables);
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
	unsigned int numa_cores = 0;
	struct ve_dev *vedev = dev_get_drvdata(dev);
	struct ve_node *node = vedev->node;
	struct ve_hw_info *info = &node->hw_info;

	if( info->model_type.version == 2 ){
		numa_cores = NUMA1_CORES_H2;
	} else {
		numa_cores = NUMA1_CORES;
	}

	return scnprintf(buf, PAGE_SIZE, "0x%llx\n",
			numa_cores & vedev->node->hw_info.core_enables);
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



static ssize_t ownership_show(  struct device *dev,
				struct device_attribute *attr, char *buf)
{
  int len;
  unsigned long flags;
  struct ve_dev *vedev = dev_get_drvdata(dev);
  spin_lock_irqsave(&vedev->node->lock, flags);
  if (vedev->node->ownership != NULL){
    len = scnprintf(buf, PAGE_SIZE, "%d\n", pid_vnr(vedev->node->ownership));
  }else{
    len = scnprintf(buf, PAGE_SIZE, "none\n");
  }
  spin_unlock_irqrestore(&vedev->node->lock, flags);
  return len;

}
static DEVICE_ATTR_RO(ownership);

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
	if (cur_state != VE_ST_AVAILABLE && cur_state != VE_ST_UNAVAILABLE  &&
	    cur_state != VE_ST_MAINTENANCE) {
		pdev_err(vedev->pdev, "ve_state: current state is invalid\n");
		goto error1;
	}
	switch (value) {
	case VE_ST_AVAILABLE:

		/* Init jiffies */
		vedev->node->online_jiffies = get_jiffies_64();

		if( cur_state == VE_ST_UNAVAILABLE ){
		  /* Init sensor values */
		  for (sensor_num = 0;
		       sensor_num < vedev->arch_class->num_sensors;
		       sensor_num++)
		    vedev->node->sensor_rawdata[sensor_num] = 0xffffffff;
		}
		/* Init driver parameters */
		hw_intr_test_param = 0;

		/* Clear interrupt count */
		ve_init_intr_count(vedev);

		/* Init EXSRAR */
		(void)ve_init_exsrar(vedev);

		break;

	case VE_ST_MAINTENANCE:
		if (cur_state == VE_ST_MAINTENANCE
		    || cur_state == VE_ST_UNAVAILABLE) {
			ret = -EINVAL;
			goto error;
		}
		break;
	case VE_ST_UNAVAILABLE:
		if (cur_state == VE_ST_UNAVAILABLE) {
			ret = -EINVAL;
			goto error;
		}
		break;
	default:
		ret = -EINVAL;
		pdev_dbg(vedev->pdev, "ve_state: invalid state is specified\n");
		goto error1;
	}
	ret = vedev->arch_class->ve_state_transition(vedev, cur_state, value);

	if (ret) {
		pdev_dbg(vedev->pdev, "error on transition from %s to %s\n",
			ve_state_str[cur_state], ve_state_str[value]);
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
 * @brief cache_l3 show attribute
 *
 * @param[in] dev: Device pointer to the sysfs device
 * @param[in] attr: Device attribute
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t cache_l3_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%d\n",
			vedev->node->model_info.l3_cache_size);

	return len;
}
static DEVICE_ATTR_RO(cache_l3);

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
	struct ve_node *node = vedev->node;
	struct ve_hw_info *info = &node->hw_info;

	len = scnprintf(buf, PAGE_SIZE, "%016llx%08llx\n",
			info->chip_sn[0],
			info->chip_sn[1]);

	return len;
}
static DEVICE_ATTR_RO(chip_id);


#ifdef VE_DRV_DEBUG
/* for debug */
static ssize_t cond_intvec_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);
	struct ve3_archdep_data *archdep_data;
	archdep_data = vedev->node->ve_archdep_data;

	len = scnprintf(buf, PAGE_SIZE, "%016llx %016llx %016llx %016llx\n",
		archdep_data->cond.intvec[0], archdep_data->cond.intvec[1],
		archdep_data->cond.intvec[2], archdep_data->cond.intvec[3]);

	return len;
}
static DEVICE_ATTR_RO(cond_intvec);
#endif

/**
 * @brief sysfs attributes
 */
static struct attribute *sysfs_ve3_attrs[] = {
	&dev_attr_partitioning_mode.attr,
	&dev_attr_throttling_level.attr,
	&dev_attr_cache_l3.attr,
	&dev_attr_bar0_size.attr,
	&dev_attr_bar0_addr.attr,
	&dev_attr_bar4_addr.attr,
	&dev_attr_numa0_cores.attr,
	&dev_attr_numa1_cores.attr,
	&dev_attr_numa_mem_block_size.attr,
	&dev_attr_first_mem_node.attr,
	&dev_attr_ownership.attr,
	&dev_attr_ve_state.attr,
	&dev_attr_chip_id.attr,
#ifdef VE_DRV_DEBUG
	&dev_attr_cond_intvec.attr,
#endif
	NULL,
};

/**
 * @brief sysfs attribute group
 */
static struct attribute_group ve3_arch_attribute_group = {
	.attrs = sysfs_ve3_attrs
};

const struct attribute_group *ve_drv_ve3_attribute_groups[] = {
	&ve3_arch_attribute_group,
	&sensor_attribute_group,
	NULL,
};
