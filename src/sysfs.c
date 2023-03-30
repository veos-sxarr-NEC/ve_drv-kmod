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
#include <linux/user_namespace.h>
#include <linux/cred.h>

#include "ve_drv.h"
#include "decoder.h"
#include "internal.h"


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
 * @brief ve_arch_class show attribute
 *
 * @param[in] dev: device structure
 * @param[in] attr: device attribute structure
 * @param[out] buf: Write buffer
 *
 * @return number of characters printed
 */
static ssize_t ve_arch_class_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	mutex_lock(&vedev->node->sysfs_mutex);
	len = scnprintf(buf, PAGE_SIZE, "%s\n", vedev->arch_class->name);
	mutex_unlock(&vedev->node->sysfs_mutex);

	return len;
}
static DEVICE_ATTR_RO(ve_arch_class);


void ve_init_intr_count(struct ve_dev *vedev)
{
	struct ve_node *node = vedev->node;
	int noc = vedev->node->core_fls;
	int core_id;

	/* Init each cores */
	for (core_id = 0; core_id < noc; core_id++)
		node->core[core_id]->count =  0;
}

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
			vedev->node->hw_info.model_type.model);

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
			vedev->node->hw_info.model_type.type);

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

	/* TODO: update the format here. */
	len = scnprintf(buf, PAGE_SIZE, "0x%06llx\n",
			vedev->node->hw_info.core_enables);

	return len;
}
static DEVICE_ATTR_RO(cores_enable);

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
			vedev->node->model_info.llc_cache_size);

	return len;
}
static DEVICE_ATTR_RO(cache_llc);

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
	struct ve_node *node = vedev->node;
	struct ve_hw_info *info = &node->hw_info;

	len = scnprintf(buf, PAGE_SIZE, "%d\n",	info->vmcfw_version);

	return len;
}
static DEVICE_ATTR_RO(fw_version);


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
	struct ve_node *node = vedev->node;
	struct ve_hw_info *info = &node->hw_info;

	len = scnprintf(buf, PAGE_SIZE, "%016llx%016llx\n",
			info->board_sn[0],
			info->board_sn[1]);

	return len;
}
static DEVICE_ATTR_RO(serial);



#ifdef VE_DRV_DEBUG
/* for debug */
static ssize_t cond_intvec_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	ssize_t len;
	struct ve_dev *vedev = dev_get_drvdata(dev);

	len = scnprintf(buf, PAGE_SIZE, "%016llx %016llx %016llx %016llx\n",
		vedev->node->cond.intvec[0], vedev->node->cond.intvec[1],
		vedev->node->cond.intvec[2], vedev->node->cond.intvec[3]);

	return len;
}
static DEVICE_ATTR_RO(cond_intvec);

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
	&dev_attr_ve_arch_class.attr,
	&dev_attr_os_state.attr,
	&dev_attr_num_of_core.attr,
	&dev_attr_memory_size.attr,
	&dev_attr_model.attr,
	&dev_attr_type.attr,
	&dev_attr_cores_enable.attr,
	&dev_attr_clock_memory.attr,
	&dev_attr_clock_chip.attr,
	&dev_attr_clock_base.attr,
	&dev_attr_cache_l1i.attr,
	&dev_attr_cache_l1d.attr,
	&dev_attr_cache_l2.attr,
	&dev_attr_cache_llc.attr,
	&dev_attr_jiffies.attr,
	&dev_attr_task_id_all.attr,
	&dev_attr_task_id_dead.attr,
	&dev_attr_abi_version.attr,
	&dev_attr_fw_version.attr,
	&dev_attr_serial.attr,
#ifdef VE_DRV_DEBUG
	&dev_attr_core_status.attr,
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

	/* create sysfs architecture-dependent files */
	err = sysfs_create_groups(&vedev->device->kobj,
			vedev->arch_class->ve_arch_sysfs_attr_groups);
	if (err) {
		pdev_err(vedev->pdev,
			"sysfs_create_groups failed (%d)\n", err);
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
	sysfs_remove_groups(&vedev->device->kobj,
			vedev->arch_class->ve_arch_sysfs_attr_groups);
}
