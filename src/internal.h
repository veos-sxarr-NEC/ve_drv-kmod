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
 * @file internal.h
 * @brief VE driver header for kernel module
 */

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/bitrev.h>
#include <linux/uidgid.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include "hw.h"
#include "ve_drv.h"

/* print macros */
#define pdev_trace(pdev) dev_dbg(&pdev->dev, "trace")
#define pdev_dbg(pdev, fmt, args...) dev_dbg(&pdev->dev, fmt, ## args)
#define pdev_err(pdev, fmt, args...) dev_err(&pdev->dev, fmt, ## args)
#define pdev_info(pdev, fmt, args...) dev_info(&pdev->dev, fmt, ## args)
#define pdev_warn(pdev, fmt, args...) dev_warn(&pdev->dev, fmt, ## args)

/**
 * @brief VE task state
 */
#define TASK_STATE_NEW		(0)
#define TASK_STATE_READY	(1)
#define TASK_STATE_DELETED	(2)
#define TASK_STATE_RELEASED	(3)
#define TASK_STATE_ASSIGNED	(4)

#define NR_VE_SENSOR		(38)

/**
 * @brief VE Core structure
 */
struct ve_core {
	unsigned int count;	/*!< Interrupt counter */
	int core_id;		/*!< VE Core ID */
	struct ve_node *node;	/*!< Link to VE node which contains this core */
	struct ve_task *task;	/*!< Link to VE task which is assigned to
				 * this core
				 */
	volatile uint64_t *exs;	/*!< EXSRAR target address
				 * (kernel virtual address)
				 */
};

/**
 * @brief KUID list for CR and VE memory mapping
 */
struct ve_kuid_list {
	kuid_t kuid;		/*<! KUID allowed to map the memory */
	struct list_head list;	/*<! Linked list of KUID */
};

/**
 * @brief VE Device information read from PCI configuration space
 */
struct ve_hw_info {
	uint8_t model;		/*!< Model */
	uint8_t type;		/*!< Product Type */
	uint8_t cpu_version;	/*!< CPU version */
	uint8_t version;	/*!< Hardware version */
	uint8_t num_of_core;	/*!< Number of cores on the model */
	uint32_t core_enables;	/*!< bitmap of enabled cores */
	uint64_t chip_sn[2];	/*!< chip serial 128bit */
	uint64_t board_sn[2];	/*!< board serial 128bit */
	uint16_t vmcfw_version;	/*!< VMC Firmware version */
	uint16_t memory_size;	/*!< Physical memory size in GB */
	uint16_t memory_clock;	/*!< Memory clock in MHz */
	uint16_t core_clock;	/*!< Core clock in MHz */
	uint16_t base_clock;	/*!< Base clock in MHz */
};

/**
 * @brief VE Device information defined by each model
 */
struct ve_model_info {
	uint8_t num_of_crpage;	/*!< Number of available CR pages */
	uint8_t pad0;		/*!< RFU */
	uint16_t num_of_pciatb;	/*!< Number of available PCIATBs */
	uint16_t pad1;		/*!< RFU */
	uint32_t i_cache_size;	/*!< Level 1 i-cache size in KB */
	uint32_t d_cache_size;	/*!< Level 1 d-cache size in KB */
	uint32_t l2_cache_size;	/*!< Level 2 cache size in KB */
	uint32_t l3_cache_size;	/*!< Level 3 cache size in KB */
};

/**
 * @brief VE Node structure
 */
struct ve_node {
	struct page_list hash_list_head[NR_PD_LIST];	/*!<
						 * list of pinned down pages
						 * by vp module
						 */
	struct mutex page_mutex[NR_PD_LIST];	/*!< mutex for page_list */
	struct ve_hw_info hw_info;	/*!< HW information obtained from
					 * PCI configuration space
					 */
	struct ve_model_info model_info;/*!< VE model information */
	struct mutex sysfs_mutex;	/*!< sysfs mutex lock */
	uint16_t sensor_rawdata[NR_VE_SENSOR];	/*!< VE sensor values */
	uint8_t ve_state;		/*!< VE HW state(defined in ve_drv.h) */
	uint8_t os_state;		/*!< VE OS state(defined in ve_drv.h) */
	uint8_t throttling_level;	/*!< Core throttling level (0 - 9) */
	uint8_t partitioning_mode;	/*!<
					 * Cache partitioning mode
					 * 00:OFF, 01:ON
					 */
	uint64_t online_jiffies;	/*!<
					 * jiffies when the state is changed
					 * to ONLINE.
					 */
	int core_fls;		/*!<
				 *   maximum physical core number in
				 *   core_enables
				 *   Ex: 1 if core_enables == 0x1
				 *       5 if core_enables == 0x10
				 */
	struct ve_core **core;	/*!< Array of VE cores */
	struct list_head task_head;	/*!< Linked list head of VE task */
	struct ve_kuid_list **cr_map;	/*!< Array of VE CR mapping info */
	struct mutex crmap_mutex;	/*!< BAR3 map list mutex */
	struct ve_kuid_list **mem_map;	/*!< Array of VE Memory mapping info */
	struct mutex pcimap_mutex;	/*!< BAR0 map list mutex */
	wait_queue_head_t waitq;	/*!< Interrupt wait queue */
	struct ve_wait_irq cond;	/*!< Interrupt wait condition */
	spinlock_t lock;	/*!<
				 * This lock must be aquire while
				 * changing the member of struct ve_core
				 * or accesing ve_task list
				 */
#ifdef VE_DRV_DEBUG
	uint8_t sysfs_crpage_entry;	/*!< CR Entry specified via sysfs */
	uint16_t sysfs_pciatb_entry;	/*!< PCIATB Entry specified via sysfs */
#endif
};

/**
 * @brief VE Device structure
 */
struct ve_dev {
	int minor;		/*!< VE device minor number */
	struct pci_dev *pdev;	/*!< PCI device structure */
	struct cdev cdev;	/*!< cdev structure */
	struct device *device;	/*!< device structure */
	uint64_t *vdma_addr;	/*!< DMA coherent address for EXSRAR
				 * (Kernel virtual address)
				 */
	dma_addr_t pdma_addr;	/*!< DMA coherent address for EXSRAR
				 * (Bus address)
				 */
	int bars;		/*!< Bit map of available BARs */
	void __iomem *bar[PCI_NUM_RESOURCES];	/*!< ioremap BAR addresses */
	uint64_t pbar[PCI_NUM_RESOURCES];	/*!< physical BAR addresses */
	size_t bar_size[PCI_NUM_RESOURCES];	/*!< BAR sizes */
	struct address_space *dev_mapping;	/*!< mmap address space */
	int msix_nvecs;		/*!< Number of MSI-X interrupt vectors */
	struct msix_entry *msix_entries;	/*!< MSI-X entries */
	const struct firmware *firmware;	/*!< Firmware loading address */
	struct ve_node *node;	/*!< VE node structure */
	struct pci_saved_state *saved_state; /*!< PCI config data for restore */
};

/**
 * @brief VE Task structure
 * @brief This structure will be created per file structure.
 *        Which means one ve_task structure is created by each open().
 */
struct ve_task {
	struct ve_dev *vedev;	/*!< VE device structure */
	wait_queue_head_t waitq;	/*!< Wait queue of VE task */
	wait_queue_head_t waitq_dead;	/*!< Wait queue of VE task for delete */
	int wait_cond;		/*!< Wait condition value */
	int wait_cond_dead;	/*!< Wait condition value for delete */
	struct pid *pid;	/*!< PID */
	struct mm_struct *mm;	/*!< mm_struct of task */
	struct list_head list;	/*!< VE task list */
	int state;		/*!< TASK_STATE_NEW, TASK_STATE_READY, ...  */
	bool mmap;		/*!< Any memory mapping(true) or not(false) */
	uint64_t exs;		/*!< EXS value */
};

/* main.c */
int ve_firmware_update(struct ve_dev *vedev);
int ve_chip_reset_sbr(struct ve_dev *vedev, uint64_t sbr);
int ve_init_exsrar(struct ve_dev *vedev);

/* device file operations (fops.c) */
int ve_drv_open(struct inode *ino, struct file *filp);
int ve_drv_flush(struct file *filp, fl_owner_t id);
int ve_drv_release(struct inode *ino, struct file *filp);
long ve_drv_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
int print_task_info(struct ve_dev *vedev, char *buf, int released);
int print_core_info(struct ve_node *node, char *buf);
int ve_drv_del_all_task(struct ve_dev *vedev);
void ve_drv_unassign_cr_all(struct ve_dev *vedev);
void ve_drv_unassign_vemem_all(struct ve_dev *vedev);

/* device file mmap operation (mmap.c) */
int ve_drv_mmap(struct file *filp, struct vm_area_struct *vma);
int ve_unmap_mapping(struct ve_dev *vedev, struct ve_unmap *usr);

/* sysfs.c */
int ve_drv_init_sysfs(struct ve_dev *vedev);
void ve_drv_fini_sysfs(struct ve_dev *vedev);

/* firmware.c */
int ve_set_lnkctl2_target_speed(struct pci_dev *pdev, u8 link_speed);
int ve_load_gen3_firmware(struct ve_dev *vedev);

/* fpga.c */
int ve_init_fpga(struct ve_dev *vedev);

/**
 * @brief Write 64bit value to MMIO address
 *
 * @param[in] to: Target kernel virtual address
 * @param val: 64bit value to be stored
 */
static inline void ve_mmio_write64(void *to, uint64_t val)
{
	memcpy_toio(to, &val, 8);
	/* in case of other arch than x86 */
	wmb();
}

static inline void ve_bar2_write64_delay(struct ve_dev *vedev, off_t offset,
				   uint64_t val, int delay)
{
	pdev_dbg(vedev->pdev, "write: offset = 0x%016llx, val = %016llx\n",
			(uint64_t)offset, val);
	ve_mmio_write64(vedev->bar[2] + offset, val);
	mdelay(delay);
}

/**
 * @brief Write 64bit value to BAR2 space
 *
 * @param[in] vedev: VE device structure
 * @param offset: Offset from top of BAR2
 * @param val: 64bit value to be stored
 */
static inline void ve_bar2_write64(struct ve_dev *vedev, off_t offset,
				   uint64_t val)
{
	ve_bar2_write64_delay(vedev, offset, val, 0);
}

/**
 * @brief Write 64bit value to BAR2 space 20 times to avoid PCIe IP bug
 *
 * @param[in] vedev: VE device structure
 * @param offset: Offset from top of BAR2
 * @param val: 64bit value to be stored
 */
static inline void ve_bar2_write64_20(struct ve_dev *vedev, off_t offset,
				   uint64_t val)
{
	int i;

	for (i = 0; i < 20; i++)
		ve_bar2_write64(vedev, offset, val);
}

/**
 * @brief Read 64bit value from MMIO address
 *
 * @param[in] from: Target kernel virtual address
 * @param[out] val: Readed 64bit value will be stored
 */
static inline void ve_mmio_read64(void *from, uint64_t *val)
{
	/* in case of other arch than x86 */
	rmb();
	memcpy_fromio(val, from, 8);
}

/**
 * @brief Read 64bit value from BAR2 space
 *
 * @param[in] vedev: VE device structure
 * @param offset: Offset from top of BAR2
 * @param[out] val: Readed 64bit value will be stored
 */
static inline void ve_bar2_read64(struct ve_dev *vedev, off_t offset,
				  uint64_t *val)
{
	ve_mmio_read64(vedev->bar[2] + offset, val);
}

/**
 * @brief Sync and read 64bit value from BAR2 space
 *
 * @param[in] vedev: VE device structure
 * @param offset: Offset from top of BAR2
 * @param[out] val: Readed 64bit value will be stored
 */
static inline void ve_bar2_read64_sync(struct ve_dev *vedev, off_t offset,
				  uint64_t *val)
{
	/* Sync in VE before read */
	ve_bar2_write64(vedev, PCI_BAR2_SCR_OFFSET + CREG_SYNC_OFFSET, 0);

	ve_bar2_read64(vedev, offset, val);
}

/**
 * @brief Return reversed bit ordering value
 *
 * @param value: input
 *
 * @return reversed bit ordering value
 */
static inline uint64_t ve_bitrev64(uint64_t value)
{
	return ((uint64_t)bitrev32(value & 0xffffffffULL) << 32)
		| (uint64_t)bitrev32(value >> 32);
}

extern int exsrar_poll_timeout_msec;
extern int exsrar_poll_delay_nsec;
extern int hw_intr_test_param;

#define SENSOR_VALUE_SHOW(SENSOR, DECODER)			\
static ssize_t sensor_##SENSOR##_show(				\
		struct device *dev,				\
		struct device_attribute *attr,			\
		char *buf)					\
{								\
	ssize_t len;						\
	struct ve_dev *vedev = dev_get_drvdata(dev);		\
	struct ve_node *node = vedev->node;			\
	uint16_t sensor_val;					\
	int64_t print_val;					\
								\
	pdev_trace(vedev->pdev);				\
								\
	if (node->ve_state != VE_ST_ONLINE)			\
		return -EIO;					\
								\
	mutex_lock(&node->sysfs_mutex);				\
	sensor_val = node->sensor_rawdata[SENSOR];		\
	if (sensor_val == 0xFFFF) {				\
		len = -EAGAIN;					\
		goto err;					\
	}							\
	print_val = DECODER(sensor_val);			\
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
	if (node->ve_state != VE_ST_ONLINE)		\
		return -EIO;				\
							\
	if (kstrtoul(buf, 0, &sensor_val) < 0)		\
		return -EINVAL;				\
							\
	mutex_lock(&node->sysfs_mutex);			\
	node->sensor_rawdata[SENSOR] =			\
			(uint16_t)sensor_val;		\
	mutex_unlock(&node->sysfs_mutex);		\
							\
	return count;					\
}

#define SENSOR_DEVICE_ATTR(SENSOR) DEVICE_ATTR_RW(sensor_##SENSOR)
