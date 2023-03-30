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
 * @file internal.h
 * @brief VE driver header for kernel module
 */
#ifndef VE_DRV_INTERNAL_H_INCLUDE_
#define VE_DRV_INTERNAL_H_INCLUDE_
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/bitrev.h>
#include <linux/uidgid.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/cdev.h>
#include <linux/pid.h>
#include <linux/kref.h>
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
struct ve_model_type {
	uint8_t model;		/*!< Model */
	uint8_t type;		/*!< Product Type */
	uint8_t cpu_version;	/*!< CPU version */
	uint8_t version;	/*!< Hardware version */
};
struct ve_hw_info {
	struct ve_model_type model_type;
	uint8_t num_of_core;	/*!< Number of cores on the model */
	uint64_t core_enables;	/*!< Bitmap of enabled cores */

	uint16_t vmcfw_version;	/*!< VMC Firmware version */
	uint16_t memory_size;	/*!< Physical memory size in GB */
	uint16_t memory_clock;	/*!< Memory clock in MHz */
	uint16_t core_clock;	/*!< Core clock in MHz */
	uint16_t base_clock;	/*!< Base clock in MHz */
	uint64_t chip_sn[2];	/*!< chip serial 128bit */
	uint64_t board_sn[2];	/*!< board serial 128bit */
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
	uint32_t llc_cache_size;/*!< Level level cache size in KB */
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
	struct ve_hw_info hw_info;	/*!< Hw information obtained from
					 * PCI configuration space
					 */
	struct ve_model_info model_info;/*!< VE model information */

	struct mutex sysfs_mutex;	/*!< sysfs mutex lock */
	uint32_t *sensor_rawdata;	/*!< VE sensor values */
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
	struct ve_wait_irq *cond;	/*!< Interrupt wait condition */
	spinlock_t lock;	/*!<
				 * This lock must be aquire while
				 * changing the member of struct ve_core
				 * or accesing ve_task list
				 */
#ifdef VE_DRV_DEBUG
	uint8_t sysfs_crpage_entry;	/*!< CR Entry specified via sysfs */
	uint16_t sysfs_pciatb_entry;	/*!< PCIATB Entry specified via sysfs */
#endif
	void *ve_archdep_data;

	struct pid  *ownership;		/*!< VE ownership */
	struct pid  *notifyfaulter;	/*!< VE notiyfault requester */
};

struct ve_arch_class;

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
	struct ve_node *node;	/*!< VE node structure */
	struct pci_saved_state *saved_state; /*!< PCI config data for restore */

	const struct ve_arch_class *arch_class;/*!< VE architecture class */

	wait_queue_head_t release_q;	/*!<VE remove wait queue */
	struct kref   ve_dev_ref;       /* ve dev reference counter  */
	struct kref   final_ref;        /* ve dev final reference counter  */
	bool remove_processing;  /* ve_pci_remove is starting */

};

/**
 * @brief VE class
 */
struct ve_arch_class {
	char name[VEDRV_ARCH_CLASS_NAME_MAX];	/*!< architecture name */
	int expected_bar_mask;	/*!< expected BARs */
	size_t max_core_num;	/*!< maximum VE core number */
	size_t num_sensors;	/*!< the number of sensors on VE */
	int (*init_early)(struct ve_dev *);	/*!< initializer before mapping
						 * PCI resources
						 */
	void (*fini_late)(struct ve_dev *);	/*!< finalizer after unmapping
						 * PCI resources
						 */
	int (*fill_hw_info)(struct ve_dev *);/*!< fill HW information */
	void (*fill_model_info)(const struct ve_dev *,
			struct ve_model_info *);	/*!<
						* fill model information
						*/

	int (*init_node)(struct ve_dev *, struct ve_node *);/*!<
						* arch-dependent initializer
						* on initialization of VE node
						*/
	void (*fini_node)(struct ve_dev *, struct ve_node *);/*!<
						* arch-dependent finalizer
						* on finalization of VE node
						*/
	int (*init_post_node)(struct ve_dev *); /*!<
						 * arch-dependent initializer
						 * after initialization of VE
						 * node structure
						 */
	int (*init_post_core)(struct ve_dev *); /*!<
						 * arch-dependent initializer
						 * after initialization of VE
						 * core structure
						 */
	int (*init_hw_check)(struct ve_dev *); /*!<
						 * arch-dependent initializer
						 * HW init check
						 * core structure
						 */

	
	void *(*exsrar_addr)(const struct ve_dev *, int);
	uint64_t (*get_exs)(struct ve_dev *, int);/*!< execution status */

	void (*request_stop_all)(struct ve_dev *);
	int (*check_stopped)(struct ve_dev *);

	int (*ve_arch_ioctl_check_permission)(const struct ve_dev *,
					unsigned int, int *);
	long (*ve_arch_ioctl)(struct file *filp, struct ve_dev *, unsigned int, unsigned long,
				int *);

	irqreturn_t (*ve_arch_intr)(struct ve_dev *, int);/*!<
						 * interrupt handler
						 */

	size_t ve_wait_irq_size;/*!< size of arch-dependent interrupt vector */
	uint64_t ve_irq_type;
	int (*ve_arch_wait_intr)(struct ve_dev *, struct ve_wait_irq *,
				struct timespec *);
	uint64_t (*core_intr_undelivered)(const struct ve_dev *, int);/*!<
						* check an undelivered core
						* interrupt
						*/

	int (*ve_arch_map_range_offset)(const struct ve_dev *, off_t, size_t,
				int *, unsigned long *);
	int (*permit_to_map)(const struct ve_dev *, int, unsigned long);

	int (*ve_state_transition)(struct ve_dev *, unsigned long,
					unsigned long);

	void (*ve_arch_release)(struct ve_dev *, struct ve_task *);
	const struct attribute_group **ve_arch_sysfs_attr_groups;

	size_t ve_archdep_size;/*!< the size of architecture-dependent data */
	/* TODO */
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
	uint64_t last_exs;	/*!< EXS value */
	bool  ownership;	/*!< VE ownership */
};

/* main.c */
void ve_drv_disable_irqs(struct ve_dev *);
int ve_drv_enable_irqs(struct ve_dev *);
int ve_init_exsrar(struct ve_dev *vedev);
int ve_check_pci_link(struct pci_dev *pdev);
irqreturn_t ve_drv_generic_core_intr(struct ve_dev *, int,
				void (*)(struct ve_dev *, int));
irqreturn_t ve_drv_generic_node_intr(struct ve_dev *, int,
				void (*)(struct ve_dev *, int));

int ve1_prepare_for_link_down(struct ve_dev *vedev, u16 *aer_cap,int sbr);
int ve_prepare_for_chip_reset(struct ve_dev *vedev, u16 *aer_cap,int disable_irq, int sbr);
int ve_drv_set_lnkctl2_target_speed(struct pci_dev *pdev, u8 link_speed);
int ve_recover_from_link_down(struct ve_dev *vedev, u16 *aer_cap,int fw_update, int sbr);


/* main_ve3.c: arch-independent code refers to the function. */
const struct ve_arch_class *ve_arch_probe_ve3(struct ve_dev *vedev);

/* main_ve1.c, arch-independent code refers to the function. */
const struct ve_arch_class *ve_arch_probe_ve1(struct ve_dev *vedev);

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

int ve_drv_generic_arch_wait_intr(struct ve_dev *,
	struct ve_wait_irq *, struct timespec *,
	bool (*)(const struct ve_wait_irq *, const struct ve_wait_irq *),
	void (*)(struct ve_dev *, struct ve_wait_irq *, struct ve_wait_irq *));

void ve_drv_device_put(struct ve_dev *vedev);
void ve_drv_device_get(struct ve_dev *vedev);
void ve_drv_final_put(struct ve_dev *vedev);
void ve_drv_final_get(struct ve_dev *vedev);
int ve_drv_unassign_task_from_core(struct ve_dev *vedev, pid_t tid_ns, int check_exsreg);

/* device file mmap operation (mmap.c) */
int ve_drv_check_pciatb_entry_permit(const struct ve_dev *vedev, int entry);
int ve_drv_check_cr_entry_permit(const struct ve_dev *vedev, int entry);
int ve_drv_mmap(struct file *filp, struct vm_area_struct *vma);
int ve_unmap_mapping(struct ve_dev *vedev, struct ve_unmap *usr);

/* sysfs.c */
int ve_drv_init_sysfs(struct ve_dev *vedev);
void ve_drv_fini_sysfs(struct ve_dev *vedev);
void ve_init_intr_count(struct ve_dev *vedev);

/* ve_config_regs.c */
int ve_drv_read_ve_config_regs(const struct ve_dev *, size_t, u32 *);
void ve_drv_set_model_type(struct ve_model_type *, u32);
int ve_drv_read_model_type(const struct ve_dev *, struct ve_model_type *);

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
extern int clear_intvec_pci_access_exception;
extern int panic_on_pci_access_exception;
extern int wait_after_vereset_sec;
#if defined(_VE_ARCH_VE3_)
#include "internal_ve3.h"
#elif defined(_VE_ARCH_VE1_)
#include "internal_ve1.h"
#else
/*
 * Since this header may be included from architecture independent source
 * files, it is not error if no architecture is specified.
 */
#endif

#endif
