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
 * @file internal_ve1.h
 * @brief VE1 specific driver internal header for kernel module
 */
#ifndef VE_DRV_INTERNAL_H_INCLUDE_
# error "Never include \"internal_ve1.h\" directly; include \"internal.h\" instead."
#endif
#ifndef VE_DRV_INTERNAL_VE1_H_INCLUDE_
#define VE_DRV_INTERNAL_VE1_H_INCLUDE_

struct firmware;
struct ve1_archdep_data {
	struct ve1_wait_irq cond;
	const struct firmware *firmware;
};

/* firmware_ve1.c */
int ve_drv_ve1_set_lnkctl2_target_speed(struct pci_dev *pdev, u8 link_speed);
int ve_drv_ve1_load_gen3_firmware(struct ve_dev *vedev);

/* main_ve1.c */
int ve_drv_ve1_chip_reset_sbr(struct ve_dev *, uint64_t);
int ve_drv_ve1_firmware_update(struct ve_dev *);

/* fops_ve1.c */
int ve_drv_ve1_wait_intr(struct ve_dev *, struct ve_wait_irq *,
				struct timespec *);
uint64_t ve_drv_ve1_core_intr_undelivered(const struct ve_dev *, int);
int ve_drv_ve1_ioctl_check_permission(const struct ve_dev *, unsigned int,
					int *);
long ve_drv_ve1_arch_ioctl(struct file *filp, struct ve_dev *, unsigned int, unsigned long, int *);

/* mmap_ve1.c */
int ve_drv_ve1_map_range_offset(const struct ve_dev *vedev, off_t head,
			size_t size, int *bar, unsigned long *offset);
int ve_drv_ve1_permit_to_map(const struct ve_dev *, int, unsigned long);

/* sysfs_ve1.c */
extern const struct attribute_group *ve_drv_ve1_attribute_groups[];
#endif
