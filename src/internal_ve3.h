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
 * @file internal_ve3.h
 * @brief VE3 specific driver internal header for kernel module
 */
#ifndef VE_DRV_INTERNAL_H_INCLUDE_
# error "Never include \"internal_ve3.h\" directly; include \"internal.h\" instead."
#endif
#ifndef VE_DRV_INTERNAL_VE3_H_INCLUDE_
#define VE_DRV_INTERNAL_VE3_H_INCLUDE_


struct ve3_archdep_data {
	struct ve3_wait_irq cond;
};

/* fops_ve3.c */
int ve_drv_ve3_wait_intr(struct ve_dev *, struct ve_wait_irq *,
				struct timespec *);
uint64_t ve_drv_ve3_core_intr_undelivered(const struct ve_dev *, int);

int ve_drv_ve3_ownership(struct file *filp, int cmd);
int ve_drv_ve3_notify_fault(struct file *filp);

/* mmap_ve3.c */
int ve_drv_ve3_map_range_offset(const struct ve_dev *, off_t, size_t,
			int *, unsigned long *);
int ve_drv_ve3_permit_to_map(const struct ve_dev *, int, unsigned long);

int ve_drv_ve3_reset(struct ve_dev *vedev, uint64_t);

/* sysfs_ve3.c */
extern const struct attribute_group *ve_drv_ve3_attribute_groups[];

/* fops_ve3.c */
void  ve3_ve_release(struct ve_dev *, struct ve_task *task);
long ve_drv_ve3_arch_ioctl(struct file *filp, struct ve_dev *, unsigned int, unsigned long, int *);
int ve_drv_ve3_ioctl_check_permission(const struct ve_dev *, unsigned int,
					int *);
int ve_drv_ve3_get_exs_reg(struct file *filp,  uint64_t __user *user_exs);
int ve_drv_ve3_complete_memclear(struct ve_dev *vedev);
int ve_drv_ve3_clock_gating(struct ve_dev *vedev, int cmd);
int ve_drv_ve3_get_clock_gating_state(struct ve_dev *vedev,  uint64_t __user *user_state);
extern int wait_sec_after_sigkill_on_notify_fault;

#endif
