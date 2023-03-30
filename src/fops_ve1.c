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
 * @file fops_ve1.c
 * @brief VE1 specific part of VE driver file operations.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/cred.h>
#include <linux/poll.h>

#define _VE_ARCH_VE1_ (1)
#include "ve_drv.h"
#include "internal.h"
#include "mmio.h"

static bool ve1_check_wait_intr(const struct ve_wait_irq *c,
			const struct ve_wait_irq *i)
{
	const struct ve1_wait_irq *cond = (const struct ve1_wait_irq *)c;
	const struct ve1_wait_irq *irq = (const struct ve1_wait_irq *)i;
	bool rv;
	pr_debug(" wait for: lower = 0x%016llx, upper = 0x%016llx\n",
		irq->lower, irq->upper);
	pr_debug("delivered: lower = 0x%016llx, upper = 0x%016llx\n",
		cond->lower, cond->upper);
	rv = (cond->upper & irq->upper) || (cond->lower & irq->lower);
	pr_debug("return %s\n", rv ? "true" : "false");
	return rv;
}


static void ve1_intr_woken(struct ve_dev *vedev, struct ve_wait_irq *c,
			struct ve_wait_irq *i)
{
	unsigned long flags;
	uint64_t mask_val;
	struct ve1_wait_irq *cond = (struct ve1_wait_irq *)c;
	struct ve1_wait_irq *irq = (struct ve1_wait_irq *)i;
	pdev_trace(vedev->pdev);
	/*
	 * spinlock and save IRQs during manipulation of
	 * condition bits
	 */
	spin_lock_irqsave(&vedev->node->lock, flags);

	/* set caused bits */
	irq->upper &= cond->upper;
	irq->lower &= cond->lower;
	/* drop caused bits from condition */
	cond->upper &= ~(irq->upper);
	cond->lower &= ~(irq->lower);

	spin_unlock_irqrestore(&vedev->node->lock, flags);

	pdev_dbg(vedev->pdev, "irq->upper = 0x%llx\n", irq->upper);
	pdev_dbg(vedev->pdev, "irq->lower = 0x%llx\n", irq->lower);
	pdev_dbg(vedev->pdev, "cond->upper = 0x%llx\n", cond->upper);
	pdev_dbg(vedev->pdev, "cond->lower = 0x%llx\n", cond->lower);

	/* following procedure is requrired only for DMA interrupt */
	if (!(irq->lower & DMA_INTERRUPT_VECTOR_MASK))
		return;

	/*
	 * Somewhat confusingly, "Interrupt Vector register" is
	 * reversed order bit of MSI-X vector.
	 * So we make reversed order bit-mask here.
	 * See HW spec for more detail.
	 */
	mask_val = ve_bitrev64(irq->lower);
	pdev_dbg(vedev->pdev, "mask_val = 0x%llx\n", mask_val);

	/* Clear interrupt mask register by writing mask value */
	ve_bar2_write64(vedev,
			VEDRV_VE1_PCI_BAR2_SCR_OFFSET + CREG_INTERRUPT_VECTOR,
			mask_val);

	return;
}


int ve_drv_ve1_wait_intr(struct ve_dev *vedev, struct ve_wait_irq *irq,
			struct timespec *timeout)
{
	return ve_drv_generic_arch_wait_intr(vedev, irq, timeout,
				ve1_check_wait_intr, ve1_intr_woken);
}

/**
 * @brief check an undelivered core interrupt
 *
 * @param vedev: VE device
 * @param core_id: core ID
 *
 * @return zero if no undelivered interrupts remain;
 *         non-zero if an interrupt has not been arrived.
 */
uint64_t ve_drv_ve1_core_intr_undelivered(const struct ve_dev *vedev, int core_id)
{
	uint64_t intvec;
	ve_bar2_read64_sync(vedev, VEDRV_VE1_PCI_BAR2_SCR_OFFSET +
		CREG_INTERRUPT_VECTOR, &intvec);
	return intvec & ((uint64_t)0x8000000000000000 >> core_id);
}


int ve_drv_ve1_ioctl_check_permission(const struct ve_dev *vedev,
				unsigned int cmd, int *handled)
{
	switch (cmd) {
	case VEDRV_CMD_UNASSIGN_TASK:
	case VEDRV_CMD_VE1_UPDATE_FIRMWARE:
	case VEDRV_CMD_VE_VE_RESET:
		*handled = 1;
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		else
			return 0;
	default:
		*handled = 0;
		return 0;
	}
}

int ve_drv_compat_ve1_wait_intr(struct ve_dev *vedev,
				struct ve1_compat_wait_irq_arg *usr)
{
	int ret, retval;
	struct ve1_compat_wait_irq_arg krn;
	struct timespec timeout;
	struct ve1_wait_irq irq;

	pdev_trace(vedev->pdev);
	ret = copy_from_user(&krn, usr, sizeof(struct ve1_compat_wait_irq_arg));
	if (ret) {
		retval = -EFAULT;
		goto err;
	}
	ret = copy_from_user(&timeout, krn.timeout, sizeof(struct timespec));
	if (ret) {
		retval = -EFAULT;
		goto err;
	}
	irq.ve_wait_irq_type = VEDRV_IRQ_TYPE_VE1;
	irq.upper = krn.bits.upper;
	irq.lower = krn.bits.lower;
	retval = ve_drv_ve1_wait_intr(vedev, (struct ve_wait_irq *)&irq,
					&timeout);
	if (retval < 0)
		goto err;
	krn.bits.upper = irq.upper;
	krn.bits.lower = irq.lower;
	ret = copy_to_user(usr, &krn, sizeof(struct ve1_compat_wait_irq_arg));
	if (ret)
		retval = -EFAULT;
err:
	return retval;
}

long ve_drv_ve1_arch_ioctl(struct file *filp, struct ve_dev *vedev, unsigned int cmd,
			   unsigned long arg, int *handled)
{
	long ret;
	switch (cmd) {
	case VEDRV_CMD_UNASSIGN_TASK:
		*handled = 1;
                ret = ve_drv_unassign_task_from_core(vedev, (pid_t)arg, 0);
		break;
	case VEDRV_CMD_VE1_UPDATE_FIRMWARE:
		*handled = 1;
		ret = ve_drv_ve1_firmware_update(vedev);
		break;
	case VEDRV_CMD_VE_VE_RESET:
		*handled = 1;
		ret = ve_drv_ve1_chip_reset_sbr(vedev, (uint64_t)arg);
		break;
	case VEDRV_CMD_COMPAT_VE1_WAIT_INTR:
		*handled = 1;
		ret = ve_drv_compat_ve1_wait_intr(vedev,
				(struct ve1_compat_wait_irq_arg __user *)arg);
		break;
	default:
		*handled = 0;
		ret = -1;
	}
	return ret;
}
