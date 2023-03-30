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
 * @file fops_ve3.c
 * @brief VE3 specific part of VE driver file operations.
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/jiffies.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/poll.h>
#include <linux/pid.h>
#include <linux/sched/signal.h>

#define _VE_ARCH_VE3_ (1)
#include "ve_drv.h"
#include "hw.h"
#include "internal.h"
#include "mmio.h"

static bool ve3_check_wait_intr(const struct ve_wait_irq *c,
			const struct ve_wait_irq *i)
{
	const struct ve3_wait_irq *cond = (const struct ve3_wait_irq *)c;
	const struct ve3_wait_irq *irq = (const struct ve3_wait_irq *)i;
	bool rv;
	pr_debug(" wait for: {0x%016llx, 0x%016llx, 0x%016llx, 0x%016llx}\n",
		irq->intvec[0], irq->intvec[1],
		irq->intvec[2], irq->intvec[3]);
	pr_debug("delivered: {0x%016llx, 0x%016llx, 0x%016llx, 0x%016llx}\n",
		cond->intvec[0], cond->intvec[1],
		cond->intvec[2], cond->intvec[3]);
	rv = (cond->intvec[0] & irq->intvec[0]) ||
		(cond->intvec[1] & irq->intvec[1]) ||
		(cond->intvec[2] & irq->intvec[2]) ||
		(cond->intvec[3] & irq->intvec[3]);
	pr_debug("return %s\n", rv ? "true" : "false");
	return rv;
}


static void ve3_intr_woken(struct ve_dev *vedev, struct ve_wait_irq *c,
			struct ve_wait_irq *i)
{
	struct ve3_wait_irq *cond = (struct ve3_wait_irq *)c;
	struct ve3_wait_irq *irq = (struct ve3_wait_irq *)i;
	int j;
	uint64_t mask_val1, mask_val2;
	unsigned long flags;
	/*
	 * spinlock and save IRQs during manipulation of
	 * condition bits
	 */
	spin_lock_irqsave(&vedev->node->lock, flags);

	for (j = 0; j < 4; ++j) {
		/* set caused bits */
		irq->intvec[j] &= cond->intvec[j];
		/* drop caused bits from condition */
		cond->intvec[j] &= ~(irq->intvec[j]);
	}

	spin_unlock_irqrestore(&vedev->node->lock, flags);

	pdev_dbg(vedev->pdev, "irq->intvec[0] = 0x%llx\n",
		irq->intvec[0]);
	pdev_dbg(vedev->pdev, "irq->intvec[1] = 0x%llx\n",
		irq->intvec[1]);
	pdev_dbg(vedev->pdev, "irq->intvec[2] = 0x%llx\n",
		irq->intvec[2]);
	pdev_dbg(vedev->pdev, "irq->intvec[3] = 0x%llx\n",
		irq->intvec[3]);
	pdev_dbg(vedev->pdev, "cond->intvec[0] = 0x%llx\n",
		cond->intvec[0]);
	pdev_dbg(vedev->pdev, "cond->intvec[1] = 0x%llx\n",
		cond->intvec[1]);
	pdev_dbg(vedev->pdev, "cond->intvec[2] = 0x%llx\n",
		cond->intvec[2]);
	pdev_dbg(vedev->pdev, "cond->intvec[3] = 0x%llx\n",
		cond->intvec[3]);

	/* following procedure is requrired only for DMA interrupt */
	if (!is_dma_interrupt(irq))
		return;

	/*
	 * Somewhat confusingly, "Interrupt Vector register" is
	 * reversed order bit of MSI-X vector.
	 * So we make reversed order bit-mask here.
	 */
	/* mask_val1 for PDMA */
	mask_val1 = ve_bitrev64(irq->intvec[1]);
	pdev_dbg(vedev->pdev, "mask_val1 = 0x%llx\n", mask_val1);
	/* mask_val2 for UDMA */
	mask_val2 = ve_bitrev64(irq->intvec[2]);
	pdev_dbg(vedev->pdev, "mask_val2 = 0x%llx\n", mask_val2);

	/* Clear interrupt mask register by writing mask value */
	ve_bar4_write64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET +
			CREG_INTERRUPT_VECTOR1, mask_val1);
	ve_bar4_write64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET +
			CREG_INTERRUPT_VECTOR2, mask_val2);

	return;
}


int ve_drv_ve3_wait_intr(struct ve_dev *vedev, struct ve_wait_irq *irq,
			struct timespec *timeout)
{
	return ve_drv_generic_arch_wait_intr(vedev, irq, timeout,
				ve3_check_wait_intr, ve3_intr_woken);
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
uint64_t ve_drv_ve3_core_intr_undelivered(const struct ve_dev *vedev, int core_id)
{
	uint64_t intvec0;
	ve_bar4_read64_sync(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET +
		CREG_INTERRUPT_VECTOR0, &intvec0);
	return intvec0 & ((uint64_t)0x8000000000000000UL >> core_id);
}

/**
 * @brief release ownership if owner
 *
 * @param vedev: VE device
 *
 */

void  ve3_ve_release(struct ve_dev *vedev, struct ve_task *task)
{
	struct pid *pid;
	pid = get_task_pid(current, PIDTYPE_PID);
	if (pid == NULL){
		pdev_dbg( vedev->pdev,
			  "ve3_ve_release:get_task_pid failed\n");
		return;
	}
	if( vedev->node->notifyfaulter == pid ){
		pdev_dbg( vedev->pdev,
			  "ve3_ve_release:notify_fautler self\n");
		vedev->node->notifyfaulter = NULL;
		return;
	}
	if( task->ownership  &&  vedev->node->ownership != NULL ){

		pdev_dbg( vedev->pdev,
			  "ve3_ve_release:ownership at release %d %d\n",
			  pid_vnr(pid),pid_vnr(vedev->node->ownership));

		if ( vedev->node->notifyfaulter == NULL ){
			vedev->node->ownership = NULL;
			task->ownership = false;
			/*  notify to waiter */
			sysfs_notify(&vedev->device->kobj, NULL, "ownership");
			pdev_info( vedev->pdev,
				   "release: release ownership (%d)\n", pid_vnr(pid));
		}else{
			vedev->node->ownership = vedev->node->notifyfaulter;
				pdev_info( vedev->pdev,
					   "release:  release ownership (%d) and set to (%d)\n",
					   pid_vnr(pid),
					   pid_vnr(vedev->node->notifyfaulter)
				);
			/*
			 * Clear the notifier
			 */
			vedev->node->notifyfaulter = NULL;
			task->ownership = true;
		}

	}

}



int ve_drv_ve3_ioctl_check_permission(const struct ve_dev *vedev,
				unsigned int cmd, int *handled)
{
	switch (cmd) {
        case VEDRV_CMD_GET_EXS_REG:
		*handled = 1;
		return 0;
	case VEDRV_CMD_UNASSIGN_TASK:
	case VEDRV_CMD_OWNERSHIP:
	case VEDRV_CMD_VE_VE_RESET:
	case VEDRV_CMD_NOTIFY_FAULT:
	case VEDRV_CMD_COMPLETE_MEMCLEAR:
	case VEDRV_CMD_HANDLE_CLOCK_GATING:
	case VEDRV_CMD_GET_CLOCK_GATING_STATE:
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

long ve_drv_ve3_arch_ioctl(struct file *filp, struct ve_dev *vedev,
			   unsigned int cmd,
			   unsigned long arg, int *handled)
{
	long ret;
	switch (cmd) {
	case VEDRV_CMD_UNASSIGN_TASK:
		*handled = 1;
                ret = ve_drv_unassign_task_from_core(vedev, (pid_t)arg, 1);
		break;
	case VEDRV_CMD_OWNERSHIP:
		*handled = 1;
		ret = ve_drv_ve3_ownership(filp, (int)arg);
		break;
	case VEDRV_CMD_NOTIFY_FAULT:
		*handled = 1;
		ret = ve_drv_ve3_notify_fault(filp);
		break;
	case VEDRV_CMD_VE_VE_RESET:
		*handled = 1;
		ret = ve_drv_ve3_reset(vedev, (uint64_t)arg);
		break;
        case VEDRV_CMD_GET_EXS_REG:
                *handled = 1;
                ret = ve_drv_ve3_get_exs_reg(filp, (uint64_t __user *)arg);
                break;
	case VEDRV_CMD_COMPLETE_MEMCLEAR:
                *handled = 1;
                ret = ve_drv_ve3_complete_memclear(vedev);
                break;
	case VEDRV_CMD_HANDLE_CLOCK_GATING:
                *handled = 1;
                ret = ve_drv_ve3_clock_gating(vedev, (int)arg );
                break;
	case VEDRV_CMD_GET_CLOCK_GATING_STATE:
                *handled = 1;
		ret = ve_drv_ve3_get_clock_gating_state(vedev,(uint64_t __user *)arg);
                break;
	default:
		*handled = 0;
		ret = -1;
	}
	return ret;
}

int ve_drv_ve3_ownership(struct file *filp, int cmd)
{
	struct ve_task *task;
	struct ve_dev *vedev;

	unsigned long flags;
	int ret;
	struct pid *pid;


	task = filp->private_data;
	vedev = task->vedev;

	pdev_dbg(vedev->pdev, "ownership in\n");
	/*
	 * 1: request
	 * 0: release
	 */
	if (cmd !=0 && cmd !=1) {
		pdev_err(vedev->pdev, "ownership: cmd is invalid\n");
		ret = -EINVAL;
		return ret;
	}
	spin_lock_irqsave(&vedev->node->lock, flags);

	pdev_dbg( vedev->pdev, "ownership: called %d\n", (int )cmd);

	pid = get_task_pid(current, PIDTYPE_PID);
	if (pid == NULL){
		pdev_err(vedev->pdev,
			 "ownership: get_task_pid error\n");
		ret = -ESRCH;
		goto error;
	}
	switch( cmd ){
	case 1: /* request  */

		if(vedev->node->ownership == NULL){
			pdev_info(vedev->pdev, "ownership: get ownership (%d)\n",pid_vnr(pid));
			vedev->node->ownership = pid;
			task->ownership = true;
		} else {
			/*
			 * I do so, even if I'm the owner
			 */
			pdev_err(vedev->pdev, "ownership: can't get ownership (%d), (%d) in use\n",
				 pid_vnr(pid),
				 pid_vnr(vedev->node->ownership));

			ret = -EBUSY;
			goto error;
		}
		break;
	case 0: /* release */

		if(vedev->node->ownership != NULL){
			/* anyoue use     */
			//if ( vedev->node->ownership == pid || capable(CAP_SYS_ADMIN)) {
			if ( vedev->node->ownership == pid ){
				pdev_info(vedev->pdev,
					  "ownership: owner release ownership (%d)\n",pid_vnr(pid));
				/* owner     */
				vedev->node->ownership = NULL;
				task->ownership = false;
			}else {
				/* not owner */
				pdev_err(vedev->pdev,
					 "ownership: can't release ownership (%d), owner is (%d)\n",
					 pid_vnr(pid),
					 pid_vnr(vedev->node->ownership));
				ret= -EACCES;
				goto error;
			}
			pdev_dbg(vedev->pdev,
				 "ownership: sysfs notify ownership\n");
			/*  notify to waiter */
			sysfs_notify(&vedev->device->kobj, NULL,"ownership");

		} else {
			pdev_err(vedev->pdev, "ownership: can't release (%d), no one owns\n",
				 pid_vnr(pid));
			/* no one used */
			//T.B.D
			//ret= -EACCES;
			ret = -EINVAL;
			goto error;
		}
		break;
	}
	spin_unlock_irqrestore(&vedev->node->lock, flags);
	pdev_dbg(vedev->pdev, "ownership out\n");
	return 0;
error:
	spin_unlock_irqrestore(&vedev->node->lock, flags);
	return ret;

}


int ve_drv_ve3_notify_fault(struct file *filp)
{
	struct ve_task *task;
	struct ve_dev *vedev;

	unsigned long flags;
	int ret;
	struct pid *pgid, *pid, *owner_pgid;
	struct task_struct *ts;
	int rv;
	int wsec;
	int old_owner_pid;


	task = filp->private_data;
	vedev = task->vedev;

	pdev_dbg(vedev->pdev, "notify_fault in\n");

	spin_lock_irqsave(&vedev->node->lock, flags);
	//T.B.D :: n
	//vedev->node->ve_state = VE_ST_UNAVAILABLE;

	pid = get_task_pid(current, PIDTYPE_PID);
	if (pid == NULL){
		pdev_err(vedev->pdev,
			 "notify_fault: get_task_pid error current\n");
		ret = -ESRCH;
		goto error;
	}
	pgid = get_task_pid(current, PIDTYPE_PGID);
	if (pgid == NULL){
		pdev_err(vedev->pdev,
			 "notify_fault: get_task_pid PIDTYPE_PGID error current\n");
		ret = -ESRCH;
		goto error;
	}

	// owner alive, and it's not mine
	if (vedev->node->ownership != NULL ){
		ts = get_pid_task(vedev->node->ownership,PIDTYPE_PID);
		if (ts == NULL){
			pdev_err(vedev->pdev,
				 "notify_fault: get_pid_task owner error \n");
			ret = -ESRCH;
			goto error;
		}
		owner_pgid = get_task_pid(ts, PIDTYPE_PGID);
		if (owner_pgid == NULL){
			pdev_err(vedev->pdev,
				 "notify_fault: get_task_pid OWNER PIDTYPE_PGID owner error\n");
			ret = -ESRCH;
			goto error;
		}
		pdev_dbg(vedev->pdev, "notify_fault:       pid=%d       pgid=%d\n",
			 pid_vnr(pid),  pid_vnr(pgid));
		pdev_dbg(vedev->pdev, "notify_fault: owner_pid=%d owner_pgid=%d\n",
			 pid_vnr(vedev->node->ownership), pid_vnr(owner_pgid));

		// it's not ours
		if(owner_pgid != pgid ){
			/*
			 * If notifyfaulter is not NULL, the previous notify_fault is waiting
			 * for kill_pid to kill the process.
			 */
			if( vedev->node->notifyfaulter  != NULL){
				ret = -EAGAIN;
				pdev_err(vedev->pdev,
					 "notify_fault: The previous notifyfault is just running. (%d) (%d) (%d)\n",
					 pid_vnr(vedev->node->ownership),
					 pid_vnr(vedev->node->notifyfaulter),
					 pid_vnr(pid));
				goto error;
			}

			/*  Set the notifier */
			vedev->node->notifyfaulter = pid;
			old_owner_pid = pid_vnr(vedev->node->ownership);
			pdev_dbg(vedev->pdev,
				 "notify_fault: kill %d and set ownership\n",
				 pid_vnr(vedev->node->ownership));
			/*
			 * kiil pid_p (which is veos ..)
			 */
			ret = kill_pid( vedev->node->ownership, SIGKILL , 1);

			if( ret < 0){
				/*
				 * even error reset ownership!!
				 */
				pdev_err(vedev->pdev,
					 "notify_fault: kill %d failed (%d)\n",
					 pid_vnr(vedev->node->ownership), ret);
				// T.B.D
				// allways  held node lock, so, if ownership  != NULL then kill_pid() not return nagative
				// but, .release function may be not called...
				//
				if( ret == -ESRCH) {
					vedev->node->notifyfaulter = NULL;
					vedev->node->ownership = NULL;
					task->ownership = false;
					/*  notify to waiter */
					sysfs_notify(&vedev->device->kobj,
						     NULL, "ownership");

					pdev_err(vedev->pdev,
						 "notify_fault: fource clear ownership\n");
				}
				goto error;

			}else{
				spin_unlock_irqrestore(&vedev->node->lock, flags);
				/*
				 * Forcibly change owner !!
				 */
				wsec = 0;
				/*
				 * wait for ownership process to close
				 * ownership will be set to notifyfaulter at .release
				 */
				do {
					rv = wait_event_interruptible_timeout
						(
						 ((struct ve_dev *)vedev)->release_q,
						 vedev->node->ownership == pid,
						 msecs_to_jiffies(1000)
						 );
				} while( vedev->node->ownership != pid &&
					 ++wsec < wait_sec_after_sigkill_on_notify_fault &&
					 rv != -ERESTARTSYS );

				spin_lock_irqsave(&vedev->node->lock, flags);

				if ( vedev->node->ownership != pid ){
					vedev->node->notifyfaulter = NULL;
					pdev_err(vedev->pdev,
						 "notify_fault: ownership process(%d) was still live after kill_pid (%d) (%d)\n",
						 pid_vnr(vedev->node->ownership), rv, wsec );

					ret = -ETIMEDOUT;

					goto error;
				}else {
					task->ownership = true;
					pdev_info(vedev->pdev,
						 "notify_fault: ownership process(%d) was killed and (%d) got new ownership (%d) (%d)\n",
						  old_owner_pid, pid_vnr(vedev->node->ownership), rv, wsec );
				}
			}

		} else {
			pdev_dbg(vedev->pdev,
				 "notify_fault: allready ownership is ours\n");
		}

	} else {
		pdev_err( vedev->pdev,
			  "notify_fault: (%d) no one owns\n",pid_vnr(pid));
		ret= -ESRCH;
		goto error;
	}

	spin_unlock_irqrestore(&vedev->node->lock, flags);
	pdev_dbg(vedev->pdev, "notify_fault out\n");
	return 0;
error:
	spin_unlock_irqrestore(&vedev->node->lock, flags);
	return ret;
}


/**
 * @brief Get  EXS register
 *
 * @details
 * This function get  EXS register
 *
 * @param[in] vedev: VE device structure
 * @param[out] user_exs: exs register value will be set
 *
 * @return 0 on success.
 *
 */
int ve_drv_ve3_get_exs_reg(struct file *filp,  uint64_t __user *user_exs)
{
	int ret;
	uint64_t exs=0;
	int core_id;
	int noc;
	unsigned long flags;

	struct ve_task *task;
	struct ve_dev *vedev;
	struct ve_node *node;

	if (filp->private_data == NULL)
		return -ESRCH;

	task = filp->private_data;
	vedev = task->vedev;
	node = vedev->node;
	noc = node->core_fls;

	pdev_trace(vedev->pdev);

	spin_lock_irqsave(&node->lock, flags);

	exs = task->exs;
	for (core_id = 0; core_id < noc; core_id++) {
		if (node->core[core_id]->task == task) {
			exs = vedev->arch_class->get_exs(vedev, core_id);
			break;
		}
	}
	if (core_id >= noc){
		pdev_dbg(vedev->pdev,
			 "task %d is unassigned but EXS register was not saved\n",
			 pid_nr(task->pid));
        }
	spin_unlock_irqrestore(&node->lock, flags);

	ret = put_user(exs, user_exs);
	if (ret)
		return -EFAULT;

	return ret;

}

int ve_drv_ve3_complete_memclear(struct ve_dev *vedev)
{

        /* (1) MCU EIF RESET */
        uint64_t val;
        ve_bar4_write64(vedev,0x005C9010, 0x00C0FF0000000000);
        ve_bar4_read64( vedev,0x005C9010,&val);

        ve_bar4_write64(vedev,0x005C9020, 0x00C0FF0000000000);
        ve_bar4_read64( vedev,0x005C9020,&val);

        /* (2) MCU INH RESET */
        ve_bar4_write64(vedev,0x0059ca08, 0x0000000000000000);
        ve_bar4_write64(vedev,0x00598810, 0x000FE00000000000);
        ve_bar4_write64(vedev,0x005990c0, 0x0000000000000000);
        ve_bar4_write64(vedev,0x005992c0, 0x0000000000000000);
        ve_bar4_write64(vedev,0x005994c0, 0x0000000000000000);
        ve_bar4_write64(vedev,0x005996c0, 0x0000000000000000);
        ve_bar4_write64(vedev,0x005998c0, 0x0000000000000000);
        ve_bar4_write64(vedev,0x00599ac0, 0x0000000000000000);
        ve_bar4_write64(vedev,0x00599cc0, 0x0000000000000000);
        ve_bar4_write64(vedev,0x00599ec0, 0x0000000000000000);

        pdev_dbg(vedev->pdev,"ve_drv_ve3_complete_memclear\n");

	return 0;
}

int ve_drv_ve3_clock_gating(struct ve_dev *vedev, int cmd)
{
	int ret=0;
	pdev_dbg(vedev->pdev, "clock_gating in\n");

	switch( cmd ){
	case 1: /* Core Clock Gating ON  */
	  ve_bar4_write64(vedev,0x00580010, 0x0000000000000800);
	  break;
	case 0: /* Core Clock Gating OFF */
	  ve_bar4_write64(vedev,0x00580020, 0x0000000000000800);
	  break;
	default:
	  pdev_err(vedev->pdev, "Clock Gating is invalid args\n");
	  ret = -EINVAL;
	  break;
	}

	pdev_dbg(vedev->pdev, "clock_gating out\n");
	return ret;
}

int ve_drv_ve3_get_clock_gating_state(struct ve_dev *vedev,  uint64_t __user *user_state)
{
	int ret;
	uint64_t state;

	ve_bar4_read64( vedev,0x00530000,&state);

	ret = put_user(state, user_state);
	if (ret)
		return -EFAULT;
	return ret;
}
