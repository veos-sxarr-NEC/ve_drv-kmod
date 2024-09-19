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
 * @file fops.c
 * @brief VE driver file operations.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/moduleparam.h>
#include <linux/kthread.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/poll.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>

#include "ve_drv.h"
#include "internal.h"

#include <linux/version.h>
#if (KERNEL_VERSION(4, 11, 0) <= LINUX_VERSION_CODE)
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#endif



/**
 * @brief open method of VE file operation
 *
 * @param[in] ino: inode structure of opening
 * @param[in] filp: file structure of opening
 *
 * @return 0 on success.
 *         -EBUSY on the the task already exist.
 *         -ENOMEM on no memory.
 *         -ESRCH on no such pid.
 */
int ve_drv_open(struct inode *ino, struct file *filp)
{
	struct list_head *ptr;
	struct ve_task *task;
	struct ve_dev *vedev;
	struct ve_node *node;
	struct list_head *head;
	unsigned long flags;
	struct pid *pid;

	vedev = container_of(ino->i_cdev, struct ve_dev, cdev);
	pdev_trace(vedev->pdev);

	/* for unmapping */
	vedev->dev_mapping = &ino->i_data;

	pid = get_task_pid(current, PIDTYPE_PID);
	if (pid == NULL)
		return -ESRCH;

	node = vedev->node;
	head = &node->task_head;

	/* Check if the pid is already in the list */
	spin_lock_irqsave(&node->lock, flags);

	list_for_each(ptr, head) {
		task = list_entry(ptr, struct ve_task, list);
		if (task->pid != pid)
			continue;

		pdev_dbg(vedev->pdev, "task %d already exists\n",
				pid_vnr(task->pid));
		spin_unlock_irqrestore(&node->lock, flags);
		put_pid(pid);
		return -EBUSY;
	}
	/* block open,  device will be deleted */
	if( vedev->remove_processing ){
		spin_unlock_irqrestore(&node->lock, flags);
		pdev_dbg(vedev->pdev,"device will be deleted, open is blocked\n");
		put_pid(pid);
		return -EINTR;// -ENODEV;
	}
	spin_unlock_irqrestore(&node->lock, flags);


	task = kmalloc(sizeof(struct ve_task), GFP_KERNEL);
	if (!task) {
		put_pid(pid);
		return -ENOMEM;
	}

	init_waitqueue_head(&task->waitq);
	init_waitqueue_head(&task->waitq_dead);
	task->wait_cond = 0;
	task->wait_cond_dead = 0;
	task->state = TASK_STATE_NEW;
	task->vedev = vedev;
	task->exs = 0;
	task->pid = pid;
	task->mm = NULL;
	task->mmap = false;
	task->ownership = false;

	filp->private_data = task;

	INIT_LIST_HEAD(&task->list);

	spin_lock_irqsave(&node->lock, flags);
	list_add(&task->list, head);
	spin_unlock_irqrestore(&node->lock, flags);

	pdev_dbg(vedev->pdev, "task %d has been created\n",
			pid_vnr(task->pid));
	/* reference dev */
	ve_drv_device_get(vedev);


	return 0;
}

/**
 * @brief Read EXS register value
 *        Firstly try to get EXS value from EXSRAR target address.
 *        In the case of timeout, read it from MMIO address.
 *
 * @param[in] vedev: VE device structure
 * @param core_id: VE core ID
 *
 * @return EXS value
 */
static inline uint64_t ve_get_exs(struct ve_dev *vedev, int core_id)
{

        u64 timeout_jiffies;
        uint64_t exs = 0;
        int count = 0;

        pdev_trace(vedev->pdev);

        /* get current jiffies and convert it to usec */
        timeout_jiffies = get_jiffies_64() +
            msecs_to_jiffies(exsrar_poll_timeout_msec);

        /* poll EXS register */
        do {
          //state is  +->10b -->11b -->01b+
          //          <-------------------+
          exs = vedev->arch_class->get_exs(vedev, core_id);
          // 10b:EXECUTE
          if ((exs & (EXS_STATE_RUN | EXS_STATE_STOP)) == EXS_STATE_RUN) {
	    //ve_get_exs is called in run state
            pdev_dbg(vedev->pdev, "EXS is STATE_RUN(0x%llx) count=%d\n",exs,count);
            return exs;
          }
          // 01b:HALT
          if ((exs & (EXS_STATE_RUN | EXS_STATE_STOP)) == EXS_STATE_STOP) {
            if (count > 0) {
              //ve_get_exs is called in before halt state, and then  halted.
              pdev_dbg(vedev->pdev, "EXS is STATE_STOP(0x%llx) count =%d\n",exs,count);
	    }
	    return exs;
          }
          // 11b:BEFORE HALT
          count++;
          ndelay(exsrar_poll_delay_nsec);
        } while (time_before64(get_jiffies_64(), timeout_jiffies));
        //stil before halt state
        pdev_err(vedev->pdev, "EXS is still before halt state. STATE(0x%llx) count =%d\n",exs,count);

	return exs;
}

/**
 * @brief Wait for VE core exception
 *
 * @param[in] filp: file pointer of ioctl
 * @param[out] user_exs: EXS value will be set
 *
 * @return 0 on success.
 *         -EAGAIN if O_NONBLOCK flag is enabled.
 *         -EINTR if interrupted by signal.
 *         -ESRCH if the VE task id is not same as current tid
 *                if task is not created.
 */
int ve_drv_wait_exception(struct file *filp, uint64_t __user *user_exs)
{
	struct ve_task *task;
	struct ve_dev *vedev;
	struct ve_node *node;
	unsigned long flags;
	struct pid *pid;
	int core_id, ret;
	uint64_t exs = 0;
	uint16_t noc;

	task = filp->private_data;
	vedev = task->vedev;
	node = vedev->node;
	noc = node->core_fls;

	pdev_trace(vedev->pdev);




	/*
	 * TODO: This is workaround. Get mm should be removed.
	 */
	/* This is a limitation of the workaround */
	if (unlikely(task->mmap == true)) {
		pdev_dbg(vedev->pdev,
				"task %d has memory map\n",
				pid_vnr(task->pid));
		return -EINVAL;
	}
	/*
	 * Raise reference count of mm here
	 * it will be put in .release
	 */
	if (unlikely(task->mm == NULL))
		task->mm = get_task_mm(current);

	/*
	 * Just for getting struct pid.
	 * We can call put_pid() immediately since
	 * get_pid was already done at open().
	 */
	pid = get_task_pid(current, PIDTYPE_PID);
	if (pid == NULL)
		return -ESRCH;
	put_pid(pid);

	spin_lock_irqsave(&node->lock, flags);
	/* Check if the task is in waitable state */
	switch (task->state) {
	case TASK_STATE_READY:
	case TASK_STATE_ASSIGNED:
		break;
	default:
		spin_unlock_irqrestore(&node->lock, flags);
		return -ESRCH;
	}

	pdev_dbg(vedev->pdev, "task %d (%d)\n", pid_nr(task->pid), task->state);

	if (filp->f_flags & O_NONBLOCK) {
		spin_unlock_irqrestore(&node->lock, flags);
		return -EAGAIN;
	}

	spin_unlock_irqrestore(&node->lock, flags);

	pdev_dbg(vedev->pdev, "task %d sleep\n", pid_nr(task->pid));
	ret = wait_event_interruptible(task->waitq,
			task->wait_cond);
	if (ret)
		return -EINTR;
	pdev_dbg(vedev->pdev, "task %d awake\n", pid_nr(task->pid));

	spin_lock_irqsave(&node->lock, flags);
	task->wait_cond = 0;

	/* Get EXS value */
	if (task->exs != 0) {
		/* the task is already unassigned */
		exs = task->exs;
		task->exs = 0;
		pdev_dbg(vedev->pdev, "EXS value saved in task is used\n");
	} else {
		for (core_id = 0; core_id < noc; core_id++) {
			if (node->core[core_id]->task == task) {
				exs = ve_get_exs(vedev, core_id);

				if (node->core[core_id]->count == 0) {
					pdev_err(vedev->pdev,
"task %d wake up but interrupt count is zero (task->exs = %llx,exs = %llx)\n",
					pid_nr(task->pid), task->exs, exs);
				}
				node->core[core_id]->count = 0;
				break;
			}
		}
		if (core_id >= noc)
			pdev_err(vedev->pdev,
				"task %d is unassigned but EXS was not saved\n",
				pid_nr(task->pid));
	}
	task->last_exs = exs;
	spin_unlock_irqrestore(&node->lock, flags);

	/* Copy EXS value to the user space */
	ret = put_user(exs, user_exs);
	if (ret)
		return -EFAULT;
	pdev_dbg(vedev->pdev, "task %d return EXS = %llx\n",
			pid_nr(task->pid), exs);

	return 0;
}

/**
 * @brief Get the number of VE core
 *
 * @param[in] vedev: VE device structure
 *
 * @return number of VE core
 */
int ve_drv_get_core_num(struct ve_dev *vedev)
{
	pdev_trace(vedev->pdev);

	return vedev->node->hw_info.num_of_core;
}

/**
 * @brief Get physical memory size of VE
 *
 * @param[in] vedev: VE device structure
 * @param[out] size: Size of memory will be stored
 *
 * @return 0 on success. Negative on failure.
 */
int ve_drv_get_memory_size(struct ve_dev *vedev, uint64_t __user *size)
{
	pdev_trace(vedev->pdev);

	return put_user(vedev->node->hw_info.memory_size, size);
}

/**
 * @brief Print task information to the buffer
 *        This function is called via sysfs
 *
 * @param[in] node: VE node structure
 * @param[out] buf: string buffer to be filled
 * @param released: print released task only if it is 1
 *
 * @return length of buffer
 */
int print_task_info(struct ve_dev *vedev, char *buf, int released)
{
	struct ve_node *node = vedev->node;
	struct list_head *ptr;
	struct ve_task *task;
	unsigned long flags;
	int ret, len;

	if (buf == NULL)
		return 0;

	ret = 0;
	spin_lock_irqsave(&node->lock, flags);
	list_for_each(ptr, &node->task_head) {
		task = list_entry(ptr, struct ve_task, list);
		/* skip new task(including veos, mmm, etc) */
		if (task->state == TASK_STATE_NEW)
			continue;
		if ((released & (task->state == TASK_STATE_RELEASED)) |
				!released) {
			len = snprintf(NULL, 0, "%d \n", pid_vnr(task->pid));
			if (unlikely(ret+len >= PAGE_SIZE))
				goto out;

			len = scnprintf(buf + ret, PAGE_SIZE - ret,
					"%d \n", pid_vnr(task->pid));
			ret += (len - 1);
		}
	}
out:
	spin_unlock_irqrestore(&node->lock, flags);
	if (ret)
		ret += 1;
	else
		ret = scnprintf(buf, PAGE_SIZE, " \n");

	return ret;
}

#ifdef VE_DRV_DEBUG
/**
 * @brief Print VE core information to the buffer
 *        This function is called via sysfs
 *
 * @param[in] node: VE node structure
 * @param[out] buf: string buffer to be filled
 *
 * @return length of buffer
 */
int print_core_info(struct ve_node *node, char *buf)
{
	int core_id;
	unsigned long flags;
	int ret, len;

	if (buf == NULL)
		return 0;

	ret = 0;
	spin_lock_irqsave(&node->lock, flags);
	for (core_id = 0; core_id < node->core_fls; core_id++) {
		len = sprintf(buf + ret, "core id: %d\n"
			      "\tintr count: %d\n"
			      "\tassigned tid: ",
			      node->core[core_id]->core_id,
			      node->core[core_id]->count);
		ret += len;
		if (node->core[core_id]->task != NULL) {
			len = sprintf(buf + ret, "%d\n",
				      pid_vnr(node->core[core_id]->task->pid));
			ret += len;
		} else {
			len = sprintf(buf + ret, "%s\n", "not assigned");
			ret += len;
		}
	}
	spin_unlock_irqrestore(&node->lock, flags);

	return ret;
}
#endif

/**
 * @brief Assign VE task to the VE core (internal function)
 *
 * @param[in] vedev: VE device structure
 * @param tid_ns: VE task ID seen from namespace of current
 * @param core_id: VE core ID
 *
 * @return 0 on success.
 *         -EINVAL on invalid core ID.
 *         -ESRCH on invalid task ID.
 *                on invalid task state.
 *         -EBUSY if some task is already assigned to the core.
 *         -EAGAIN if exception saved in task is not handled yet.
 */
static int
_ve_drv_assign_task_to_core(struct ve_dev *vedev, pid_t tid_ns, int core_id)
{
	struct ve_node *node = vedev->node;
	struct ve_hw_info *info = &node->hw_info;
	struct list_head *head = &node->task_head;
	struct list_head *ptr;
	struct ve_task *task;
	unsigned long flags;
	int ret = 0;

	pdev_trace(vedev->pdev);

	if (!(info->core_enables & (1 << core_id)) || core_id < 0)
		return -EINVAL;

	spin_lock_irqsave(&node->lock, flags);
	list_for_each(ptr, head) {
		task = list_entry(ptr, struct ve_task, list);
		if (pid_vnr(task->pid) == tid_ns)
			goto found;
	}
	ret = -ESRCH;
	goto unlock;
 found:
	if (node->core[core_id]->task != NULL) {
		pdev_dbg(vedev->pdev, "task is not NULL\n");
		ret = -EBUSY;
		goto unlock;
	}
	if (task->exs || task->state == TASK_STATE_RELEASED) {
		pdev_dbg(vedev->pdev, "exs = %llx, task->state = %d\n",
				task->exs, task->state);
		ret = -EAGAIN;
		goto unlock;
	}
	if (task->state != TASK_STATE_READY) {
		pdev_dbg(vedev->pdev, "task->state = %d\n", task->state);
		ret = -ESRCH;
		goto unlock;
	}

	node->core[core_id]->task = task;
	task->state = TASK_STATE_ASSIGNED;
	pdev_dbg(vedev->pdev, "%d is assigned to core %d\n", pid_vnr(task->pid),
			core_id);

 unlock:
	spin_unlock_irqrestore(&node->lock, flags);

	return ret;
}

/**
 * @brief Assign VE task to the VE core
 *        This function is called via ioctl
 *
 * @param[in] vedev: VE device structure
 * @param[in] arg: ioctl argument
 *
 * @return 0 on success.
 *         -EFAULT on invalid arg.
 *         -EINVAL on invalid core ID in arg.
 *         -ESRCH on invalid task ID in arg.
 */
int ve_drv_assign_task_to_core(struct ve_dev *vedev,
		struct ve_tid_core __user *arg)
{
	int err;
	struct ve_tid_core tmp;

	pdev_trace(vedev->pdev);

	err = copy_from_user(&tmp, arg, sizeof(struct ve_tid_core));
	if (err)
		return -EFAULT;
	else
		return (_ve_drv_assign_task_to_core(vedev, tmp.tid,
						    tmp.core_id));
}

/**
 * @brief Unassign VE task from VE core (internal function)
 *
 * @param[in] vedev: VE device structure
 * @param[in] task: VE task structure
 * @param force: unassign forcely
 *
 * @return 0 on success.
 *         -EINVAL if the VE task is not assigned to any VE core.
 *         -EBUSY if the VE core is in running state.
 */
static int _unassign_task_from_core(struct ve_dev *vedev, struct ve_task *task,
				    int force, int check_exsreg)
{
	int core_id;
	int count;
	struct ve_node *node = vedev->node;
	uint64_t exs = 0;

	for (core_id = 0; core_id < node->core_fls; core_id++) {
		if (node->core[core_id]->task != task)
			continue;

		if (force)
			goto unassign;

		/*
		 * NOTE: Since VEOS can manipulate the EXS register
		 * asynchronously, VE driver cannot assure that the core
		 * is in stopped state and all exception is solved
		 * during VE task unassignment. Following checks are
		 * just for preventing VEOS from bug.
		 */
		exs = vedev->arch_class->get_exs(vedev, core_id);
		if (exs & EXS_STATE_RUN)
			return -EBUSY;

		/* Check if the VE core is in exceptional state */
		count = node->core[core_id]->count;
		if (count > 0) {
			pdev_dbg(vedev->pdev,
				"task %d interrupt is not handled yet\n",
				pid_vnr(task->pid));
			/* Save EXS to task structure */
			node->core[core_id]->count = 0;
			if( check_exsreg ){
				task->exs = exs;
				/*
				 * Wait for the write to *EXSRAR to complete, then
				 * clears *EXSRAR, Use the value of the EXS register
				 * instead of *EXSRAR.
				 */
				ve_get_exs(vedev, core_id);
			} else
				task->exs = ve_get_exs(vedev, core_id);
			pdev_dbg(vedev->pdev,
			"Saving exs value to the task %d (task->exs = %llx)\n",
				pid_vnr(task->pid), task->exs);
			if( check_exsreg == 0 ){
				/* only VE1 */
				/* wake the task */
				task->wait_cond = 1;
				wake_up_interruptible(&task->waitq);
			}
		} else {
			/*
			 * Interrupt has not been arrived yet so we return
			 * -EAGAIN to wait for that
			 */
			if (vedev->arch_class->core_intr_undelivered(vedev,
						core_id))
				return -EAGAIN;

			// Not interrupt,
			// last_exs is 0 and this time have exception cause.
			//
			if( check_exsreg &&
			    ( (EXS_EXCEPTION_MASK|EXS_RDBG) & task->last_exs ) == 0 &&
			    ( (EXS_EXCEPTION_MASK|EXS_RDBG) & exs ) ){
				pdev_dbg(vedev->pdev, "task %d is unassigned from core 0x%llx:0x%llx\n",
					  pid_vnr(task->pid),task->last_exs, exs );
                             task->exs = exs;
			     task->wait_cond = 1;
			     wake_up_interruptible(&task->waitq);
			}

		}
unassign:
		/* Unassign the task from the core */
		node->core[core_id]->task = NULL;
		if (task->state != TASK_STATE_RELEASED)
			task->state = TASK_STATE_READY;

		pdev_dbg(vedev->pdev, "task %d is unassigned from core\n",
				pid_vnr(task->pid));
		return 0;
	}

	return -EINVAL;
}

/**
 * @brief Unassign VE task from VE core
 *        This function is called via ioctl
 *
 * @param[in] vedev: VE device structure
 * @param tid_ns: VE task ID seen from namespace of current
 * @param check_exsreg:: check exs register directly
 *
 * @return 0 on success.
 *         -ESRCH if the VE task is not found.
 *         -EINVAL if the VE task is not assigned to any VE core.
 *         -EBUSY if the VE core is in running state.
 */
int ve_drv_unassign_task_from_core(struct ve_dev *vedev, pid_t tid_ns, int check_exsreg)
{
	struct ve_node *node = vedev->node;
	struct list_head *head = &node->task_head;
	struct list_head *ptr;
	struct ve_task *task;
	unsigned long flags;
	int ret;

	pdev_trace(vedev->pdev);

	spin_lock_irqsave(&node->lock, flags);
	list_for_each(ptr, head) {
		task = list_entry(ptr, struct ve_task, list);
		if (pid_vnr(task->pid) == tid_ns)
			goto found;
	}
	spin_unlock_irqrestore(&node->lock, flags);
	return -ESRCH;
 found:
	ret = _unassign_task_from_core(vedev, task, 0, check_exsreg);
	spin_unlock_irqrestore(&node->lock, flags);

	return ret;
}

/**
 * @brief Delete VE task
 *        This function is called via ioctl
 *
 * @param[in] vedev: VE device structure
 * @param tid_ns: VE task ID seen from namespace of current
 *
 * @return 0 on success.
 *         -EAGAIN if mutex lock is already locked or
 *                 VE task can not be unassigned now.
 *         -ESRCH if the VE task of the ID is not found.
 */
int ve_drv_del_ve_task(struct ve_dev *vedev, pid_t tid_ns)
{
	struct ve_node *node = vedev->node;
	struct list_head *head = &node->task_head;
	struct list_head *ptr, *n;
	struct ve_task *task;
	unsigned long flags;
	int ret = 0;

	pdev_trace(vedev->pdev);

	spin_lock_irqsave(&node->lock, flags);
	list_for_each_safe(ptr, n, head) {
		task = list_entry(ptr, struct ve_task, list);
		if (pid_vnr(task->pid) != tid_ns)
			continue;

		switch (task->state) {
		case TASK_STATE_NEW:
			break;
		case TASK_STATE_READY:
			/*
			 * set the state as deleted and delete the structure
			 * in release()
			 */
			task->state = TASK_STATE_DELETED;
			break;
		case TASK_STATE_ASSIGNED:
			pdev_dbg(vedev->pdev,
				"task %d is currently assigned to core.\n",
				pid_vnr(task->pid));
			pdev_dbg(vedev->pdev,
				"Unassign from core and try again\n");
			ret = -EAGAIN;
			break;
		case TASK_STATE_RELEASED:
			/*
			 * wake up the sleeping task in release method.
			 */
			pdev_dbg(vedev->pdev,
				"wake up task %d to delete itself\n",
				pid_vnr(task->pid));
			task->wait_cond_dead = 1;
			wake_up(&task->waitq_dead);
			break;
		default:
			pdev_dbg(vedev->pdev,
				"task %d is already marked as deleted\n",
				pid_vnr(task->pid));
			/* Do nothing */
			break;
		}
		goto out;
	}
	ret = -ESRCH;
 out:
	spin_unlock_irqrestore(&node->lock, flags);
	return ret;
}

/**
 * @brief Revive VE task
 *        This function change ve_task state
 *        from TASK_STATE_DELETED to TASK_STATE_READY
 *
 * @param[in] vedev: VE device structure
 * @param tid_ns: VE task ID seen from namespace of current
 *
 * @return 0 on success.
 *         -EINVAL if the VE task is in non-revival state.
 *         -ESRCH if the VE task of the ID is not found.
 */
int ve_drv_revive_ve_task(struct ve_dev *vedev, pid_t tid_ns)
{
	struct ve_node *node = vedev->node;
	struct list_head *head = &node->task_head;
	struct list_head *ptr, *n;
	struct ve_task *task;
	unsigned long flags;
	int ret = 0;

	pdev_trace(vedev->pdev);

	spin_lock_irqsave(&node->lock, flags);
	list_for_each_safe(ptr, n, head) {
		task = list_entry(ptr, struct ve_task, list);
		if (pid_vnr(task->pid) != tid_ns)
			continue;

		switch (task->state) {
		case TASK_STATE_READY:
			break;
		case TASK_STATE_DELETED:
			task->state = TASK_STATE_READY;
			break;
		default:
			pdev_dbg(vedev->pdev,
				"task %d cannot not be revived\n",
				pid_vnr(task->pid));
			ret = -EINVAL;
			break;
		}
		goto out;
	}
	ret = -ESRCH;
 out:
	spin_unlock_irqrestore(&node->lock, flags);
	return ret;
}


int ve_drv_del_all_task(struct ve_dev *vedev)
{
	struct ve_node *node = vedev->node;
	struct list_head *head = &node->task_head;
	struct list_head *ptr, *n;
	struct ve_task *task;
	unsigned long flags;

	pdev_trace(vedev->pdev);

	spin_lock_irqsave(&node->lock, flags);
	list_for_each_safe(ptr, n, head) {
		task = list_entry(ptr, struct ve_task, list);

		/* Unassign task forcely */
		(void)_unassign_task_from_core(vedev, task, 1, 0);

		switch (task->state) {
		case TASK_STATE_NEW:
			break;
		case TASK_STATE_READY:
			/*
			 * set the state as deleted and delete the structure
			 * in release method
			 */
			task->state = TASK_STATE_DELETED;
			break;
		case TASK_STATE_RELEASED:
			/*
			 * wake up the sleeping task in release method.
			 */
			pdev_dbg(vedev->pdev,
				"wake up task %d to delete itself\n",
				pid_vnr(task->pid));
			task->wait_cond_dead = 1;
			wake_up(&task->waitq_dead);
			break;
		default:
			pdev_dbg(vedev->pdev,
				"task %d is already marked as deleted\n",
				pid_vnr(task->pid));
			/* Do nothing */
			break;
		}
	}
	spin_unlock_irqrestore(&node->lock, flags);
	return 0;
}

/**
 * @brief flush method of VE file operation
 *
 * @param[in] filp: file structure of flushing
 * @param id: POSIX Owner ID of flushing (legacy argument)
 *
 * @return always 0.
 */
int ve_drv_flush(struct file *filp, fl_owner_t id)
{
	/* currently nothing to do */
	return 0;
}

/**
 * @brief release method of VE file operation
 *        Currently there is nothing to do here.
 *
 * @param[in] ino: inode structure of releasing
 * @param[in] filp: file structure of releasing
 *
 * @return always 0.
 */
int ve_drv_release(struct inode *ino, struct file *filp)
{
	unsigned long flags;
	struct ve_task *task, *list_task;
	struct ve_dev *vedev;
	struct ve_node *node;
	struct list_head *head, *ptr, *n;
	int ret;
	vedev = container_of(ino->i_cdev, struct ve_dev, cdev);
	pdev_trace(vedev->pdev);
	/* Just in case */
	if (filp->private_data == NULL) {
		pdev_warn(vedev->pdev,
				"filp->private_data was already released\n");
		return 0;
	}

	task = filp->private_data;
	node = vedev->node;
	head = &node->task_head;

	spin_lock_irqsave(&vedev->node->lock, flags);
	switch (task->state) {
	case TASK_STATE_ASSIGNED:
		pdev_dbg(vedev->pdev,
			"task %d is killed but still assigned to the core\n",
			pid_vnr(task->pid));
#if (KERNEL_VERSION(5, 9, 0) <= LINUX_VERSION_CODE)
		fallthrough;
#endif
	case TASK_STATE_READY:
		/*
		 * Change state to released.
		 * Then notify veos of it.
		 */
		task->state = TASK_STATE_RELEASED;
		spin_unlock_irqrestore(&vedev->node->lock, flags);

		sysfs_notify(&vedev->device->kobj, NULL,
				"task_id_dead");
		pdev_dbg(vedev->pdev, "task %d is released\n",
				pid_vnr(task->pid));


		/* block here for protecting IB resources */
		wait_event(task->waitq_dead, task->wait_cond_dead);

		spin_lock_irqsave(&vedev->node->lock, flags);

		/*
		 * Unassign task from core if it is not unassigned yet.
		 * -EINVAL is expected. If success, it is VEOS bug.
		 * VEOS must unassign task before deleting.
		 */
		ret = _unassign_task_from_core(vedev, task, 0, 0);
		if (ret != -EINVAL) {
			pdev_err(vedev->pdev,
		"VEOS BUG: task %d is deleted without unassign from core\n",
		 pid_vnr(task->pid));
		}

		break;

	case TASK_STATE_NEW:
	case TASK_STATE_DELETED:
		/*
		 * Delete task structure right now.
		 */
		break;

	default:
		pdev_err(vedev->pdev, "ve_task %d invalid state (%d)\n",
				pid_vnr(task->pid), task->state);
	}

	list_for_each_safe(ptr, n, head) {
		list_task = list_entry(ptr, struct ve_task, list);
		if (list_task == task) {
			if( vedev->arch_class->ve_arch_release ){
				vedev->arch_class->ve_arch_release(vedev,task);
			}
			pdev_dbg(vedev->pdev, "task %d is deleted\n",
					pid_vnr(task->pid));

			list_del(&task->list);
			goto found;
		}
	}
	pdev_warn(vedev->pdev, "task %d is not found in the list\n",
			pid_vnr(task->pid));
found:

	spin_unlock_irqrestore(&vedev->node->lock, flags);
	put_pid(task->pid);
	if (task->mm)
		mmput(task->mm);
	kfree(task);
	filp->private_data = NULL;

	/* de reference */
	ve_drv_device_put(vedev);

	return 0;
}

/**
 * @brief Create VE task
 *        This function is called via ioctl.
 *
 * @param[in] vedev: VE device structure
 * @param tid_ns: VE task ID seen from namespace of current
 *
 * @return 0 on success.
 *         -ESRCH if VE task ID is not found
 */
int ve_drv_add_ve_task(struct ve_dev *vedev, pid_t tid_ns)
{
	struct ve_node *node = vedev->node;
	struct list_head *head = &node->task_head;
	struct list_head *ptr, *n;
	struct ve_task *task;
	unsigned long flags;
	int ret = 0;

	pdev_trace(vedev->pdev);

	spin_lock_irqsave(&node->lock, flags);
	list_for_each_safe(ptr, n, head) {
		task = list_entry(ptr, struct ve_task, list);
		if (pid_vnr(task->pid) != tid_ns)
			continue;

		switch (task->state) {
		case TASK_STATE_NEW:
			task->state = TASK_STATE_READY;
			goto out;
		default:
			pdev_dbg(vedev->pdev, "task %d is already created\n",
					pid_vnr(task->pid));
			/* Do nothing */
			break;
		}
		goto out;
	}
	ret = -ESRCH;
 out:
	spin_unlock_irqrestore(&node->lock, flags);
	return ret;
}

/**
 * @brief Reset interrupt count of VE core
 *        This function is called via ioctl.
 *
 * @param[in] vedev: VE device structure
 * @param core_id: VE core ID
 *
 * @return 0 on success.
 *         -EINVAL if the core ID is invalid.
 */
int ve_drv_reset_intr_count(struct ve_dev *vedev, uint64_t core_id)
{
	/* Do nothing */

	return 0;
}
#if (KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE)
static inline unsigned long timespec_to_jiffies(const struct timespec *value)
{
	struct timespec64 ts = *(const struct timespec64 *)(value);
        return timespec64_to_jiffies(&ts);
}
#endif
/**
 * @brief Wait for specific interrupt such as DMA, Error, and so on.
 *        (internal function)
 *
 * @param[in] vedev: VE device structure
 * @param[in,out] irq: interrupt vector to wait
 * @param[in] timeout: timeout value
 *
 * @return Positive on success.
 *         -EINTR if it is interrupted by signal.
 *         -ETIMEDOUT in case of timeout.
 */
int ve_drv_generic_arch_wait_intr(struct ve_dev *vedev,
	struct ve_wait_irq *irq, struct timespec *timeout,
	bool (*check)(const struct ve_wait_irq *, const struct ve_wait_irq *),
	void (*woken_cb)(struct ve_dev *,
		struct ve_wait_irq *, struct ve_wait_irq *))
{
	int ret;
	struct ve_node *node = vedev->node;

	pdev_trace(vedev->pdev);

	/* This will returns immediately when the condition is true. */
	ret = wait_event_interruptible_timeout(node->waitq,
					       check(node->cond, irq),
					       timespec_to_jiffies(timeout));

	if (ret == -ERESTARTSYS)
		return -EINTR;
	if (ret == 0)
		return -ETIMEDOUT;
	if (ret > 0) {
		woken_cb(vedev, node->cond, irq);
	}

	return ret;
}

/**
 * @brief Wait for specific interrupt such as DMA, Error, and so on.
 *        This function is called via ioctl.
 *
 * @param[in] vedev: VE device structure
 * @param[in,out] usr: ioctl argument
 *
 * @return Positive on success.
 *         -EFAULT if failed to copy the argument.
 *         -EINTR if it is interrupted by signal.
 *         -ETIMEDOUT in case of timeout.
 */
int ve_drv_wait_intr(struct ve_dev *vedev, struct ve_wait_irq_arg *usr)
{
	int ret, retval;

	struct ve_wait_irq_arg krn;
	struct timespec timeout;
	struct ve_wait_irq *cond;
	size_t cond_size;

	pdev_trace(vedev->pdev);

	cond_size = vedev->arch_class->ve_wait_irq_size;
	cond = kmalloc(cond_size, GFP_KERNEL);
	if (!cond)
		return -ENOMEM;
	ret = copy_from_user(&krn, usr, sizeof(struct ve_wait_irq_arg));
	if (ret) {
		retval = -EFAULT;
		goto err;
	}
	ret = copy_from_user(&timeout, krn.timeout, sizeof(struct timespec));
	if (ret) {
		retval = -EFAULT;
		goto err;
	}
	ret = copy_from_user(cond, krn.bits, cond_size);
	if (ret) {
		retval = -EFAULT;
		goto err;
	}
	if (cond->ve_irq_type != vedev->arch_class->ve_irq_type) {
		retval = -EINVAL;
		goto err;
	}

	retval = vedev->arch_class->ve_arch_wait_intr(vedev, cond, &timeout);
	if (retval < 0)
		goto err;

	ret = copy_to_user(krn.bits, cond, cond_size);
	if (ret)
		retval = -EFAULT;
 err:
	kfree(cond);
	return retval;
}

/**
 * @brief Assign CR page (Allowing BAR3 memory mapping) to specific user ID
 *        This function is called via ioctl.
 *
 * @param[in] vedev: VE device structure
 * @param[in] usr: ioctl arguments. Do copy_from_user() before useing.
 *
 * @return 0 on success.
 *         -EINVAL if the argument is incorrect or UID is already assigned.
 *         -ENOMEM on lacking of memory.
 */
int ve_drv_assign_cr(struct ve_dev *vedev, struct ve_cr_assign *usr)
{
	int err;
	struct ve_cr_assign arg;
	struct ve_node *node = vedev->node;
	struct list_head *ptr;
	struct list_head *head;
	struct ve_kuid_list *uid_list;
	kuid_t arg_kuid;

	pdev_trace(vedev->pdev);

	err = copy_from_user(&arg, usr, sizeof(struct ve_cr_assign));
	if (err)
		return -EFAULT;
	arg_kuid = make_kuid(current_user_ns(), arg.owner_uid);
	if (!uid_valid(arg_kuid))
		return -EINVAL;

	if (arg.cr_page_num >= node->model_info.num_of_crpage ||
			arg.cr_page_num < 0) {
		pdev_dbg(vedev->pdev, "invalid CR entry\n");
		return -EINVAL;
	}
	head = &node->cr_map[arg.cr_page_num]->list;

	/* Check if the UID is already assigned to this CR page */
	mutex_lock(&node->crmap_mutex);
	list_for_each(ptr, head) {
		uid_list = list_entry(ptr, struct ve_kuid_list, list);
		if (uid_eq(uid_list->kuid, arg_kuid)) {
			pdev_dbg(vedev->pdev,
			"Specified UID is already assigned to the CR page\n");
			mutex_unlock(&node->crmap_mutex);
			return -EINVAL;
		}
	}

	uid_list = kmalloc(sizeof(struct ve_kuid_list), GFP_KERNEL);
	if (!uid_list) {
		mutex_unlock(&node->crmap_mutex);
		return -ENOMEM;
	}
	uid_list->kuid = arg_kuid;

	INIT_LIST_HEAD(&uid_list->list);
	list_add(&uid_list->list, head);

	mutex_unlock(&node->crmap_mutex);

	return 0;
}

/**
 * @brief Unassign all CR page from any UID
 *        This function is called via sysfs.
 *
 * @param[in] vedev: VE device structure
 */
void ve_drv_unassign_cr_all(struct ve_dev *vedev)
{
	struct ve_node *node = vedev->node;
	struct list_head *ptr, *n;
	struct list_head *head;
	struct ve_kuid_list *uid_list;
	int entry;

	pdev_trace(vedev->pdev);

	mutex_lock(&node->crmap_mutex);
	for (entry = 0; entry < node->model_info.num_of_crpage; entry++) {
		head = &node->cr_map[entry]->list;

		list_for_each_safe(ptr, n, head) {
			uid_list = list_entry(ptr, struct ve_kuid_list, list);
			list_del(&uid_list->list);
			kfree(uid_list);
			pdev_dbg(vedev->pdev,
				"UID %d is unassigned from CR page %d\n",
				from_kuid_munged(current_user_ns(),
					uid_list->kuid), entry);
		}
	}
	mutex_unlock(&node->crmap_mutex);
}

/**
 * @brief Unassign CR page from specific user ID
 *        This function is called via ioctl.
 *
 * @param[in] vedev: VE device structure
 * @param[in] usr: ioctl arguments. Do copy_from_user() before useing.
 *
 * @return 0 on success.
 *         -EINVAL if the argument is incorrect or UID is already assigned.
 */
int ve_drv_unassign_cr(struct ve_dev *vedev, struct ve_cr_assign *usr)
{
	int err;
	struct ve_cr_assign arg;
	struct ve_node *node = vedev->node;
	struct list_head *ptr, *n;
	struct list_head *head;
	struct ve_kuid_list *uid_list;
	kuid_t arg_kuid;

	pdev_trace(vedev->pdev);

	err = copy_from_user(&arg, usr, sizeof(struct ve_cr_assign));
	if (err)
		return -EFAULT;
	arg_kuid = make_kuid(current_user_ns(), arg.owner_uid);
	if (!uid_valid(arg_kuid))
		return -EINVAL;

	if (arg.cr_page_num >= node->model_info.num_of_crpage ||
			arg.cr_page_num < 0) {
		pdev_dbg(vedev->pdev, "invalid CR page\n");
		return -EINVAL;
	}
	head = &node->cr_map[arg.cr_page_num]->list;

	mutex_lock(&node->crmap_mutex);
	list_for_each_safe(ptr, n, head) {
		uid_list = list_entry(ptr, struct ve_kuid_list, list);
		if (uid_eq(uid_list->kuid, arg_kuid)) {
			list_del(&uid_list->list);
			kfree(uid_list);
			pdev_dbg(vedev->pdev,
				"UID %d is unassigned from CR page %d\n",
			       arg.owner_uid, arg.cr_page_num);
		}
	}
	mutex_unlock(&node->crmap_mutex);

	return 0;
}

/**
 * @brief Unassign all VE memory from any UID
 *        This function is called via sysfs.
 *
 * @param[in] vedev: VE device structure
 */
void ve_drv_unassign_vemem_all(struct ve_dev *vedev)
{
	struct ve_node *node = vedev->node;
	struct list_head *ptr, *n;
	struct list_head *head;
	struct ve_kuid_list *uid_list;
	int entry;

	pdev_trace(vedev->pdev);

	mutex_lock(&node->pcimap_mutex);
	for (entry = 0; entry < node->model_info.num_of_pciatb; entry++) {
		head = &node->mem_map[entry]->list;

		list_for_each_safe(ptr, n, head) {
			uid_list = list_entry(ptr, struct ve_kuid_list, list);
			list_del(&uid_list->list);
			kfree(uid_list);
			pdev_dbg(vedev->pdev,
				"UID %d is unassigned from PCIATB entry  %d\n",
			       from_kuid_munged(current_user_ns(),
						uid_list->kuid), entry);
		}
	}
	mutex_unlock(&node->pcimap_mutex);
}

/**
 * @brief Assign VE memory (Allowing BAR01 memory mapping) to specific user ID
 *
 * @param[in] vedev: VE device structure
 * @param[in] usr: ioctl arguments. Do copy_from_user() before useing.
 *
 * @return 0 on success.
 */
int ve_drv_assign_vemem(struct ve_dev *vedev, struct ve_pcimem_assign *usr)
{
	int err;
	struct ve_pcimem_assign arg;
	struct ve_node *node = vedev->node;
	struct list_head *ptr;
	struct list_head *head;
	struct ve_kuid_list *uid_list;
	kuid_t arg_kuid;

	pdev_trace(vedev->pdev);

	err = copy_from_user(&arg, usr, sizeof(struct ve_pcimem_assign));
	if (err)
		return -EFAULT;
	arg_kuid = make_kuid(current_user_ns(), arg.owner_uid);
	if (!uid_valid(arg_kuid))
		return -EINVAL;

	if (arg.pciatb_entry >= node->model_info.num_of_pciatb ||
			arg.pciatb_entry < 0) {
		pdev_err(vedev->pdev, "invalid PCIATB entry\n");
		return -EINVAL;
	}
	head = &node->mem_map[arg.pciatb_entry]->list;

	/* Check if the UID is already assigned to this PCIATB entry */
	mutex_lock(&node->pcimap_mutex);
	list_for_each(ptr, head) {
		uid_list = list_entry(ptr, struct ve_kuid_list, list);
		if (uid_eq(uid_list->kuid, arg_kuid)) {
			mutex_unlock(&node->pcimap_mutex);
			return 0;
		}
	}

	/* allocate new list and add to the head */
	uid_list = kmalloc(sizeof(struct ve_kuid_list), GFP_KERNEL);
	if (!uid_list) {
		mutex_unlock(&node->pcimap_mutex);
		return -ENOMEM;
	}
	uid_list->kuid = arg_kuid;

	INIT_LIST_HEAD(&uid_list->list);
	list_add(&uid_list->list, head);

	mutex_unlock(&node->pcimap_mutex);

	return 0;
}

/**
 * @brief Unassign VE memory from specific user ID
 *
 * @param[in] vedev: VE device structure
 * @param[in] usr: ioctl arguments. Do copy_from_user() before useing.
 *
 * @return 0 on success.
 */
int ve_drv_unassign_vemem(struct ve_dev *vedev, struct ve_pcimem_assign *usr)
{
	int err;
	struct ve_pcimem_assign arg;
	struct ve_node *node = vedev->node;
	struct list_head *ptr, *n;
	struct list_head *head;
	struct ve_kuid_list *uid_list;
	kuid_t arg_kuid;

	pdev_trace(vedev->pdev);

	err = copy_from_user(&arg, usr, sizeof(struct ve_pcimem_assign));
	if (err)
		return -EFAULT;
	arg_kuid = make_kuid(current_user_ns(), arg.owner_uid);
	if (!uid_valid(arg_kuid))
		return -EINVAL;

	if (arg.pciatb_entry >= node->model_info.num_of_pciatb ||
			arg.pciatb_entry < 0) {
		pdev_err(vedev->pdev, "invalid PCIATB entry\n");
		return -EINVAL;
	}
	head = &node->mem_map[arg.pciatb_entry]->list;

	mutex_lock(&node->pcimap_mutex);
	list_for_each_safe(ptr, n, head) {
		uid_list = list_entry(ptr, struct ve_kuid_list, list);
		if (uid_eq(uid_list->kuid, arg_kuid)) {
			list_del(&uid_list->list);
			kfree(uid_list);
			pdev_dbg(vedev->pdev,
				"UID %d is unassigned from PCIATB entry %d\n",
				arg.owner_uid, arg.pciatb_entry);
		}
	}
	mutex_unlock(&node->pcimap_mutex);

	return 0;
}

/**
 * @brief Clear EXSRAR target memory
 *        This function is called via ioctl
 *
 * @param[in] vedev: VE device structure
 * @param core_id: VE core ID
 *
 * @return 0 on success.
 *         -EINVAL if the argument is invalid or EXSRAR is not available.
 */
int ve_drv_reset_exsrar_mem(struct ve_dev *vedev, int core_id)
{
	struct ve_node *node = vedev->node;

	pdev_trace(vedev->pdev);

	if (core_id >= node->core_fls || core_id < 0)
		return -EINVAL;

	if (node->core[core_id]->exs != NULL)
		*(node->core[core_id]->exs) = 0;
	else
		return -EINVAL;

	return 0;
}

/**
 * @brief Check permission of the each command of ioctl
 *
 * @param cmd: ioctl command
 *
 * @return 0 if it is permitted to call.
 *         -EPERM if it is not permitted to call.
 */
static int ve_check_permission(const struct ve_dev *vedev, unsigned int cmd)
{
	int (*check)(const struct ve_dev *, unsigned int, int *);
	
	check= vedev->arch_class->ve_arch_ioctl_check_permission;
	if (check) {
		int handled = 0;
		int rv = check(vedev, cmd, &handled);
		if (handled)
			return rv;
	}

	/**
	 * VEDRV_CMD_WAIT_EXCEPTION is allowed to be called from anyone
	 */
	switch (cmd) {
	case VEDRV_CMD_WAIT_EXCEPTION:
		break;
	/* Other commands required ADMIN capability */
	default:
		if (!capable(CAP_SYS_ADMIN))
			return -EPERM;
		break;
	}

	return 0;
}

long ve_drv_cmd_vhva_to_vsaa(struct ve_dev *dev,
		struct ve_vp __user *uptr, int pindown)
{
	int ret;
	int type;
	struct ve_node *node = dev->node;

	ret = get_user(type, &uptr->type);
	if (ret)
		return -EFAULT;
	if (type < 0 || NR_PD_LIST <= type)
		return -EINVAL;

	mutex_lock(&node->page_mutex[type]);
	ret = vp_v2p_from_user((struct vp __user *)&uptr->vp_info, pindown,
			&node->hash_list_head[type]);
	mutex_unlock(&node->page_mutex[type]);

	return ret;
}

long ve_drv_cmd_vhva_to_vsaa_blk(struct ve_dev *dev,
		struct ve_vp_blk __user *uptr, int pindown)
{
	int ret;
	int type;
	struct ve_node *node = dev->node;

	ret = get_user(type, &uptr->type);
	if (ret)
		return -EFAULT;
	if (type < 0 || NR_PD_LIST <= type)
		return -EINVAL;

	mutex_lock(&node->page_mutex[type]);
	ret = vp_v2p_blk_from_user((struct vp_blk __user *)&uptr->vp_info,
				   pindown, &node->hash_list_head[type]);
	mutex_unlock(&node->page_mutex[type]);

	return ret;
}

long ve_drv_cmd_release_pd_page(struct ve_dev *dev,
		struct ve_vp_release __user *uptr, int all)
{
	int ret;
	int type;
	unsigned long addr;
	struct ve_node *node = dev->node;

	ret = get_user(type, &uptr->type);
	if (ret)
		return -EFAULT;
	if (type < 0 || NR_PD_LIST <= type)
		return -EINVAL;

	mutex_lock(&node->page_mutex[type]);
	if (all) {
		vp_page_release_all(&node->hash_list_head[type]);
		ret = 0;
	} else {
		ret = get_user(addr, &uptr->addr);
		if (ret)
			goto err;
		ret = vp_page_release(addr, &node->hash_list_head[type]);
	}
err:
	mutex_unlock(&node->page_mutex[type]);

	return ret;
}

long ve_drv_cmd_count_pd_page(struct ve_dev *dev,
		struct ve_vp_release __user *uptr)
{
	int ret;
	int type;
	struct ve_node *node = dev->node;

	pdev_trace(dev->pdev);

	ret = get_user(type, &uptr->type);
	if (ret)
		return -EFAULT;
	if (type < 0 || NR_PD_LIST <= type)
		return -EINVAL;

	mutex_lock(&node->page_mutex[type]);
	ret = vp_page_count_all(&node->hash_list_head[type]);
	mutex_unlock(&node->page_mutex[type]);

	return ret;
}


pid_t ve_drv_host_pid(struct ve_dev *dev, struct ve_get_host_pid *arg)
{
	int err;
	struct ve_get_host_pid tmp;
	struct ve_node *node = dev->node;
	struct task_struct *task = NULL;
	struct pid_namespace *namespace = NULL;
	pid_t pid;
	unsigned long flags;

	pdev_trace(dev->pdev);

	err = copy_from_user(&tmp, arg, sizeof(struct ve_get_host_pid));
	if (err)
		return -EFAULT;
	spin_lock_irqsave(&node->lock, flags);
	rcu_read_lock();

	/* find namespace from host_pid */
	task = pid_task(find_vpid(tmp.host_pid), PIDTYPE_PID);
	if(task == NULL){
		rcu_read_unlock();
		spin_unlock_irqrestore(&node->lock, flags);
		return -ESRCH;
	}
	if(task)
		get_task_struct(task);
	
	namespace = task_active_pid_ns(task);
	if(namespace == NULL){
		put_task_struct(task);
		rcu_read_unlock();
		spin_unlock_irqrestore(&node->lock, flags);
		return -ESRCH;
	}

	/* get pid */
	pid = pid_vnr(find_pid_ns(tmp.namespace_pid, namespace));
	if(pid == 0){
		put_task_struct(task);
		rcu_read_unlock();
		spin_unlock_irqrestore(&node->lock, flags);
		return -ESRCH;
	}

	put_task_struct(task);
	rcu_read_unlock();
	spin_unlock_irqrestore(&node->lock, flags);
	return pid;
}

long ve_drv_cmd_release_pd_page_blk(struct ve_dev *dev,
		struct ve_vp_blk_release __user *uptr)
{
	int ret;
	int npages, type;
	uint64_t *addr;
	uint64_t *addrs;
	uint64_t smallbuff[128];
	struct ve_node *node = dev->node;

	ret = get_user(type, &uptr->type);
	if (ret)
		return -EFAULT;
	ret = get_user(npages, &uptr->npages);
	if (ret)
		return -EFAULT;
	if (npages > VP_MAXBULK) {
		printk(KERN_ERR "ve_drv_cmd_release_pd_page_blk npages %d > %d\n",
		       npages, VP_MAXBULK);
		return -EINVAL;
	}
	/* avoid kmalloc for small buffers */
	if (npages < 128)
		addrs = smallbuff;
	else {
		addrs = kmalloc(npages * sizeof(uint64_t), GFP_KERNEL);
		if (!addrs) {
			printk(KERN_ERR "ve_drv_cmd_release_pd_page_blk "
			       "kmalloc failed. npages=%d\n", npages);
			return -ENOMEM;
		}
	}
	
	if (type < 0 || NR_PD_LIST <= type) {
		printk(KERN_ERR "ve_drv_cmd_release_pd_page_bulk type=%d\n", type);
		return -EINVAL;
	}
	ret = get_user(addr, &uptr->addr);
	if (ret)
		return -EFAULT;

	mutex_lock(&node->page_mutex[type]);
	ret = copy_from_user(addrs, (void __user *)addr,
			     npages * sizeof(uint64_t));
	if (ret)
		goto err;
	ret = vp_page_release_blk(addrs, npages, &node->hash_list_head[type]);

err:
	mutex_unlock(&node->page_mutex[type]);

	if (npages >= 128)
		kfree(addrs);
	return ret;
}

/**
 * @brief ioctl method of VE file operation
 *
 * @param[in] filp: file structure
 * @param cmd: ioctl command
 * @param arg: ioctl argument
 *
 * @return -EINVAL if the command is not defined.
 *         -ESRCH if required structure is already freed.
 *         -EPERM if it is not permitted to call.
 *         The rest of return value is depend on the command.
 */
long ve_drv_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	long ret;
	struct ve_task *task;
	struct ve_dev *vedev;
	struct ve_node *node;
	long (*arch_ioctl)(struct file *, struct ve_dev *, unsigned int, unsigned long, int *);

	if (filp->private_data == NULL)
		return -ESRCH;

	task = filp->private_data;
	vedev = task->vedev;
	node = vedev->node;

	pdev_trace(vedev->pdev);

	ret = ve_check_permission(vedev, cmd);
	if (ret)
		return ret;

	pdev_trace(vedev->pdev);

	arch_ioctl = vedev->arch_class->ve_arch_ioctl;
	if (arch_ioctl) {
		int handled = 0;
		ret = arch_ioctl(filp, vedev, cmd, arg, &handled);
		if (handled)
			return ret;
	}

	switch (cmd) {
	case VEDRV_CMD_WAIT_INTR:
		ret = ve_drv_wait_intr(vedev,
				(struct ve_wait_irq_arg __user *)arg);
		break;
	case VEDRV_CMD_WAIT_EXCEPTION:
		ret = ve_drv_wait_exception(filp, (uint64_t __user *)arg);
		break;
	case VEDRV_CMD_VHVA_TO_VSAA:
		ret = ve_drv_cmd_vhva_to_vsaa(vedev,
				(struct ve_vp  __user *)arg, 0);
		break;
	case VEDRV_CMD_VHVA_TO_VSAA_PIN_DOWN:
		ret = ve_drv_cmd_vhva_to_vsaa(vedev,
				(struct ve_vp __user *)arg, 1);
		break;
	case VEDRV_CMD_VHVA_TO_VSAA_BLK:
		ret = ve_drv_cmd_vhva_to_vsaa_blk(vedev,
				(struct ve_vp_blk  __user *)arg, 0);
		break;
	case VEDRV_CMD_VHVA_TO_VSAA_BLK_PIN_DOWN:
		ret = ve_drv_cmd_vhva_to_vsaa_blk(vedev,
				(struct ve_vp_blk __user *)arg, 1);
		break;
	case VEDRV_CMD_RELEASE_PD_PAGE:
		ret = ve_drv_cmd_release_pd_page(vedev,
				(struct ve_vp_release  __user *)arg, 0);
		break;
	case VEDRV_CMD_RELEASE_PD_PAGE_BLK:
		ret = ve_drv_cmd_release_pd_page_blk(vedev,
				(struct ve_vp_blk_release  __user *)arg);
		break;
	case VEDRV_CMD_RELEASE_PD_PAGE_ALL:
		ret = ve_drv_cmd_release_pd_page(vedev,
				(struct ve_vp_release __user *)arg, 1);
		break;
	case VEDRV_CMD_COUNT_PD_PAGE_ALL:
		ret = ve_drv_cmd_count_pd_page(vedev,
				(struct ve_vp_release __user *)arg);
		break;
	case VEDRV_CMD_CREATE_TASK:
		ret = ve_drv_add_ve_task(vedev, (pid_t)arg);
		break;
	case VEDRV_CMD_DELETE_TASK:
		ret = ve_drv_del_ve_task(vedev, (pid_t)arg);
		break;
	case VEDRV_CMD_ASSIGN_TASK:
		ret = ve_drv_assign_task_to_core(vedev,
				(struct ve_tid_core __user *)arg);
		break;
	case VEDRV_CMD_REVIVE_TASK:
		ret = ve_drv_revive_ve_task(vedev, (pid_t)arg);
		break;
	case VEDRV_CMD_ASSIGN_CR:
		ret = ve_drv_assign_cr(vedev,
				(struct ve_cr_assign __user *)arg);
		break;
	case VEDRV_CMD_UNASSIGN_CR:
		ret = ve_drv_unassign_cr(vedev,
				(struct ve_cr_assign __user *)arg);
		break;
	case VEDRV_CMD_ASSIGN_VEMEM:
		ret = ve_drv_assign_vemem(vedev,
				(struct ve_pcimem_assign __user *)arg);
		break;
	case VEDRV_CMD_UNASSIGN_VEMEM:
		ret = ve_drv_unassign_vemem(vedev,
				(struct ve_pcimem_assign __user *)arg);
		break;
	case VEDRV_CMD_RST_EXSRAR_MEM:
		ret = ve_drv_reset_exsrar_mem(vedev, (int)arg);
		break;
	case VEDRV_CMD_UNMAP:
		ret = ve_unmap_mapping(vedev, (struct ve_unmap __user *)arg);
		break;
	case VEDRV_CMD_DELETE_ALL_TASK:
		ret = ve_drv_del_all_task(vedev);
		break;
	case VEDRV_CMD_RST_INTR_COUNT:
		ret = ve_drv_reset_intr_count(vedev, (uint64_t)arg);
		break;
	case VEDRV_CMD_HOST_PID:
		ret = ve_drv_host_pid(vedev, (struct ve_get_host_pid *)arg);
		break;

	default:
		return -EINVAL;
	}

	return ret;
}
