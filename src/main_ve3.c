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
 * @file main_ve3.c
 * @brief VE3 specific part of VE driver main file
 */

#define _VE_ARCH_VE3_ (1)
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kmod.h>
#include <linux/moduleparam.h>
#include "ve_drv.h"
#include "hw.h"
#include "internal.h"
#include "mmio.h"

int wait_sec_ve_init_done=120;
module_param(wait_sec_ve_init_done, int, 0600);
MODULE_PARM_DESC(wait_sec_ve_init_done,
                 "This parameter is wait time HW init check.");


static int ve3_fill_hw_info(struct ve_dev *vedev)
{
	u32 data[VE3_VCR_SIZE];

	struct ve_node *node = vedev->node;
	struct ve_hw_info *info = &node->hw_info;

	int ret;
	ret = ve_drv_read_ve_config_regs(vedev, VE3_VCR_SIZE, data);
	if (ret != 0)
		return -EIO;
	ve_drv_set_model_type(&info->model_type, data[0]);

	info->num_of_core = (uint8_t)((data[1] & 0xff000000) >> 24);
	/* new configure registers */
	if( info->model_type.version == 2 ){
		info->core_enables = data[0x5] & 0xffffffff;
	} else{
		info->core_enables = data[0x1] & 0x00ffffff;
	}
	info->vmcfw_version = (uint16_t)(data[10] & 0x0000ffff);
	info->memory_size = (uint16_t)((data[11] & 0xffff0000) >> 16);
	info->memory_clock = (uint16_t)(data[11] & 0x0000ffff);
	info->core_clock = (uint16_t)((data[12] & 0xffff0000) >> 16);
	info->base_clock = (uint16_t)(data[12] & 0x0000ffff);

	info->chip_sn[0] = (uint64_t)data[2] << 32;
	info->chip_sn[0] |= (uint64_t)data[3];
	info->chip_sn[1] = (uint64_t)data[4];


	info->board_sn[0] = (uint64_t)data[6] << 32;
	info->board_sn[0] |= (uint64_t)data[7];
	info->board_sn[1] = (uint64_t)data[8] << 32;
	info->board_sn[1] |= (uint64_t)data[9];

	return 0;
}

static void ve3_fill_model_info(const struct ve_dev *vedev, \
			struct ve_model_info *model)
{
	model->num_of_crpage = VE3_CR_PAGE;
	model->num_of_pciatb = VE3_PCIATB_ENTRY;
	model->i_cache_size = 64; /* 64KB */
	model->d_cache_size = 64; /* 64KB */
	model->l2_cache_size = 512;  /* 512KB */
	model->l3_cache_size = 2 * 1024;  /*  2MB */
	model->llc_cache_size = 64 * 1024;  /* 64MB */

}

static int ve3_init_node(struct ve_dev *vedev, struct ve_node *node)
{
	struct ve3_archdep_data *data = node->ve_archdep_data;
	/* initialize intvec */
	data->cond.ve_wait_irq_type = VEDRV_IRQ_TYPE_VE3;
	memset(data->cond.intvec, 0, sizeof(data->cond.intvec));
	node->cond = (struct ve_wait_irq *)&data->cond;
	/* set ve_state */
	// node->ve_state = VE_ST_AVAILABLE;
	/* arch_hw_info has been filled here; was set on ve3_fill_hw_info(). */
	return 0;
}

static void ve3_fini_node(struct ve_dev *vedev, struct ve_node *node)
{
	kfree(node->cond);
	node->cond = 0;
}

static inline void ve3_clear_intvec(struct ve_dev *vedev)
{
	/* Clear interrupt mask register */
	ve_bar4_write64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET
			+ CREG_INTERRUPT_VECTOR0, ~0ULL);
	ve_bar4_write64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET
			+ CREG_INTERRUPT_VECTOR1, ~0ULL);
	ve_bar4_write64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET
			+ CREG_INTERRUPT_VECTOR2, ~0ULL);

	/*
	 * Does not reset the cause of the failure that occurred before the
	 * driver started. Later, when the MMM unmasks, the interrupt will
	 * be delivered.
	 */
#if 0
	ve_bar4_write64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET
			+ CREG_INTERRUPT_VECTOR3, ~0ULL);
#endif
}

static int ve3_init_post(struct ve_dev *vedev)
{
	ve3_clear_intvec(vedev);
	return 0;
}

static void *ve3_exsrar_addr(const struct ve_dev *vedev, int core_id)
{
	uint64_t exsrar_offset = (VEDRV_VE3_PCI_BAR4_CREG_SIZE * core_id) +
			VEDRV_VE3_PCI_BAR4_SREG_OFFSET + SREG_EXSRAR_OFFSET;
	return (char *)vedev->bar[4] + exsrar_offset;
}

/**
 * @brief Read EXS register value from MMIO space
 *
 * @param[in] vedev: VE device structure
 * @param core_id: VE core ID
 *
 * @return EXS value
 */
static uint64_t ve3_get_exs(struct ve_dev *vedev, int core_id)
{
	uint64_t exs;
	ve_bar4_read64(vedev, VEDRV_VE3_PCI_BAR4_CREG_SIZE * core_id
			+ UREG_EXS_OFFSET, &exs);
	return exs;
}

static void ve3_core_intr_cb(struct ve_dev *vedev, int core_id)
{
	/* Clear Interrupt Vector Register */
	ve_bar4_write64(vedev,
		VEDRV_VE3_PCI_BAR4_SCR_OFFSET + CREG_INTERRUPT_VECTOR0,
		(uint64_t)0x8000000000000000 >> core_id);
}

static void ve3_pdma_intr_cb(struct ve_dev *vedev, int entry)
{
	BUG_ON(entry != 32);
	((struct ve3_wait_irq *)vedev->node->cond)->intvec[1] |= 1;
}

static void ve3_udma_intr_cb(struct ve_dev *vedev, int entry)
{
	uint64_t intvec2;
        BUG_ON(entry != 33);
	//((struct ve3_wait_irq *)vedev->node->cond)->intvec[2] |= 0xffffffffffffffff;
	//N.B  ve_bar4_read64_sync()?
	//
	ve_bar4_read64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET
		       + CREG_INTERRUPT_VECTOR2,
		       &intvec2);
	// h/w format to s/w format
	((struct ve3_wait_irq *)vedev->node->cond)->intvec[2] |= ve_bitrev64( intvec2 );
}

static void ve3_pci_accs_intr_cb(struct ve_dev *vedev, int entry)
{
        uint64_t intvec1;
        uint64_t pciexc[2];
        pdev_trace(vedev->pdev);

        BUG_ON(entry != 34);
        // s/w 0x0000FFFF00000000
        // h/w 0x00000000FFFF0000
        //((struct ve3_wait_irq *)vedev->node->cond)->intvec[1] |= 0x0000FFFF00000000;
        ve_bar4_read64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET
                       + CREG_INTERRUPT_VECTOR1,
                       &intvec1);
        //only get PCI ACCESS EXCEPTION
        intvec1 &= 0x00000000FFFF0000;
        // h/w format to s/w format
        ((struct ve3_wait_irq *)vedev->node->cond)->intvec[1] |= ve_bitrev64( intvec1 );

        //get CAUSE of PCI ACCESS EXCEPTION
        ve_bar4_read64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET + 0x2400,
                &pciexc[0]);
        ve_bar4_read64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET + 0x2408,
                &pciexc[1]);
        pdev_dbg(vedev->pdev, "PCI access exception: PCIEXC=%016llx, %016llx\n",
                pciexc[0], pciexc[1]);
        if (panic_on_pci_access_exception) {
                panic("Panic due to PCI access exception.\n");
        }
#if 0
        if (vedev->veos) {
                int rv;
                int signo = SIGBUS;
                rv = send_sig(signo, vedev->veos, 1);
                if (rv < 0) {
                        pdev_err(vedev->pdev,
                                "Error on sending a signal to VEOS (%d)\n", rv);
                }
        } else {
                pdev_info(vedev->pdev, "VEOS process is not specified.\n");
        }
#endif
        /* Clear Interrupt Vector Register */
        if (clear_intvec_pci_access_exception) {
                ve_bar4_write64(vedev,
                        VEDRV_VE3_PCI_BAR4_SCR_OFFSET + CREG_INTERRUPT_VECTOR1,
                        0x0000000080000000UL);
        }
}

static void ve3_hw_intr_cb(struct ve_dev *vedev, int entry)
{
	uint64_t intvec3;
        BUG_ON(entry != 35);
	// s/w 0x00001FF7ffffffff
	// h/w 0xffffffffeff80000

	pdev_dbg(vedev->pdev, "HW Error occurred (Entry 35)\n");
        //((struct ve3_wait_irq *)vedev->node->cond)->intvec[3] |= 0x00001FF7ffffffff;
        ve_bar4_read64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET
                       + CREG_INTERRUPT_VECTOR3,
                       &intvec3);
        // h/w format to s/w format
        ((struct ve3_wait_irq *)vedev->node->cond)->intvec[3] |= ve_bitrev64( intvec3 );
}

static irqreturn_t ve3_intr(struct ve_dev *vedev, int entry)
{
	if (unlikely(entry < 0 || 35 < entry))
		return IRQ_HANDLED;

	if (unlikely(entry == 34)) {
		/* PCI ACCESS EXCEPTION */
                return ve_drv_generic_node_intr(vedev, entry, ve3_pci_accs_intr_cb);
	}

	if (unlikely(entry == 35)) {
		/* HW error */
                return ve_drv_generic_node_intr(vedev, entry, ve3_hw_intr_cb);
	}
	if (entry < 32 && likely(!hw_intr_test_param))
		/* core interrupt; core# == entry) */
		return ve_drv_generic_core_intr(vedev, entry, ve3_core_intr_cb);
	if (entry == 33) {
		/* USER DMA */
                return ve_drv_generic_node_intr(vedev, entry, ve3_udma_intr_cb);
	}
	if (entry == 32)
		/* PDMA */
		return ve_drv_generic_node_intr(vedev, entry, ve3_pdma_intr_cb);
	/* TODO: implement handlers of entry 33, 34 and 35. */
	BUG();
	return IRQ_HANDLED;
}

static void ve3_request_stop_all(struct ve_dev *vedev)
{
	struct ve_hw_info *info = &vedev->node->hw_info;
	off_t offset;
	int core_id, i;

	/* Stop PDMA */
	offset = VEDRV_VE3_PCI_BAR4_SCR_OFFSET + CREG_DMACTLP_OFFSET;
	ve_bar4_write64(vedev, offset, DMACTL_DISABLE_PERMIT);

	/* Stop cores */
	for (core_id = 0; core_id < vedev->node->core_fls; core_id++) {
		if (!(info->core_enables & (1 << core_id)))
			continue;

                /* Set core register offset */
		offset = UREG_EXS_OFFSET +
		  VEDRV_VE3_PCI_BAR4_CREG_SIZE * core_id;

		/* STOP the core */
		ve_bar4_write64(vedev, offset, EXS_STATE_STOP);
	}

	/* STOP user DMA */
	for (i = 0; i < VE3_DMADESU_NUM_IMPLEMENTED; ++i) {
		ve_bar4_write64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET +
			CREG_DMACTLU_OFFSET(i), DMACTL_DISABLE_PERMIT);
	}
}

static int ve3_check_stopped(struct ve_dev *vedev)
{
	struct ve_hw_info *info = &vedev->node->hw_info;
	off_t offset;
	int core_id, i;
	uint64_t regdata;

	/* PDMA */
	offset = VEDRV_VE3_PCI_BAR4_SCR_OFFSET + CREG_DMACTLP_OFFSET;
	ve_bar4_read64(vedev, offset, &regdata);
	if (!(regdata & DMACTL_HALT_MASK)){
		pdev_dbg(vedev->pdev , "PDMA does not stop yet %llx\n",regdata);
		return 0; /* PDMA does not stop yet */
	}
	/* cores */
	for (core_id = 0; core_id < vedev->node->core_fls; core_id++) {
		if (!(info->core_enables & (1 << core_id)))
			continue;
		/* Set core register offset */
		offset = UREG_EXS_OFFSET +
			+ VEDRV_VE3_PCI_BAR4_CREG_SIZE * core_id;
		ve_bar4_read64(vedev, offset,&regdata);
		if (regdata & EXS_STATE_RUN){
			pdev_dbg(vedev->pdev , "core_id %d is running yet \n", core_id);
			return 0;/* core #core_id is running yet */
		}
	}
	/* user DMA */
	for (i = 0; i < VE3_DMADESU_NUM_IMPLEMENTED; ++i) {
		ve_bar4_read64(vedev, VEDRV_VE3_PCI_BAR4_SCR_OFFSET +
			CREG_DMACTLU_OFFSET(i), &regdata);
		if (!(regdata & DMACTL_HALT_MASK)){
			pdev_dbg(vedev->pdev , "UDMA %i does not stopped yet\n", i);
			return 0; /* UDMA#i does not stopped yet */
		}
	}
	pdev_dbg(vedev->pdev , "CHECK STOP OK\n");
	return 1;
}

static int ve3_wait_hw_identifier( struct ve_dev *vedev , int sec, int notify)
{
	u32 data[VE3_VCR_SIZE];
	int ret;
	int sec_count=0;

	do {
 		ret = ve_drv_read_ve_config_regs(vedev, VE3_VCR_SIZE, data);
		if (ret != 0)
			return -EIO;
		/* check INIT FAIL BIT */
		if ( data[10] & 0x20000000 ){
			if ( data[10] & 0x10000000 ){
				pdev_err(vedev->pdev , "HW init check fail(4)\n");
			}else{
				pdev_err(vedev->pdev , "HW init check fail(2)\n");
			}
			ret = -EIO;
			goto  init_fail;
		}
		/*
		 * check init DONE bit( This point, INIT FAIL=0 )
		 */
		if ( data[10] & 0x10000000 ){
			/*
			 * get NUMAMODE bit
			 */
		  if( notify != -1) {
			vedev->node->partitioning_mode =
				(uint8_t)((data[10] & 0x80000000) >> 31);
		  }
		  if( notify != 0)
		    pdev_info(vedev->pdev , "HW init check OK (%d)\n", sec_count);

		  return 0;
		}
		if( notify != 0 &&  sec_count % 10 == 0 )
		  pdev_dbg(vedev->pdev , "HW init check try %d\n", sec_count);
		sec_count++;
		ssleep(1);

	} while(sec_count < sec );
	if( notify != 0)
	  pdev_err(vedev->pdev , "HW init check timeout (%dsec)\n",sec_count);
	ret = -ETIME;
 init_fail:
	/*
	 * get NUMAMODE bit
	 */
	if( notify != -1) {
	  vedev->node->partitioning_mode =
	    (uint8_t)((data[10] & 0x80000000) >> 31);
	  vedev->node->ve_state = VE_ST_UNAVAILABLE;
	  if ( notify )
	    sysfs_notify(&vedev->device->kobj, NULL, "ve_state");
	}
	return ret;
}

static int ve3_check_config_test(struct ve_dev *vedev, int notify)
{
        int rv;
	char *numa_s[2] ={"0","1"};
	int ret = 0;
	char ve_minor[4];
	char *argv[5];

        char *envp[] = {
                "HOME=/",
                "PATH=/sbin:/bin:/usr/sbin:/usr/bin",
                NULL,
        };

	snprintf(ve_minor, sizeof(ve_minor), "%d",vedev->minor );

	argv[0] = "ve_check_config";
	argv[1] = (char *) dev_name(&vedev->pdev->dev);    /* domain:bas:function */
	argv[2] = ve_minor;                                /* N of /dev/veN */
	argv[3] = numa_s[vedev->node->partitioning_mode];  /* config register numa bit */
	argv[4] = NULL;

        rv = call_usermodehelper(
				 "/opt/nec/ve/veos/libexec/ve_check_config",
				 argv, envp, UMH_WAIT_PROC);
	/*
	 * caller must mutex lock
	 */
        if (rv == 0) {
                vedev->node->ve_state = VE_ST_AVAILABLE;
		pdev_info(vedev->pdev,
			  "Numa H/W setting check OK\n");

	} else {
                vedev->node->ve_state = VE_ST_MAINTENANCE;
		pdev_err(vedev->pdev,
			 "Numa H/W setting is different from configuration (%d)\n",
			 rv);
		ret = -EINVAL;
	}
	/*
	 * notfy to MMM etc.
	 */
	if ( notify )
		sysfs_notify(&vedev->device->kobj, NULL, "ve_state");
	return ret;
}

/**
 * when this function is called, vedev->node->sysfs_mutex is held.
 */
static int ve3_ve_state_transition(struct ve_dev *vedev,
		unsigned long cur_state, unsigned long new_state)
{
	if (new_state == VE_ST_AVAILABLE)
		ve3_clear_intvec(vedev);
	return 0;
}

static inline void do_ve3_card_reset(struct ve_dev *vedev)
{

	/* (1) Issue VE_Card Reset request */
	uint64_t val;
        ve_bar4_write64(vedev,0x00500198, 0x000000D8000000C0);
        ve_bar4_write64(vedev,0x00500190, 0x8800000000200002);
        ve_bar4_read64(vedev,0x00500000,&val);

	/* (2) Cancel Interrupt settings */
        ve_bar4_write64(vedev,0x00510050, 0xffffc00000000000);
	ve_bar4_write64(vedev,0x00510070, 0x8000000080000000);
	ve_bar4_write64(vedev,0x00510090, 0xfffffffff0000000);
	ve_bar4_write64(vedev,0x005100b0, 0xffffc000eff80000);

	/* Stop (1) from overtakaking */
	ssleep(1);

	/* (3) VE Card reset */
	ve_bar4_write64(vedev, 0x00500198, 0x0000020000000200);
	ve_bar4_write64(vedev, 0x00500190, 0x8800000000200052);
#if 0
	/* (4) */
	/* disable, because, caller ssleep() */
	ssleep(1);
#endif
}

static int ve3_recover_from_chip_reset(struct ve_dev *vedev, u16 *aer_cap,
		int enable_irq, int fw_update, int sbr)
{
	int err;
	struct ve3_wait_irq *cond;

	pdev_trace(vedev->pdev);

	/* Restore PCI config and link retrain to link with Gen3 */

	err = ve_recover_from_link_down(vedev, aer_cap, fw_update, sbr);
	if (err)
		return err;
	/* Enable MSI-X */
	if (enable_irq) {
		cond = (struct ve3_wait_irq *)vedev->node->cond;
		/* clear all pending interrupt bits in driver */
		cond->intvec[0]=0;
		cond->intvec[1]=0;
		cond->intvec[2]=0;
		cond->intvec[3]=0;

		err = ve_drv_enable_irqs(vedev);
		if (err)
			return err;
	}
	return 0;
}

/*
 * FIXME. pcie_has_flr and pcie_flr function are changed frequently.
 *        so check internaly
 * 4.18.0    : int pcie_flr(struct pci_dev *dev)
 * 4.12      : int pcie_flr(struct pci_dev *dev)
 * 4.11      : int pcie_flr(struct pci_dev *dev, int probe)
 * 3.19.8    : int pcie_flr(struct pci_dev *dev, int probe)
 * 3.10.108  : int pcie_flr(struct pci_dev *dev, int probe)
 * 3.10.1    : int pcie_flr(struct pci_dev *dev, int probe)
 * 3.10.0-957: void pcie_flr(struct pci_dev *dev)
 *
 */

static bool ve_drv_ve3_pcie_has_flr(struct pci_dev *dev)
{
	u32 cap;

	if (dev->dev_flags & PCI_DEV_FLAGS_NO_FLR_RESET)
		return false;

	pcie_capability_read_dword(dev, PCI_EXP_DEVCAP, &cap);
	return cap & PCI_EXP_DEVCAP_FLR;
}

int ve3_init_hw_check(struct ve_dev *vedev, int notify)
{
	int err;
	int sensor_num;
	/*
	 * wait hw init complete and get numamode
	 */
	err = ve3_wait_hw_identifier(vedev, wait_sec_ve_init_done, notify);

	if(err)
		goto err_state;
	/*
	 * call MMM check using usermode
	 */
	err = ve3_check_config_test(vedev, notify);

 err_state:

	if( notify == 0) {
	  for (sensor_num = 0;
	       sensor_num < vedev->arch_class->num_sensors;
	       sensor_num++)
	    vedev->node->sensor_rawdata[sensor_num] = 0xffffffff;
	}
	return err;
}

int ve3_init_early(struct ve_dev *vedev)
{
  return ve3_wait_hw_identifier(vedev, wait_sec_ve_init_done, -1);
}


int ve3_init_hw_check_early(struct ve_dev *vedev)
{
  return ve3_init_hw_check(vedev, 0);

}

int ve_drv_ve3_reset(struct ve_dev *vedev, uint64_t reset_level)
{
	int irq = 1;
	int err = 0;
	int retry=0;
#if (KERNEL_VERSION(3, 10, 0) != LINUX_VERSION_CODE)
	int check_err=0;
#endif
	u16 aer_cap;
	int core_id;
	struct ve_node *node;
	/*
	 * ve3 is always 0 not update fw
	 */
	int update_only = 0;

	mutex_lock(&vedev->node->sysfs_mutex);

	node = vedev->node;

	if (vedev->node->os_state != OS_ST_OFFLINE) {
		err = -EAGAIN;
		goto err_state;
	}
	if ( reset_level > 2){
		err = -EINVAL;
		goto err_state;
	}

	if (reset_level == 2){
		if( !ve_drv_ve3_pcie_has_flr(vedev->pdev) ){
			pdev_err(vedev->pdev, "Not support PCIe function level reset\n");
			err = -EINVAL;
			goto err_state;
		}
	}

	/* !Card Reset*/
	if (reset_level != 0)
		irq = 0;

	err = ve_prepare_for_chip_reset(vedev, &aer_cap, irq, reset_level);

	if (err)
		goto err_state;

	switch( reset_level ){
	case 0:
		pdev_info(vedev->pdev, "Reset VE Card\n");
		do_ve3_card_reset(vedev);
		break;
	case 1:
		pdev_info(vedev->pdev->bus->self, "Reset Secondary Bus\n");

#if (KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE)
		pci_reset_bridge_secondary_bus(vedev->pdev->bus->self);
#else
		pci_bridge_secondary_bus_reset(vedev->pdev->bus->self);
#endif
		break;
	case 2:
		pdev_info(vedev->pdev, "Reset function\n");

#if (KERNEL_VERSION(3, 10, 0) == LINUX_VERSION_CODE)
		/*
		 * for RHEL7
		 */
		pcie_flr(vedev->pdev);
		pdev_info(vedev->pdev, "Reset check \n");
#else

#if (KERNEL_VERSION(4, 12, 0) <= LINUX_VERSION_CODE)
		check_err = pcie_flr(vedev->pdev);
#else
		/* FIXME.
		 * from 3.10.1 to 4.11.xx
		 */
		check_err = pcie_flr(vedev->pdev,0);
#endif
		pdev_info(vedev->pdev, "Reset check %d\n", check_err);
#endif
		break;
	}
        /* Wait wait_after_vereset_sec sec */
        do {
                ssleep(1);
                err = ve_check_pci_link(vedev->pdev);
        } while( ++retry < wait_after_vereset_sec && err );

        if(err){
                pdev_err(vedev->pdev, "Waited for %d seconds, but VE RESET failed\n", retry);
	}

	err = ve3_recover_from_chip_reset(vedev, &aer_cap, irq, update_only, reset_level);
	if(err)
		goto err_state;
	/*
	 * wait for init done flag to reinit
	 */
	ssleep(10);
	/*
	 * wait hw init complete and get numamode
	 */
	err = ve3_init_hw_check(vedev, 1);
	if(err)
		goto err_state;

	ve3_clear_intvec(vedev);

        for (core_id = 0; core_id < vedev->node->core_fls; core_id++) {
               node->core[core_id]->exs = &(vedev->vdma_addr[core_id]);
        }
        err = ve_init_exsrar(vedev);
 err_state:

	mutex_unlock(&vedev->node->sysfs_mutex);
	return err;
}

static const struct ve_arch_class vedrv_ve3_arch_class = {
	.name = VE_DRV_ARCH_NAME_VE3,
	.expected_bar_mask = 0x15, /* BAR01, 23, and 4 */
	.max_core_num = VE3_MAX_CORE_NUM,
	/*
	 * VE3 sensor 0  not use. +1 is for array access.
	 */
	.num_sensors = 42+1, /* May be fix */
	.init_early  = ve3_init_early,
	.fini_late = 0,
	.init_hw_check = ve3_init_hw_check_early,
	.fill_hw_info = ve3_fill_hw_info,
	.fill_model_info = ve3_fill_model_info,
	.init_node = ve3_init_node,
	.fini_node = ve3_fini_node,
	.init_post_node = 0,
	.init_post_core = ve3_init_post,
	.exsrar_addr = ve3_exsrar_addr,
	.get_exs = ve3_get_exs,
	.ve_arch_ioctl_check_permission = ve_drv_ve3_ioctl_check_permission,
	.ve_arch_ioctl = ve_drv_ve3_arch_ioctl,
	.ve_arch_intr = ve3_intr,
	.ve_irq_type = VEDRV_IRQ_TYPE_VE3,
	.ve_wait_irq_size = sizeof(struct ve3_wait_irq),
	.ve_arch_wait_intr = ve_drv_ve3_wait_intr,
	.core_intr_undelivered = ve_drv_ve3_core_intr_undelivered,
	.ve_arch_map_range_offset = ve_drv_ve3_map_range_offset,
	.permit_to_map = ve_drv_ve3_permit_to_map,
	.request_stop_all = ve3_request_stop_all,
	.check_stopped = ve3_check_stopped,
	.ve_state_transition = ve3_ve_state_transition,
	.ve_arch_release = ve3_ve_release,
	.ve_arch_sysfs_attr_groups = ve_drv_ve3_attribute_groups,

	.ve_archdep_size = sizeof(struct ve3_archdep_data),
};

const struct ve_arch_class *ve_arch_probe_ve3(struct ve_dev *vedev)
{
	struct pci_dev *pdev = vedev->pdev;
	int ret;
	struct ve_model_type info;

	pdev_trace(pdev);
	/* Emulator Environment */
	if (PCI_VENDOR_ID_VE3 == pdev->vendor &&
		PCI_DEVICE_ID_VE3_EMULATOR == pdev->device) {
		/* On Emulator, config values are not checked. */
		ret = ve_drv_read_model_type(vedev, &info);
		if (ret == 0)
			return &vedrv_ve3_arch_class;
		else
			return NULL;
	}
#if 0
	/* Device ID of VE3 == that of VE1 */
	if (PCI_VENDOR_ID_VE3 != pdev->vendor ||
		PCI_DEVICE_ID_VE1 != pdev->device) 
		return NULL;
#endif
	ret = ve_drv_read_model_type(vedev, &info);
	if (ret)
		return NULL;

	/* check header version */
	if (info.version != 1 &&  info.version != 2) {
		return NULL;
	}
	/* check model and cpu version */
	if (info.model != 3 || info.cpu_version != 1) {
		return NULL;
	}
	return &vedrv_ve3_arch_class;
}
