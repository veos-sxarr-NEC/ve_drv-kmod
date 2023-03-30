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
 * @file hw_ve1.h
 * @brief Header for VE1 Hardware information
 */

#ifndef VE_HW_VE1_H_INCLUDE_
#define VE_HW_VE1_H_INCLUDE_

#define VE1_MAX_CORE_NUM	(10)
#define VE1_CR_PAGE (32)
#define VE1_PCIATB_ENTRY (1024)

/* VE model */
#define MODEL_VE1			(0x01)
#define MODEL_VE2			(0x02)
#define QEMU_MODEL_0			(0xFE)

#define CR_BAR3_OFFSET(cr_page_num, cr_page_size) \
	(cr_page_num * 2 * cr_page_size)
#define VEMEM_BAR01_OFFSET(pciatb_entry_num, pciatb_page_size) \
	(pciatb_entry_num * pciatb_page_size)

/* interrupt mask */
#define DMA_INTERRUPT_VECTOR_MASK	(0x1ffffffff0000)

/* PCI config */
#define VE1_VCR_SIZE				(13) /* !< 32bits * 13 */

/* Core User Registers */
#define UREG_EXS_OFFSET				(0x1008)

/* Core System Registers */
#define SREG_DMACTLH_OFFSET			(0x22000)
#define SREG_DMACTLE_OFFSET			(0x22010)
#define SREG_EXSRAR_OFFSET			(0x10900)

/* System Common Registers */
#define CREG_SYNC_OFFSET			(0x8)
#define CREG_DMACTLP_OFFSET			(0x42000)
#define CREG_PCIATB_OFFSET			(0x60000)
#define CREG_PCIATBA_OFFSET			(0x70000)
#define CREG_INTERRUPT_VECTOR			(0x2000)
/* System Common Registers (BAR23) */

/* Register values, etc */
#define EXS_STATE_RUN				(0x2)
#define EXS_STATE_STOP				(0x1)
#define EXS_EXCEPTION_MASK			(0xFFFFFFFFFF000000)
#define DMACTL_DISABLE_PERMIT			(0x0)
#define DMACTL_HALT_MASK			(0x2)
#define PCIATB_2M_PAGE				(0x200000)
#define PCIATB_64M_PAGE				(0x4000000)

/* Non SVR registers (BAR2) offset */
#define LINK_DOWN_EIF_INH_OFFSET		(0x01484C00)

/* Non SVR registers (BAR2) data */
#define GS_CHIP_RESET_DATA			(0x0000000000000100)
#define LINK_DOWN_EIF_INH_DATA			(0x00A9700000000000)

/* NUMA enable cores, etc */
#define NUMA0_CORES	(0x1f)
#define NUMA1_CORES	(0x3e0)
#define NUMA_MEM_BLOCK_SIZE	(0x4000000)
#define FIRST_MEM_NODE	(0)

#endif /* VE_HW_VE1_H_INCLUDE_ */
