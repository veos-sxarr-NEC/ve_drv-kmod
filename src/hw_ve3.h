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
 * @file hw_ve3.h
 * @brief Header for VE3 Hardware information
 */

#ifndef VE_HW_VE3_H_INCLUDE_
#define VE_HW_VE3_H_INCLUDE_

#define VE3_MAX_CORE_NUM	(32)
#define VE3_CR_PAGE (32)
#define VE3_DMADESU_NUM (64)
#define VE3_DMADESU_NUM_IMPLEMENTED (36)

#define VE3_PCIATB_ENTRY (4096) /* FIX for 256G with PCIATB 64M */

#define CR_BAR3_OFFSET(cr_page_num, cr_page_size) \
	(cr_page_num * 2 * cr_page_size)
#define VEMEM_BAR01_OFFSET(pciatb_entry_num, pciatb_page_size) \
	(pciatb_entry_num * pciatb_page_size)

/* interrupt mask */
static inline int is_dma_interrupt(const struct ve3_wait_irq *irq) {
	return (irq->intvec[1] & 1) || (irq->intvec[2] != 0);
}

/* PCI config */
#define VE3_VCR_SIZE				(13) /* !< 32bits * 13 */

/* Core User Registers (BAR4) */
#define UREG_EXS_OFFSET				(0x0000)

/* Core System Registers (BAR4) */
#define SREG_EXSRAR_OFFSET			(0x0000)

/* System Common Registers (BAR4) */
#define CREG_SYNC_OFFSET			(0x8)
#define CREG_DMACTLP_OFFSET			(0xA000)
#define CREG_DMACTLU_OFFSET(n)	(0x50000 + 0x10* ((n) & 1) + 0x1000 * ((n) >> 1))
#define CREG_INTERRUPT_VECTOR0			(0x2000)
#define CREG_INTERRUPT_VECTOR1			(0x2008)
#define CREG_INTERRUPT_VECTOR2			(0x2010)
#define CREG_INTERRUPT_VECTOR3			(0x2018)
#define CREG_CR_SET_OFFSET(n)			(0x80000 + n * 0x2000)
#define CREG_CR_AREA_SIZE			(0x40000)
/* System Common Registers (BAR23) */
#define CREG_PCIATB_OFFSET			(0x0)
#define CREG_PCIATBA_OFFSET			(0x10000)

/* Register values, etc */
#define EXS_STATE_RUN				(0x2)
#define EXS_STATE_STOP				(0x1)
#define EXS_EXCEPTION_MASK			(0xFFFFFFFFFF000000)
#define DMACTL_DISABLE_PERMIT			(0x0)
#define DMACTL_HALT_MASK			(0x2)
#define PCIATB_2M_PAGE				(0x200000)
#define PCIATB_64M_PAGE				(0x4000000)

/* Non SVR registers (BAR2) data */
#define GS_CHIP_RESET_DATA			(0x0000000000000100)

/* NUMA enable cores, etc */
/* TODO: fix */
#define NUMA0_CORES	(0x1f)
#define NUMA1_CORES	(0x3e0)
#define NUMA0_CORES_H2	(0x1ff)
#define NUMA1_CORES_H2	(0x3fe00)

#define NUMA_MEM_BLOCK_SIZE	(0x4000000)
#define FIRST_MEM_NODE	(0)

#endif /* VE_HW_VE3_H_INCLUDE_ */
