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
 * @file hw.h
 * @brief Header for VE Hardware information
 */

#ifndef VE_HW_H_INCLUDE_
#define VE_HW_H_INCLUDE_

/* VID, DID */
#define PCI_VENDOR_ID_VE3	(0x1bcf)
#define PCI_DEVICE_ID_VE3_EMULATOR	(0x1000)
#define PCI_DEVICE_ID_VE3	(0x0039)
#define PCI_VENDOR_ID_VE1	(0x1bcf)
#define PCI_DEVICE_ID_VE1	(0x001c)

/* AER Flag */
#define PCI_EXP_AER_FLAGS       (PCI_EXP_DEVCTL_CERE | PCI_EXP_DEVCTL_NFERE | \
		PCI_EXP_DEVCTL_FERE | PCI_EXP_DEVCTL_URRE)

#define VEMEM_BAR01_OFFSET(pciatb_entry_num, pciatb_page_size) \
	(pciatb_entry_num * pciatb_page_size)


/* PCI config */
#define PCI_CONFIG_VE_CONFIG_REGS_OFFSET	(0xf00)

/* Register values, etc */
#define EXS_STATE_RUN				(0x2)
#define EXS_STATE_STOP				(0x1)
#define EXS_EXCEPTION_MASK			(0xFFFFFFFFFF000000)
#define EXS_RDBG                                (0x0000000000800000ULL)
#define EXS_INTB_INTH                           (0x000000000000000CULL)
#define DMACTL_DISABLE_PERMIT			(0x0)
#define DMACTL_HALT_MASK			(0x2)
#define PCIATB_2M_PAGE				(0x200000)
#define PCIATB_64M_PAGE				(0x4000000)

#endif /* VE_HW_H_INCLUDE_ */
