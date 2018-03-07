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
 * @file firmware.c
 * @brief VE driver firmware loading.
 */

#include <linux/firmware.h>
#include <linux/jiffies.h>
#include "ve_drv.h"
#include "internal.h"

#define FW_VE_SBUS_00	"fw_ve_sbus_00.bin"
#define FW_VE_SDES_00	"fw_ve_sdes_00.bin"

static uint64_t dummy_read(struct ve_dev *vedev)
{
	uint64_t read_data;

	ve_bar2_read64(vedev, 0x01400000, &read_data);

	return read_data;
}

static void wait_nsec(struct ve_dev *vedev, int nsec)
{
	uint64_t dummy;

	dummy = dummy_read(vedev);
	ndelay(nsec);

	pdev_dbg(vedev->pdev, "Dummy read (0x%llx)\n", dummy);
}

static inline void start_sbus_command(struct ve_dev *vedev)
{
	ve_bar2_write64(vedev, 0x01420170, 0x0200000000000000);
}

static inline void finish_sbus_command(struct ve_dev *vedev)
{
	ve_bar2_write64(vedev, 0x01440170, 0x0200000000000000);
}

static inline int check_completion_base(struct ve_dev *vedev,
					int action_number, int repeat,
					int delay_nsec, uint64_t check_addr,
					uint64_t check_data,
					uint64_t check_mask)
{
	int i;
	uint64_t read_data;

	for (i = 0; i < repeat; i++) {
		wait_nsec(vedev, delay_nsec);

		ve_bar2_read64_sync(vedev, check_addr, &read_data);
		if ((read_data & check_mask) == check_data)
			return 0;
	}

	pdev_dbg(vedev->pdev, "FW loading step %d failed (0x%llx)\n",
			action_number, read_data);
	return -1;
}

static inline int check_sbus_done_deassertion(struct ve_dev *vedev,
		int action_number)
{
	return check_completion_base(vedev, action_number, 2, 0,
			0x01400178, 0, 0x9000);

}

/**
 * @return
 *      0 : read was done okay and an valid data was returned (good enough)
 *     -1 : read was okay but an invalid data came back (retry one time)
 *     -2 : read action itself was incomplete (should instantly abort)
 */
static inline int check_completion_base1(struct ve_dev *vedev,
		int action_number, int repeat, int delay_nsec,
		uint64_t check_addr, uint64_t check_data,
		uint64_t check_mask,
		uint64_t check_data2, uint64_t check_mask2)
{
	int i;
	uint64_t read_data;

	for (i = 0; i < repeat; i++) {
		wait_nsec(vedev, delay_nsec);

		ve_bar2_read64_sync(vedev, check_addr, &read_data);
		if ((read_data & check_mask2) == check_data2)
			goto cmd_successfully_established1;
	}

	pdev_dbg(vedev->pdev, "FW loading step %d failed (0x%llx)\n",
			action_number, read_data);
	return -2;

cmd_successfully_established1:
	if ((read_data & check_mask) == check_data)
		return 0;
	return -1;
}

/**
 * @return
 *       0 : read was done okay and an valid data was returned (good enough)
 *      -1 : read was okay but an invalid data came back (retry one time)
 *      -2 : read action itself was incomplete (should instantly abort)
 */
static inline int check_completion_base2(struct ve_dev *vedev,
		int action_number, int repeat, int delay_nsec,
		uint64_t check_addr, uint64_t check_data,
		uint64_t check_mask, uint64_t write_data,
		uint64_t check_data2, uint64_t check_mask2)
{
	int i, err;
	uint64_t read_data;

	ve_bar2_write64(vedev, 0x01400170, write_data);
	start_sbus_command(vedev);

	for (i = 0; i < repeat; i++) {
		/* Check preparation for swap */
		wait_nsec(vedev, delay_nsec);
		/* Check SBus command completion */
		ve_bar2_read64_sync(vedev, check_addr, &read_data);

		if ((read_data & check_mask2) == check_data2)
			goto cmd_successfully_established2;
	}

	pdev_dbg(vedev->pdev, "FW loading step %d failed (0x%llx)\n",
			action_number, read_data);
	return -2;

cmd_successfully_established2:
	finish_sbus_command(vedev);
	err = check_sbus_done_deassertion(vedev, 225);
	if (err) {
		pdev_dbg(vedev->pdev,
				"check_sbus_done_deassertion failed\n");
		return -2;
	}

	if ((read_data & check_mask) == check_data)
		return 0;
	return -1;
}

static inline int check_sbus_command_completion(struct ve_dev *vedev,
		int action_number)
{
	return check_completion_base1(vedev, action_number, 4, 5000,
			0x01400178, 0x0000000000009100, 0x9700,
			0x9000, 0x9000);
}

static inline int check_sbus_command_completion2(struct ve_dev *vedev,
		int action_number, uint64_t write_data)
{
	return check_completion_base2(vedev, action_number, 4, 5000,
			0x01400178, 0x0000000000129400, 0xFFFFFFFF9700,
			write_data, 0x9000, 0x9000);
}

static inline int check_interrupt_progress(struct ve_dev *vedev,
		int action_number)
{
	return check_completion_base(vedev, action_number, 4, 5000,
			0x0148CD88, 0x00000F0F00000F0F, 0x00000F0F00000F0F);
}

static inline int check_interrupt_progress2(struct ve_dev *vedev,
		int action_number)
{
	return check_completion_base(vedev, action_number, 4, 5000,
			0x0148CD88, 0x0, 0xF0F00000F0F);
}

static int sbus_command(struct ve_dev *vedev, int action_number)
{
	int err;
	int i;

	for (i = 0; i < 2; i++) {
		start_sbus_command(vedev);

		err = check_sbus_command_completion(vedev, action_number + 2);
		if (err == -2)
			goto sbus_command_failed;

		finish_sbus_command(vedev);
		err = check_sbus_done_deassertion(vedev, action_number + 4);
		if (err) {
			pdev_dbg(vedev->pdev,
				"check_sbus_done_deassertion failed.\n");
			return -1;
		}

		if (err == 0)
			goto sbus_command_success;
	}
sbus_command_failed:
	pdev_dbg(vedev->pdev, "check_sbus_command_completion failed.\n");
	return -1;
sbus_command_success:

	return 0;
}

static int fw_download_in_burst_mode(struct ve_dev *vedev, uint16_t *rom,
		ssize_t size, uint32_t upper_32bits)
{
	int i = 0;
	int err;
	int action_number;
	uint32_t x, y, z;
	uint32_t aa;
	uint64_t write_data;

	if (upper_32bits == 0x0021FD14)
		action_number = 160;
	else
		action_number = 240;

	while (i * sizeof(uint16_t) < size) {
		/* FW download in burst mode */
		z =  rom[i++] & 0x03FF;
		if (!(i * 16 < size)) {
			aa = 0x1;
			y = 0;
			x = 0;
			goto make_data;
		}
		y =  rom[i++] & 0x03FF;
		if (!(i * 16 < size)) {
			aa = 0x2;
			x = 0;
			goto make_data;
		}
		x =  rom[i++] & 0x03FF;
		aa = 0x3;
make_data:
		write_data = (uint64_t)upper_32bits << 32 |
			(aa << 30) | (x << 20) | (y << 10) | z;
		ve_bar2_write64(vedev, 0x01400170, write_data);

		err = sbus_command(vedev, action_number);
		if (err)
			return -1;
	}

	return 0;
}

static int check_preperation_for_swap(struct ve_dev *vedev)
{
	struct pci_dev *pdev = vedev->pdev;
	int res, pres;
	uint8_t mm;
	uint64_t write_data;
	unsigned long timeout_jiffies;

	timeout_jiffies = jiffies + msecs_to_jiffies(20);

	for (mm = 0x03; mm < 0x22; mm += 2) {

		write_data = 0x0022002A00000000 | (uint64_t)mm << 40;
		pres = -1;
		/* Two consequtive valid reads are required */
		while (1) {
			res = check_sbus_command_completion2(vedev, 220,
					write_data);
			if ((res == 0) && (pres == 0))
				break;
			if (res == -2)
				goto error_out;

			/* timeout */
			if (time_after(jiffies, timeout_jiffies)) {
				pdev_dbg(pdev,
			"check_sbus_command_completion failed (timed out)\n");
				return -1;
			}
			pres = res;
		}
	}
	return 0;
error_out:
	pdev_dbg(pdev, "%s failed\n", __func__);
	return -1;
}

static int ve_load_gen3_sbus_firmware(struct ve_dev *vedev)
{
	int err;
	uint16_t *rom;
	ssize_t size;
	struct pci_dev *pdev = vedev->pdev;

	pdev_trace(pdev);

	/*
	 * Load SBus Master firmware
	 */
	err = request_firmware(&vedev->firmware, FW_VE_SBUS_00,
			&pdev->dev);
	if (err) {
		pdev_err(pdev, "Can't load firmware file \"%s\"\n",
				FW_VE_SBUS_00);
		return err;
	}
	pdev_dbg(pdev, "Firmware is loaded \"%s\"\n", FW_VE_SBUS_00);

	rom = (uint16_t *)vedev->firmware->data;
	size = vedev->firmware->size;

	pdev_dbg(pdev, "Size = %zu\n", size);

	/* (1-2) Halt Processor */
	ve_bar2_write64(vedev, 0x01400170, 0x0021FD0500000001);
	err = sbus_command(vedev, 110);
	if (err) {
		pdev_err(pdev, "Failed to Halt Processor.\n");
		goto err_sbus_fw;
	}

	/* (1-3) SPICO reset */
	ve_bar2_write64(vedev, 0x01400170, 0x0021FD01000000C0);
	err = sbus_command(vedev, 120);
	if (err) {
		pdev_err(pdev, "Failed to SPICO reset.\n");
		goto err_sbus_fw;
	}

	/* (1-4) Set IMEM_CNTL_EN */
	ve_bar2_write64(vedev, 0x01400170, 0x0021FD0100000240);
	err = sbus_command(vedev, 130);
	if (err) {
		pdev_err(pdev, "Failed to set IMEM_CNTL_EN.\n");
		goto err_sbus_fw;
	}

	/* (1-5) Remove Halt */
	ve_bar2_write64(vedev, 0x01400170, 0x0021FD0500000000);
	err = sbus_command(vedev, 140);
	if (err) {
		pdev_err(pdev, "Failed to remove Halt.\n");
		goto err_sbus_fw;
	}

	/* (1-6) Set IMEM_WRT_MODE */
	ve_bar2_write64(vedev, 0x01400170, 0x0021FD0380000000);
	err = sbus_command(vedev, 150);
	if (err) {
		pdev_err(pdev, "Failed to set IMEM_WRT_MODE.\n");
		goto err_sbus_fw;
	}

	/* (1-7) Download SBus Master firmware in burst mode */
	err = fw_download_in_burst_mode(vedev, rom, size, 0x0021FD14);
	if (err) {
		pdev_err(pdev,
		"Failed to Download SBus Master firmware in burst mode.\n");
		goto err_sbus_fw;
	}

	/* (1-8) De-assert IMEM_CNTL_EN */
	ve_bar2_write64(vedev, 0x01400170, 0x0021FD0100000040);
	err = sbus_command(vedev, 170);
	if (err) {
		pdev_err(pdev, "Failed to de-assert IMEM_CNTL_EN.\n");
		goto err_sbus_fw;
	}

	/* (1-9) Turn ECC on */
	ve_bar2_write64(vedev, 0x01400170, 0x0021FD16000C0000);
	err = sbus_command(vedev, 180);
	if (err) {
		pdev_err(pdev, "Failed to turn ECC on.\n");
		goto err_sbus_fw;
	}

	/* (1-10) Set SPICO_ENABLE */
	ve_bar2_write64(vedev, 0x01400170, 0x0021FD0100000140);
	err = sbus_command(vedev, 190);
	if (err) {
		pdev_err(pdev, "Failed to set SPICO_ENABLE.\n");
		goto err_sbus_fw;
	}

	release_firmware(vedev->firmware);
	return 0;

err_sbus_fw:
	release_firmware(vedev->firmware);
	return -EINVAL;
}

static int ve_set_interrupt_code_data(struct ve_dev *vedev)
{
	int err;

	err = check_interrupt_progress2(vedev, 210);
	if (err)
		return -1;
	/* Set interrupt 3A (code) */
	ve_bar2_write64(vedev, 0x01480618, 0x083A083A00002000);
	ve_bar2_write64(vedev, 0x01480620, 0x0000000000000000);

	/* Assert interrupt */
	ve_bar2_write64(vedev, 0x01480618, 0x083A083AFFFF2000);

	wait_nsec(vedev, 5000);

	check_interrupt_progress(vedev, 213);
	if (err)
		return -1;

	/* De-assert interrupt */
	ve_bar2_write64(vedev, 0x01480618, 0x083A083A00002000);

	err = check_interrupt_progress2(vedev, 215);
	if (err)
		return -1;

	return 0;
}

static int ve_load_gen3_sdes_firmware(struct ve_dev *vedev)
{
	int err;
	uint16_t *rom;
	ssize_t size;
	struct pci_dev *pdev = vedev->pdev;

	pdev_trace(pdev);

	/*
	 * Load full-featured PCIe firmware
	 */
	err = request_firmware(&vedev->firmware, FW_VE_SDES_00,
			&pdev->dev);
	if (err) {
		pdev_err(pdev, "Can't load firmware file \"%s\"\n",
				FW_VE_SDES_00);
		return err;
	}
	pdev_dbg(pdev, "Firmware is loaded \"%s\"\n", FW_VE_SDES_00);

	rom = (uint16_t *)vedev->firmware->data;
	size = vedev->firmware->size;

	/* (2-1) Set interrupt_code/data to PCIe for the update preparation */
	err = ve_set_interrupt_code_data(vedev);
	if (err) {
		pdev_err(pdev, "Failed to set interrupt_code/data.\n");
		goto err_sdes_fw;
	}

	/* (2-2) Confirm interrupt status */
	err = check_preperation_for_swap(vedev);
	if (err) {
		pdev_err(pdev, "Failed to confirm interrupt status.\n");
		goto err_sdes_fw;
	}

	/* (2-3) Assert IMEM_override */
	ve_bar2_write64(vedev, 0x01400170, 0x0021FF0040000000);
	err = sbus_command(vedev, 230);
	if (err) {
		pdev_err(pdev, "Failed to Assert IMEM_override.\n");
		goto err_sdes_fw;
	}

	/* (2-4) Download full-featured firmware in burst mode */
	err = fw_download_in_burst_mode(vedev, rom, size, 0x0021FF0A);
	if (err) {
		pdev_err(pdev,
		"Failed to download full-featured firmware in burst mode.\n");
		goto err_sdes_fw;
	}

	/* (2-5) De-assert IMEM_override */
	ve_bar2_write64(vedev, 0x01400170, 0x0021FF0000000000);
	err = sbus_command(vedev, 250);
	if (err) {
		pdev_err(pdev, "Failed to de-assert IMEM_override.\n");
		goto err_sdes_fw;
	}

	release_firmware(vedev->firmware);
	return 0;

err_sdes_fw:
	release_firmware(vedev->firmware);
	return -EINVAL;
}

static int ve_notify_vmc_of_fw_update(struct ve_dev *vedev)
{
	pdev_trace(vedev->pdev);

	/* Set SPI register */
	ve_bar2_write64(vedev, 0x01400190, 0x8000000000200002);

	/* Set SPI register */
	ve_bar2_write64(vedev, 0x01400198, 0x0000010000000100);

	/* Execute SPI command */
	ve_bar2_write64(vedev, 0x01420190, 0x0800000000000000);

	/* Wait 2 sec */
	ssleep(2);

	return 0;
}

/**
 * @brief Enable Gen3 Link mode
 *
 * @param pdev PCI device structure
 *
 * @return 0 on success. Negative on failure.
 */
int ve_set_lnkctl2_target_speed(struct pci_dev *pdev, u8 link_speed)
{
	int err;
	u16 link_ctl2;

	if (link_speed > 0x7) {
		pdev_err(pdev, "invalid linkspeed is specified.\n");
		return -1;
	}

	/* Read Link Control 2 Register (PCIe r3.0-complient)  */
	err = pcie_capability_read_word(pdev, PCI_EXP_LNKCTL2, &link_ctl2);
	if (err) {
		pdev_err(pdev, "Failed to read Link Control 2 Register\n");
		return -1;
	}
	if ((link_ctl2 & 0xf) == link_speed) {
		pdev_dbg(pdev, "link speed is already set\n");
		return 0;
	}

	/* set target link speed */
	link_ctl2 &= ~0xf;
	link_ctl2 |= link_speed;
	pcie_capability_write_word(pdev, PCI_EXP_LNKCTL2, link_ctl2);
	pdev_info(pdev, "link cntrol 2 register is set (0x%x)\n", link_ctl2);

	return 0;
}

/**
 * @brief Load PCIe Gen3 Firmware
 *
 * @param[in] vedev: VE device structure
 *
 * @return 0 on success. negative on failure.
 */
int ve_load_gen3_firmware(struct ve_dev *vedev)
{
	int err;
	struct pci_dev *pdev = vedev->pdev;

	pdev_trace(pdev);

	/* (1-1) Set parent target speed to Gen1 */
	err = ve_set_lnkctl2_target_speed(vedev->pdev->bus->self, 1);
	if (err)
		return -EIO;

	/* (1) Load SBUS master Firmware */
	err = ve_load_gen3_sbus_firmware(vedev);
	if (err)
		return -EIO;

	/* (2) Load SerDes Firmware */
	err = ve_load_gen3_sdes_firmware(vedev);
	if (err)
		return -EIO;

	/* (2-6) Complete FW Update */
	err = ve_notify_vmc_of_fw_update(vedev);
	if (err)
		return -EIO;

	/* (4-2) Set parent target speed to Gen3 */
	err = ve_set_lnkctl2_target_speed(vedev->pdev->bus->self, 3);
	if (err)
		return -EIO;

	ssleep(2);

	return 0;
}

