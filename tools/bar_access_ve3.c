#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>

#define _VE_ARCH_VE3_ 1
#include "bar_access.h"

void *map_bar(int *fd, int bar, char *filename)
{
	void *bar_addr;
	unsigned long size;

	*fd = open(filename, O_RDWR);
	if (*fd == -1) {
		fprintf(stderr, "open %s: %s\n", filename, strerror(errno));
		return (void *)-1;
	}

	if (bar == VE3_BAR_01) {
		size = VE3_BAR0_SIZE;
		bar_addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
				*fd, VEDRV_VE3_MAP_BAR0_OFFSET);
	} else if (bar == VE3_BAR_23) {
		size = VE3_BAR2_SIZE;
		bar_addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
				*fd, VEDRV_VE3_MAP_BAR2_OFFSET);
	} else if (bar == VE3_BAR_4) {
		size = VE3_BAR4_SIZE;
		bar_addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED,
				*fd, VEDRV_VE3_MAP_BAR4_OFFSET);
	} else {
		fprintf(stderr, "invalid bar number(%d)\n", bar);
		return (void *)-1;
	}
	if (bar_addr == MAP_FAILED) {
		perror("mmap");
		return (void *)-1;
	}

	return bar_addr;
}

int unmap_bar(int *fd, void *bar_addr, int bar)
{
	unsigned long size;

	if (bar == VE3_BAR_01) {
		size = VE3_BAR0_SIZE;
	} else if (bar == VE3_BAR_23) {
		size = VE3_BAR2_SIZE;
	} else if (bar == VE3_BAR_4) {
		size = VE3_BAR4_SIZE;
	} else {
		fprintf(stderr, "invalid bar number(%d)\n", bar);
		return -1;
	}

	munmap(bar_addr, size);
	close(*fd);

	return 0;
}
