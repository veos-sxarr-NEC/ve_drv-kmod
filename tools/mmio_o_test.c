#define _GNU_SOURCE

#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stdbool.h>
#include <getopt.h>
#include <pthread.h>

#include "bar_access.h"

#ifdef DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stderr, "DEBUG: "__VA_ARGS__ ); } while( false )
#else
#define DEBUG_PRINT(...) do{ } while ( false )
#endif
#define handle_error_en(en, msg) \
	do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define ITERATION_NUM	(0x0001FFFF)

pthread_cond_t c_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t c_mutex = PTHREAD_MUTEX_INITIALIZER;
int state = 0;
#define STATE_READY (1)

void usage(void)
{
	printf("Usage: mmio_o_test [-f devicefile] [-m 1|2|3|4|5|6]\n");
	printf("Example: mmio_o_test -f /dev/auve_sys0 -m 1\n");
}

void *parent_thread(void *arg)
{
	int ret;
	volatile void *bar_addr = arg;
	uint64_t sr00;

	cpu_set_t cpuset;
	pthread_t thread;
	thread = pthread_self();

	/* set CPU affinity (CPU 1) */
	CPU_ZERO(&cpuset);
	CPU_SET(1, &cpuset);
	
	ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
	if (ret != 0)
		handle_error_en(ret, "pthread_setaffinity_np");

	pthread_mutex_lock(&c_mutex);
	state = STATE_READY;
	pthread_mutex_unlock(&c_mutex);

	pthread_cond_signal(&c_cond);

	sr00 = *(uint64_t *)(bar_addr + 0x0100000 + 0x1400);
	printf("sr00 = %016lx\n", sr00);

	return NULL;
}

void *child_thread(void *arg)
{
	int ret;
	volatile void *bar_addr = arg;
	uint64_t sr01;

	cpu_set_t cpuset;
	pthread_t thread;
	thread = pthread_self();

	/* set CPU affinity (CPU 2) */
	CPU_ZERO(&cpuset);
	CPU_SET(2, &cpuset);
	
	ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
	if (ret != 0)
		handle_error_en(ret, "pthread_setaffinity_np");

	printf("child thread started.\n");

	pthread_mutex_lock(&c_mutex);
	while (state != STATE_READY) {
		pthread_cond_wait(&c_cond, &c_mutex);
	}
	pthread_mutex_unlock(&c_mutex);

	printf("child thread is awaken.\n");

	sr01 = *(uint64_t *)(bar_addr + 0x0100000 + 0x1408);
	printf("sr01 = %016lx\n", sr01);

	return NULL;
}

static int do_mmio(volatile void *bar_addr, int mode)
{
	int i = ITERATION_NUM;
	uint64_t read_data = 0xFFFFFFFFFFFFFFF;
	volatile void *bar_addr_offset;
	bar_addr_offset = bar_addr;
	pthread_t ptc;

	switch(mode) {
		case 0:
			break;
		case 1:
			printf("push return to start");
			getchar();
			__asm__ __volatile__(
					".LOOP1:	\n\t"
					/* store 8 byte from bar_addr to read_data */
					"movq (%1), %0	\n\t"
					/* store 8 byte 1024 to bar_addr */
					"movq $0xCACE1, (%1)	\n\t"
					"subl $1, %2	\n\t"
					"jne .LOOP1	\n\t"
					: "=r" (read_data), "+r" (bar_addr) , "+r" (i)
					:
					: "memory");
			break;
		case 2:
			bar_addr_offset += 0x1000;
			printf("push return to start");
			getchar();
			__asm__ __volatile__(
					".LOOP2:	\n\t"
					/* store 8 byte from bar_addr to read_data */
					"movq (%1), %0	\n\t"
					/* store 8 byte 4096 to bar_addr_offset */
					"movq $0xCACE2, (%2)	\n\t"
					"subl $1, %3	\n\t"
					"jne .LOOP2	\n\t"
					: "=r" (read_data), "+r" (bar_addr),
					  "+r" (bar_addr_offset), "+r" (i)
					:
					: "memory");
			break;
		case 3:
			bar_addr_offset += 0x1000;
			printf("push return to start");
			getchar();
			__asm__ __volatile__(
					".LOOP3:	\n\t"
					/* store 8 byte from bar_addr to read_data */
					"movq (%1), %0	\n\t"
					/* memory barrier */
					"sfence		\n\t"
					/* store 8 byte 4096 to bar_addr_offset */
					"movq $0xCACE3, (%2)	\n\t"
					"subl $1, %3	\n\t"
					"jne .LOOP3	\n\t"
					: "=r" (read_data), "+r" (bar_addr),
					  "+r" (bar_addr_offset), "+r" (i)
					:
					: "memory");
			break;
		case 4:
			bar_addr += 0x01480000;
			printf("push return to start");
			getchar();
			__asm__ __volatile__(
					".LOOP4:	\n\t"
					/* store 8 byte from bar_addr to read_data */
					"movq (%1), %0	\n\t"
					/* store 8 byte 4096 to bar_addr_offset */
					"movq $0x800000, (%1)	\n\t"
					"subl $1, %2	\n\t"
					"jne .LOOP4	\n\t"
					: "=r" (read_data), "+r" (bar_addr),
					  "+r" (i)
					:
					: "memory");
			break;
		case 5:
			bar_addr += 0x01400000;
			bar_addr_offset += 0x01480000;
			printf("push return to start");
			getchar();
			__asm__ __volatile__(
					".LOOP5:	\n\t"
					/* store 8 byte from bar_addr to read_data */
					"movq (%1), %0	\n\t"
					/* store 8 byte 4096 to bar_addr_offset */
					"movq $0x800000, (%3)	\n\t"
					"subl $1, %2	\n\t"
					"jne .LOOP5	\n\t"
					: "=r" (read_data), "+r" (bar_addr),
					  "+r" (i), "+r" (bar_addr_offset)
					:
					: "memory");
			break;
		case 6:
			bar_addr += 0x01400000;
			bar_addr_offset += 0x01480000;
			printf("push return to start");
			getchar();
			__asm__ __volatile__(
					".LOOP6:	\n\t"
					/* store 8 byte from bar_addr to read_data */
					"movq (%1), %0	\n\t"
					/* memory barrier */
					"sfence		\n\t"
					/* store 8 byte 4096 to bar_addr_offset */
					"movq $0x800000, (%3)	\n\t"
					"subl $1, %2	\n\t"
					"jne .LOOP6	\n\t"
					: "=r" (read_data), "+r" (bar_addr),
					  "+r" (i), "+r" (bar_addr_offset)
					:
					: "memory");
			break;
		case 7:
			if (pthread_create(&ptc, NULL, child_thread, (void *)bar_addr)) {
				fprintf(stderr, "Error creating thread\n");
				return 1;
			}
			parent_thread((void *)bar_addr);
			if (pthread_join(ptc, NULL)) {
				fprintf(stderr, "Error joining thread\n");
				return 2;
			}
			
		default:
			return 0;
	}

	printf("read_data = 0x%lx\n", read_data);
	printf("*bar_addr = 0x%lx\n", *(uint64_t *)bar_addr);
	if (mode != 1 && mode != 4)
		printf("*bar_addr_offset = 0x%lx\n", *(uint64_t *)bar_addr_offset);

	return 0;
}

int
main(int argc, char *argv[])
{
	int bar, opt, fd, option_index;
	bool option_devfile;
	char *filename;
	volatile void *bar_addr;
	char *endptr;
	int retval;
	int mode;

	/* default value */
	option_devfile = false;
	mode = 0;

	struct option long_options[] = {
		{"devfile", required_argument, NULL, 'f'},
		{"mode", no_argument, NULL, 'm'},
		{0,0,0,0}
	};

	while((opt = getopt_long(argc, argv, "f:m:", long_options,
					&option_index)) != -1) {
		switch(opt) {
			case 'f':
				option_devfile = true;
				filename = (char *)malloc(sizeof(char)
						*strlen(optarg));
				strncpy(filename, optarg, strlen(optarg));
				DEBUG_PRINT("device filename = %s\n", filename);
				break;
			case 'm':
				mode = (off_t)strtoull(optarg, &endptr, 0);
				if (mode == (off_t)0 && optarg == endptr) {
					fprintf(stderr, "invalid mode\n");
					return 1;
				}
				break;
			case '?':
				usage();
				return 1;
		}
	}

	/* Check mandatory options */
	if (!option_devfile) {
		fprintf(stderr, "specify device filename.\n");
		usage();
		return 1;
	}

	switch(mode) {
		case 0:
		case 1:
		case 2:
		case 3:
			bar = BAR_01;
			break;
		case 4:
		case 5:
		case 6:
		case 7:
			bar = BAR_2;
			break;
		default:
			usage();
			return 1;
	}

	bar_addr = map_bar(&fd, bar, filename);
	if (bar_addr == (void *)-1) {
		fprintf(stderr, "map_bar failed.\n");
		return 1;
	}

	printf("bar_addr = %p\n", bar_addr);
	retval = do_mmio(bar_addr, mode);

	/* Unmap BAR */
	retval = unmap_bar(&fd, (void *)bar_addr, bar);

	return retval;
}
