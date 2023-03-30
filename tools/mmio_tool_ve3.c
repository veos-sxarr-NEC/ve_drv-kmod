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
#include <immintrin.h>
#include <xmmintrin.h>
#include <time.h>

#include "bar_access.h"

#ifdef DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stderr, "DEBUG: "__VA_ARGS__ ); } \
	while( false )
#else
#define DEBUG_PRINT(...) do{ } while ( false )
#endif

#define MMIO_READ	(0)
#define MMIO_WRITE	(1)
#define SIMD_DISABLE	(0)
#define SIMD_SSE2	(1)
#define SIMD_AVX	(2)

bool option_printspeed = false;

void usage(void)
{
	printf("Usage: mmio_tool [-f devicefile] [-b 01|2|4] [-r|-w] [-a offset] "
			"[-s size] [-d data]\n");
	printf("Example: # mmio_tool -f /dev/ve0 -b 01 -w -a 0x100 -s 0x8 "
			"-d 0xdeadbeefdeadbeef\n");
}

void dump_buffer(void *addr, size_t size, uint64_t base_addr)
{
        int i;
        char str[9];
        uint64_t *ptr64;

        ptr64 = (uint64_t *)addr;
        str[8] = '\0';

        for (i = 0; i < size / 8; i++) {
                strncpy(str, (char *)&(ptr64[i]), 8);
                printf("0x%016lx: 0x%016lx (%s)\n", base_addr + i * 8, ptr64[i],
                       str);
        }
}

int fill_buffer_with_data(void *vaddr, uint64_t *data, size_t size)
{
        void *ptr;
        ptr = vaddr;

        for (; ptr < vaddr + size; ptr += sizeof(uint64_t)) {
                memcpy(ptr, data, sizeof(uint64_t));
        }
        if (ptr != vaddr + size) {
                memcpy(ptr, data, vaddr + size - ptr);
        }

#ifdef DEBUG_BUFF
        dump_buffer(vaddr, size, 0);
#endif

        return 0;
}

static inline void _sse2_memcpy(volatile void *to, volatile void *from,
		size_t size)
{
	volatile void *fp = from;
	volatile void *tp = to;
	int i = size;
#ifdef __SSE2__
	__m128i f;

	if ((uint64_t)from % 16 || (uint64_t)to % 16) {
		fprintf(stderr, "SSE2: invalid alignment\n");
		fprintf(stderr, "from = %p\n", from);
		fprintf(stderr, "to = %p\n", to);
		exit(1);
	}

	/* copy memory by using SIMD register (SSE2) */
        while (i >= sizeof(__m128i)) {
                f = _mm_load_si128((__m128i *) fp);
                _mm_store_si128((__m128i *) tp, f);
                fp += sizeof(__m128i);
                tp += sizeof(__m128i);
                i -= sizeof(__m128i);
        }
#endif

	if (i) {
		memcpy((void *)tp, (void *)fp, i);
	}
}

static inline void _avx_memcpy(volatile void *to, volatile void *from,
		size_t size)
{
	volatile void *fp = from;
	volatile void *tp = to;
	int i = size;
#ifdef __AVX__
	__m256i f;

        /* check alignment */
        if ((uint64_t)from % 32 || (uint64_t)to % 32) {
		fprintf(stderr, "AVX: invalid alignment\n");
		fprintf(stderr, "from = %p\n", from);
		fprintf(stderr, "to = %p\n", to);
		exit(1);
        }

        /* copy memory by using SIMD register (AVX) */
        while (i >= sizeof(__m256i)) {
                f = _mm256_load_si256((__m256i *) fp);
                _mm256_store_si256((__m256i *) tp, f);
                fp += sizeof(__m256i);
                tp += sizeof(__m256i);
                i -= sizeof(__m256i);
        }
#endif

	if (i) {
		memcpy((void *)tp, (void *)fp, i);
	}
}

static inline void _simd_memcpy(void *to, void *from, size_t size,
		int simd_mode, int loop)
{
	int i;
	struct timespec ts1,ts2;

	if (clock_gettime(CLOCK_MONOTONIC, &ts1) != 0) {
		perror("clock_gettime");
		exit(1);
	}
	if (simd_mode == SIMD_SSE2) {
		for (i = 0; i < loop; i++) {
			_sse2_memcpy((volatile void *)to,
					(volatile void *)from, size);
		}
	} else if (simd_mode == SIMD_AVX) {
		for (i = 0; i < loop; i++) {
			_avx_memcpy((volatile void *)to,
					(volatile void *)from, size);
		}
	} else {
		for (i = 0; i < loop; i++) {
			memcpy(to, from, size);
		}
	}

	if (clock_gettime(CLOCK_MONOTONIC, &ts2) != 0) {
		perror("clock_gettime");
		exit(1);
	}

	if (!option_printspeed)
		return;

	unsigned long nsec = (ts2.tv_sec - ts1.tv_sec) * 1000000000L
		+ (ts2.tv_nsec - ts1.tv_nsec);
	unsigned long len = size * loop;
	printf("%lu bytes / %lu nsec = %f MB/s\n", len, nsec,
			(double)len * 1000 / nsec);
}

static int do_mmio(int mmiorw, void *bar_addr, off_t offset, size_t size,
		uint64_t data, int simd_mode, int loop)
{
	void *addr;
	void *datap;

#ifdef __AVX__
	int ret;
	ret = posix_memalign(&datap, sizeof(__m256i), size);
	if (ret) {
		fputs(strerror(ret), stderr);
		exit(1);
	}
#else
	datap = malloc(size);
	if (datap == NULL) {
		fputs(strerror(errno), stderr);
                exit(1);
	}
#endif

	addr = bar_addr+offset;

	if (mmiorw == MMIO_READ) {
		_simd_memcpy(datap, addr, size, simd_mode, loop);
		dump_buffer(datap, size, offset);
	} else if (mmiorw == MMIO_WRITE) {
		fill_buffer_with_data(datap, &data, size);
		_simd_memcpy(addr, datap, size, simd_mode, loop);
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	int opt, bar, fd, option_index;
	int mmiorw;
	int simd_mode = SIMD_DISABLE;
	int loop = 1;
	bool option_bar, option_read, option_write, option_addr;
	bool option_data, option_devfile, option_wait = false;
	off_t offset;
	size_t size = 0x8;
	uint64_t data = 0x0;
	char *filename;
	void *bar_addr;
	char *endptr;
	int retval;

	struct option long_options[] = {
		{"bar", required_argument, NULL, 'b'},
		{"read", no_argument, NULL, 'r'},
		{"write", no_argument, NULL, 'w'},
		{"offset", required_argument, NULL, 'a'},
		{"size", required_argument, NULL, 's'},
		{"data", required_argument, NULL, 'd'},
		{"devfile", required_argument, NULL, 'f'},
		{"sse", no_argument, NULL, 'S'},
		{"avx", no_argument, NULL, 'A'},
		{"loop", required_argument, NULL, 'l'},
		{"wait", no_argument, NULL, 'W'},
		{"printspeed", no_argument, NULL, 'p'},
		{0,0,0,0}
	};

	while((opt = getopt_long(argc, argv, "b:rwa:s:d:f:SAl:Wp", long_options,
					&option_index)) != -1) {
		switch(opt) {
			case 'b':
				option_bar = true;
				if (strlen(optarg) > 2) {
					usage();
					return 1;
				} else {
					if (!strncmp(optarg, "01", 2)) {
						bar = VE3_BAR_01;
					} else if (!strncmp(optarg, "2", 1)) {
						bar = VE3_BAR_23;
					} else if (!strncmp(optarg, "4", 1)) {
						bar = VE3_BAR_4;
					} else {
						fprintf(stderr,
							"invalid BAR\n");
						usage();
						return 1;
					}
				}
				DEBUG_PRINT("bar = %d\n", bar);
				break;
			case 'r':
				option_read = true;
				mmiorw = MMIO_READ;
				DEBUG_PRINT("mmiorw = %d\n", mmiorw);
				break;
			case 'w':
				option_write = true;
				mmiorw = MMIO_WRITE;
				DEBUG_PRINT("mmiorw = %d\n", mmiorw);
				break;
			case 'a':
				option_addr = true;
				offset = (off_t)strtoull(optarg, &endptr, 0);
				if (offset == (off_t)0 && optarg == endptr) {
					fprintf(stderr,
						"invalid offset address.\n");
					return 1;
				}
				DEBUG_PRINT("offset = %jd\n", offset);
				break;
			case 's':
				size = strtoll(optarg, NULL, 0);
				if (size <= 0) {
					fprintf(stderr, "invalid size.\n");
					return 1;
				}
				DEBUG_PRINT("size = %zd\n", size);
				break;
			case 'd':
				option_data = true;
				data = strtoull(optarg, &endptr, 0);
				if (data == 0 && optarg == endptr) {
					fprintf(stderr, "invalid data.\n");
					return 1;
				}
				DEBUG_PRINT("write data = 0x%lx\n", data);
				break;
			case 'f':
				option_devfile = true;
				filename = (char *)malloc(sizeof(char)
						*strlen(optarg));
				strncpy(filename, optarg, strlen(optarg));
				DEBUG_PRINT("device filename = %s\n", filename);
				break;
			case 'S':
#ifndef __SSE2__
				fprintf(stderr, "SSE is not available.\n");
				return 1;
#else
				simd_mode = SIMD_SSE2;
				if (size < sizeof(__m128i))
					size = sizeof(__m128i);
				DEBUG_PRINT("SSE2 is enabled.\n");
#endif
				break;
			case 'A':
#ifndef __AVX__
				fprintf(stderr, "AVX is not available.\n");
				return 1;
#else
				simd_mode = SIMD_AVX;
				if (size < sizeof(__m256i))
					size = sizeof(__m256i);
				DEBUG_PRINT("AVX is enabled.\n");
#endif
				break;
			case 'l':
				loop = strtoul(optarg, NULL, 0);
				if (loop <= 0) {
					fprintf(stderr, "invalid loop num "
							"(%d).\n", loop);
					return 1;
				}
				DEBUG_PRINT("loop num = %d.\n", loop);
				break;
			case 'W':
				option_wait = true;
				break;
			case 'p':
				option_printspeed = true;
				break;
			case '?':
				usage();
				return 1;
		}
	}

	/* Check mandatory options */
	if (!(option_bar && (option_read || option_write) && option_addr
				&& option_devfile)) {
		fprintf(stderr, "missing mandatory arguments.\n");
		usage();
		return 1;
	} else if ((mmiorw == MMIO_WRITE) && !option_data) {
		fprintf(stderr, "missing data to write.\n");
		usage();
		return 1;
	}

	/* Check access range */
	if (bar == VE3_BAR_01) {
		if (offset + size > VE3_BAR0_SIZE) {
			fprintf(stderr, "out of BAR01 range.\n");
			return 1;
		}
	} else if (bar == VE3_BAR_23) {
		if (offset + size > VE3_BAR2_SIZE) {
			fprintf(stderr, "out of BAR2 range.\n");
			return 1;
		}
	} else if (bar == VE3_BAR_4) {
		if (offset + size > VE3_BAR4_SIZE) {
			fprintf(stderr, "out of BAR4 range.\n");
			return 1;
		}
	}

	/* Map BAR */
	bar_addr = map_bar(&fd, bar, filename);
	if (bar_addr == (void *)-1) {
		fprintf(stderr, "map_bar failed.\n");
		return 1;
	}

	if (option_wait)
		getchar();

	retval = do_mmio(mmiorw, bar_addr, offset, size, data, simd_mode, loop);

	/* Unmap BAR */
	retval = unmap_bar(&fd, bar_addr, bar);

	return retval;
}
