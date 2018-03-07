#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#define STR_SIZE 256

int main(int argc, char **argv) {
	int fd;
	char str[STR_SIZE];
	struct pollfd pfd;
	int retval;

	fd = open(argv[1], O_RDWR);
	if (errno) {
		fprintf(stderr, "%s: %s\n", strerror(errno), argv[1]);
		exit(1);
	}

	retval = read(fd, str, STR_SIZE);
	if (errno) {
		perror("read");
		exit(1);
	}
	str[retval] = '\0';
	printf("readed %s\n", str);

	pfd.fd = fd;
	pfd.events = POLLPRI | POLLERR;
	pfd.revents = 0;

	do {
		printf("poll start\n");
		poll(&pfd, 1, -1);

		retval = lseek(fd, 0, SEEK_SET);
		if (retval == -1) {
			perror("lseek");
		}

		retval = read(fd, str, STR_SIZE);
		if (retval == -1) {
			perror("read");
			exit(1);
		}
		str[retval] = '\0';

		printf("str = %s\n", str);
	} while (1);

	retval = close(fd);

	return retval;
}
