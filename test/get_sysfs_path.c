#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#include <libudev.h>

int main(int argc, char *argv[])
{
	struct stat sb;
	struct udev *udev;
	struct udev_device *dev;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <pathname>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (stat(argv[1], &sb) == -1) {
		perror("stat");
		exit(EXIT_FAILURE);
	}

	udev = udev_new();
	dev = udev_device_new_from_devnum(udev, 'c', sb.st_rdev);
	if (dev == NULL) {
		perror("udev_device_new_from_devnum");
		exit(EXIT_FAILURE);
	}
	printf("%s %s\n", "sysfs path: ", udev_device_get_syspath(dev));

	exit(EXIT_SUCCESS);
}
