#include "ve_drv.h"

#define BAR_01  (0)
#define BAR_2   (2)
#define BAR_3   (3)

void *map_bar(int *, int, char *);
int unmap_bar(int *, void *, int);

#define BAR0_SIZE 128*1024*1024
#define BAR2_SIZE 32*1024*1024
#define BAR3_SIZE 256*1024
