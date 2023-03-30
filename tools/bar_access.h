
#include "ve_drv.h"

#define VE1_BAR_01  (0)
#define VE1_BAR_2   (2)
#define VE1_BAR_3   (3)


#define VE3_BAR_01  (0)
#define VE3_BAR_23  (2)
#define VE3_BAR_4   (4)

void *map_bar(int *, int, char *);
int unmap_bar(int *, void *, int);

#define VE1_BAR0_SIZE 128*1024*1024
#define VE1_BAR2_SIZE 32*1024*1024
#define VE1_BAR3_SIZE 256*1024


#define VE3_BAR0_SIZE 128*1024*1024
#define VE3_BAR2_SIZE 64*1024*1024
#define VE3_BAR4_SIZE 8*1024*1024

