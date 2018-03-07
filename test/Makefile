PROGRAM = wait_test_attr wait_ve_state_attr get_sysfs_path
OBJS_W_TEST = wait_test_attr.o
OBJS_W_VE_STATE = wait_ve_state_attr.o
OBJS_S_PATH = get_sysfs_path.o
CC = gcc

CFLAGS = -Wall -I../src

.PHONY: all
all: $(PROGRAM)

.PHONY: debug
debug: $(PROGRAM) 
debug: CFLAGS += -g -DDEBUG

wait_test_attr: $(OBJS_W_TEST)
	$(CC) $(CFLAGS) -o $@ $^
wait_test_attr.o: wait_test_attr.c
	$(CC) $(CFLAGS) -c -o $@ $<

wait_ve_state_attr: $(OBJS_W_VE_STATE)
	$(CC) $(CFLAGS) -o $@ $^
wait_ve_state_attr.o: wait_ve_state_attr.c
	$(CC) $(CFLAGS) -c -o $@ $<

get_sysfs_path: CFLAGS += -ludev
get_sysfs_path: $(OBJS_S_PATH)
	$(CC) $(CFLAGS) -o $@ $^
get_sysfs_path.o: get_sysfs_path.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f $(PROGRAM) $(OBJS_W_TEST)

