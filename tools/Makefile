PROGRAM = mmio_tool mmio_o_test
OBJS_MMIO_TOOL = mmio_tool.o bar_access.o
OBJS_MMIO_O_TEST = mmio_o_test.o bar_access.o
CC = gcc

CFLAGS = -Wall -I../src

.PHONY: all
all: $(PROGRAM)

.PHONY: debug
debug: $(PROGRAM) 
debug: CFLAGS += -g -DDEBUG

.PHONY: mmio_tool
mmio_tool: $(OBJS_MMIO_TOOL)
	$(CC) $(CFLAGS) -o $@ $^
mmio_tool.o: mmio_tool.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: mmio_o_test
CFLAGS += -lpthread
mmio_o_test: $(OBJS_MMIO_O_TEST)
	$(CC) $(CFLAGS) -o $@ $^
mmio_o_test.o: mmio_o_test.c
	$(CC) $(CFLAGS) -c -o $@ $<

bar_access.o: bar_access.c
	$(CC) $(CFLAGS) -c -o $@ $<
.PHONY: clean
clean:
	rm -f $(PROGRAM) $(OBJS_MMIO_TOOL) $(OBJS_MMIO_O_TEST)
