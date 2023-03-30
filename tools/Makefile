PROGRAM = mmio_tool mmio_o_test
OBJS_MMIO_TOOL = mmio_tool.o bar_access.o
OBJS_MMIO_O_TEST = mmio_o_test.o bar_access.o

PROGRAM_VE3 = mmio_tool_ve3 mmio_o_test_ve3
OBJS_MMIO_TOOL_VE3 = mmio_tool_ve3.o bar_access_ve3.o
OBJS_MMIO_O_TEST_VE3 = mmio_o_test_ve3.o bar_access_ve3.o

CC = gcc

CFLAGS = -Wall -I../src

.PHONY: all
all: $(PROGRAM) $(PROGRAM_VE3)

.PHONY: debug
debug: $(PROGRAM)  $(PROGRAM_VE3)
debug: CFLAGS += -g -DDEBUG

.PHONY: mmio_tool
mmio_tool: $(OBJS_MMIO_TOOL)
	$(CC) $(CFLAGS) -o $@ $^
mmio_tool.o: mmio_tool.c
	$(CC) $(CFLAGS) -c -o $@ $<


mmio_tool_ve3: $(OBJS_MMIO_TOOL_VE3)
	$(CC) $(CFLAGS) -o $@ $^
mmio_tool_ve3.o: mmio_tool_ve3.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: mmio_o_test mmio_o_test_ve3
CFLAGS += -lpthread
mmio_o_test: $(OBJS_MMIO_O_TEST)
	$(CC) $(CFLAGS) -o $@ $^
mmio_o_test.o: mmio_o_test.c
	$(CC) $(CFLAGS) -c -o $@ $<

bar_access.o: bar_access.c
	$(CC) $(CFLAGS) -c -o $@ $<


mmio_o_test_ve3: $(OBJS_MMIO_O_TEST_VE3)
	$(CC) $(CFLAGS) -o $@ $^
mmio_o_test_ve3.o: mmio_o_test_ve3.c
	$(CC) $(CFLAGS) -c -o $@ $<

bar_access_ve3.o: bar_access_ve3.c
	$(CC) $(CFLAGS) -c -o $@ $<

.PHONY: clean
clean:
	rm -f $(PROGRAM) $(OBJS_MMIO_TOOL) $(OBJS_MMIO_O_TEST)
	rm -f $(PROGRAM_VE3) $(OBJS_MMIO_TOOL_VE3) $(OBJS_MMIO_O_TEST_VE3)
