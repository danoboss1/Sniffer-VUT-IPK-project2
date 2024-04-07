.PHONY: all clean

CC := gcc
CFLAGS := -g -std=c11 -pedantic -Wall -Wextra -D_BSD_SOURCE -D_DEFAULT_SOURCE
PROG_OBJS := ipk-sniffer.o 

all: ipk-sniffer

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< -lpcap

ipk-sniffer: $(PROG_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lpcap

clean:
	rm -f $(PROG_OBJS) ipk-sniffer