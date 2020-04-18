.PHONY: all clean
CC = g++
CFLAGS = -std=gnu99 -Wall -Wextra -Werror -pedantic

EXECUTABLE = ipk-sniffer

all: $(EXECUTABLE)

ipk-sniffer: $(EXECUTABLE).o
	$(CC) -o $@ $^ -lpcap

ipk-sniffer.o: $(EXECUTABLE).cpp
	$(CC) -c $^

zip:
	zip $(EXECUTABLE).zip *.c *.h Makefile

clean:
	rm -rf $(EXECUTABLE) *.o