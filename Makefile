CC = clang

CFLAGS = -O2 -g -Wall
CFLAGS += -target bpf
CFLAGS += -fno-jump-tables
CFLAGS += -Wno-compare-distinct-pointer-types
CFLAGS += -Wno-pragma-pack

all: kern.o overseer

kern.o: kern/kern.c
	$(CC) $(CFLAGS) -c $< -o $@

overseer: kern.o $(wildcard *.go)
	CGO_ENABLED=0 go build -o $@

.PHONY: all
