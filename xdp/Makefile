CLANGFLAGS = -Wall -Werror -O2 -target bpf -emit-llvm -I../include/libbpf/src/
CLANG := clang-11
LLC := llc-11

GCCFLAGS = -Wall -Werror -I../include/libbpf/src -L../include/libbpf/src
LDFLAGS = -Wl,-rpath=../include/libbpf/src -lbpf -lelf
CC := gcc

XDP_SRC:=xdp.c xdp-simple.c

all: xdp xdp-simple xdp-test

xdp:
	$(CLANG) $(CLANGFLAGS) -o xdp.ll -c xdp.c
	$(LLC) -march=bpf -filetype=obj -o xdp.o xdp.ll

xdp-simple:
	$(CLANG) $(CLANGFLAGS) -o xdp-simple.ll -c xdp-simple.c
	$(LLC) -march=bpf -filetype=obj -o xdp-simple.o xdp-simple.ll

xdp-test:
	$(CC) $(GCCFLAGS) -o xdp-bench xdp-bench.c $(LDFLAGS)
clean:
	rm -f *.o *.ll xdp-test
