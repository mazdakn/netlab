CLANGFLAGS = -Wall -Werror -O2 -target bpf -emit-llvm -I../libbpf/src/
GCCFLAGS = -Wall -Werror -I../libbpf/src -L../libbpf/src
LDFLAGS = -Wl,-rpath=../libbpf/src -lbpf -lelf
CC := gcc

PROG_SRC:=$(wildcard *.xdp.c)
PROG_OBJ:=$(PROG_SRC:.c=.o)
PROG_LL:=$(PROG_SRC:.c=.ll)

LOADER_SRC:=xdp-bench.c
LOADER:=xdp-bench

all: $(LOADER) $(PROG_OBJ)
$(PROG_OBJ): $(PROG_LL)
	llc -march=bpf -filetype=obj -o $@ $<
$(PROG_LL): $(PROG_SRC)
	clang $(CLANGFLAGS) -o $@ -c $<
$(LOADER):
	$(CC) $(GCCFLAGS) -o $(LOADER) $(LOADER_SRC) $(LDFLAGS)
clean:
	rm -f *.o *.ll $(LOADER)
