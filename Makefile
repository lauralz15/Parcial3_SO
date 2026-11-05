CLANG ?= clang
CC ?= gcc
BPFTOOL ?= bpftool
CFLAGS ?= -O2 -g -Wall -Wextra -Werror
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf 2>/dev/null)
ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

.PHONY: all user bpf test bench clean check-deps
all: user bpf

user: shield_loader poc_mmap poc_readonly poc_race_safe bench_mmap

poc_mmap: exploits/poc_mmap.c
	$(CC) $(CFLAGS) $< -o $@

poc_readonly: exploits/poc_readonly.c
	$(CC) $(CFLAGS) $< -o $@

poc_race_safe: exploits/poc_race_safe.c
	$(CC) $(CFLAGS) -pthread $< -o $@

bench_mmap: exploits/bench_mmap.c
	$(CC) $(CFLAGS) $< -o $@

shield_loader: src/shield_loader.c
	@test -n "$(LIBBPF_LIBS)" || (echo "Falta libbpf-dev/libbpf-devel y pkg-config" >&2; exit 1)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) $< -o $@ $(LIBBPF_LIBS)

bpf: bpf/mmap_shield.bpf.o

bpf/vmlinux.h:
	@test -r /sys/kernel/btf/vmlinux || (echo "No existe /sys/kernel/btf/vmlinux; el kernel debe exponer BTF" >&2; exit 1)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

bpf/mmap_shield.bpf.o: bpf/mmap_shield.bpf.c bpf/vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(LIBBPF_CFLAGS) -c $< -o $@

test: all
	bash tests/test_kernel_mmap.sh

bench: all
	bash tests/bench.sh

clean:
	rm -f bench_mmap shield_loader poc_mmap poc_readonly poc_race_safe bpf/mmap_shield.bpf.o bpf/vmlinux.h
