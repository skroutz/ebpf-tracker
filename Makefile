.PHONY: vmlinux generate build clean

CLANG      ?= clang
BPFTOOL    ?= bpftool
ARCH       ?= x86

vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > tracker/bpf/vmlinux.h

generate: vmlinux
	cd tracker && go generate ./cmd/...

build: generate
	cd tracker && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
		go build -ldflags="-s -w" -o ebpf-tracker ./cmd/

clean:
	rm -f tracker/bpf/vmlinux.h \
	       tracker/networktracker_bpf*.go \
	       tracker/networktracker_bpf*.o \
	       tracker/ebpf-tracker
