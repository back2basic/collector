package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags "-m64 -I/usr/include -I/usr/include/x86_64-linux-gnu" Sia prog.c
