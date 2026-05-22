//go:build linux

// Network connection tracker using eBPF CO-RE. Writes JSONL to /tmp/ebpf-network-events.json.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" NetworkTracker ../bpf/network_tracker.c -- -I../bpf
package main

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/skroutz/ebpf-tracker/internal/events"
)

const outputFile = "/tmp/ebpf-network-events.json"

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	objs := NetworkTrackerObjects{}
	if err := LoadNetworkTrackerObjects(&objs, nil); err != nil {
		log.Fatalf("load BPF objects: %v", err)
	}
	defer objs.Close()

	var klinks []link.Link

	mustKprobe := func(sym string, prog interface{ FD() int }) {
		// prog is one of the typed *ebpf.Program fields from the generated objs.
		// We call link.Kprobe via the concrete types below.
		_ = sym
		_ = prog
	}
	_ = mustKprobe

	kp1, err := link.Kprobe("tcp_v4_connect", objs.TraceTcpV4Connect, nil)
	if err != nil {
		log.Fatalf("kprobe tcp_v4_connect: %v", err)
	}
	klinks = append(klinks, kp1)

	kp2, err := link.Kprobe("tcp_v6_connect", objs.TraceTcpV6Connect, nil)
	if err != nil {
		log.Fatalf("kprobe tcp_v6_connect: %v", err)
	}
	klinks = append(klinks, kp2)

	kp3, err := link.Kprobe("udp_sendmsg", objs.TraceUdpSendmsg, nil)
	if err != nil {
		log.Fatalf("kprobe udp_sendmsg: %v", err)
	}
	klinks = append(klinks, kp3)

	kp4, err := link.Kprobe("udp_recvmsg", objs.TraceUdpRecvmsg, nil)
	if err != nil {
		log.Fatalf("kprobe udp_recvmsg: %v", err)
	}
	klinks = append(klinks, kp4)

	// udpv6_sendmsg may not exist on all kernels; attach best-effort.
	kp5, err := link.Kprobe("udpv6_sendmsg", objs.TraceUdpv6Sendmsg, nil)
	if err != nil {
		log.Printf("kprobe udpv6_sendmsg (non-fatal): %v", err)
	} else {
		klinks = append(klinks, kp5)
	}

	defer func() {
		for _, l := range klinks {
			l.Close()
		}
	}()

	f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("open output file: %v", err)
	}
	w := bufio.NewWriterSize(f, 64*1024)
	defer func() {
		w.Flush()
		f.Close()
	}()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf reader: %v", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	log.Printf("ebpf-tracker running, writing to %s", outputFile)

	go func() {
		<-sig
		log.Println("shutting down...")
		rd.Close()
	}()

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				break
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}

		e, err := events.Parse(record.RawSample)
		if err != nil {
			log.Printf("parse event: %v", err)
			continue
		}

		je := events.Format(e, time.Now())
		if err := enc.Encode(je); err != nil {
			log.Printf("encode json: %v", err)
		}
	}

	w.Flush()
	log.Println("ebpf-tracker stopped")
}
