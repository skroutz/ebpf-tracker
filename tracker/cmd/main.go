//go:build linux

// Network connection tracker using eBPF CO-RE. Writes JSONL to /tmp/ebpf-network-events.json.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" NetworkTracker ../bpf/network_tracker.c -- -I../bpf
package main

import (
	"bufio"
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/skroutz/ebpf-tracker/internal/events"
)

const defaultOutputFile = "/tmp/ebpf-network-events.json"

func main() {
	outputFile := flag.String("output", defaultOutputFile, "path to JSONL output file, or '-' for stdout")
	flag.Parse()

	runID := os.Getenv("GITHUB_RUN_ID")
	if runID == "" {
		runID = "local"
	}
	repository := os.Getenv("GITHUB_REPOSITORY")
	workflowName := os.Getenv("GITHUB_WORKFLOW")

	bootTime, err := events.BootTime()
	if err != nil {
		log.Fatalf("read boot time: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	objs := NetworkTrackerObjects{}
	if err := LoadNetworkTrackerObjects(&objs, nil); err != nil {
		log.Fatalf("load BPF objects: %v", err)
	}
	defer objs.Close()

	var klinks []link.Link

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

	// udpv6_sendmsg and udpv6_recvmsg may not exist on all kernels; best-effort.
	kp5, err := link.Kprobe("udpv6_sendmsg", objs.TraceUdpv6Sendmsg, nil)
	if err != nil {
		log.Printf("kprobe udpv6_sendmsg (non-fatal): %v", err)
	} else {
		klinks = append(klinks, kp5)
	}

	kp6, err := link.Kprobe("udpv6_recvmsg", objs.TraceUdpv6Recvmsg, nil)
	if err != nil {
		log.Printf("kprobe udpv6_recvmsg (non-fatal): %v", err)
	} else {
		klinks = append(klinks, kp6)
	}

	defer func() {
		for _, l := range klinks {
			l.Close()
		}
	}()

	var w *bufio.Writer
	if *outputFile == "-" {
		w = bufio.NewWriterSize(os.Stdout, 64*1024)
		log.Printf("ebpf-tracker running, writing to stdout")
		defer w.Flush()
	} else {
		f, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			log.Fatalf("open output file: %v", err)
		}
		w = bufio.NewWriterSize(f, 64*1024)
		defer func() {
			w.Flush()
			f.Close()
		}()
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("open ringbuf reader: %v", err)
	}
	defer rd.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *outputFile != "-" {
		log.Printf("ebpf-tracker running, writing to %s", *outputFile)
	}

	// Close the reader when the signal fires so rd.Read() unblocks.
	go func() {
		<-ctx.Done()
		log.Println("shutting down...")
		rd.Close()
	}()

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

		je := events.Format(e, bootTime, runID, repository, workflowName)
		line, err := events.Marshal(je)
		if err != nil {
			log.Printf("marshal event: %v", err)
			continue
		}
		w.Write(line)
		w.WriteByte('\n')
	}

	log.Println("ebpf-tracker stopped")
}
