//go:build linux

// Network connection tracker using eBPF CO-RE. Writes JSONL to /tmp/ebpf-network-events.json.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -Werror -D__TARGET_ARCH_x86" NetworkTracker ../bpf/network_tracker.c -- -I../bpf
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/skroutz/ebpf-tracker/internal/events"
	"github.com/skroutz/ebpf-tracker/internal/procscan"
)

const defaultOutputFile = "/tmp/ebpf-network-events.json"

func main() {
	outputFile := flag.String("output", defaultOutputFile, "path to JSONL output file, or '-' for stdout")
	procScanInterval := flag.Duration("proc-scan-interval", 200*time.Millisecond,
		"how often to poll /proc/net for pre-existing connections (0 to disable)")
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

	// Write PID file so the GHA post step can send an exact SIGTERM.
	if err := os.WriteFile("/tmp/ebpf-tracker.pid", []byte(strconv.Itoa(os.Getpid())), 0644); err != nil {
		log.Printf("write pid file: %v", err)
	}
	defer os.Remove("/tmp/ebpf-tracker.pid")

	var klinks []link.Link

	kp1, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceTcpV4Connect})
	if err != nil {
		log.Fatalf("fexit tcp_v4_connect: %v", err)
	}
	klinks = append(klinks, kp1)

	kp2, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceTcpV6Connect})
	if err != nil {
		log.Fatalf("fexit tcp_v6_connect: %v", err)
	}
	klinks = append(klinks, kp2)

	kp3, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceUdpSendmsg})
	if err != nil {
		log.Fatalf("fentry udp_sendmsg: %v", err)
	}
	klinks = append(klinks, kp3)

	kp4, err := link.AttachTracing(link.TracingOptions{Program: objs.TraceUdpRecvmsg})
	if err != nil {
		log.Fatalf("fentry udp_recvmsg: %v", err)
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
	var mu sync.Mutex
	if *outputFile == "-" {
		w = bufio.NewWriterSize(os.Stdout, 64*1024)
		log.Printf("ebpf-tracker running, writing to stdout")
		defer w.Flush()
	} else {
		f, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
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

	// Start the /proc/net scanner unless disabled.
	dedup := procscan.NewDedup(5 * time.Minute)
	if *procScanInterval > 0 {
		scanner := procscan.NewScanner(*procScanInterval, dedup, w, &mu, runID, repository, workflowName)
		go scanner.Run(ctx)
		log.Printf("proc scanner running (interval: %s)", *procScanInterval)
	}

	// Set a past deadline on the reader when the signal fires so rd.Read()
	// unblocks immediately. Using SetDeadline is more reliable than Close()
	// for interrupting a blocked epoll wait inside cilium/ebpf's ring buffer.
	go func() {
		<-ctx.Done()
		log.Println("shutting down...")
		rd.SetDeadline(time.Now())
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed || errors.Is(err, os.ErrDeadlineExceeded) {
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
		mu.Lock()
		w.Write(line)
		w.WriteByte('\n')
		// In stdio mode flush immediately so events are visible in the runner
		// log without waiting for the 64 KiB buffer to fill or a clean exit.
		if *outputFile == "-" {
			w.Flush()
		}
		mu.Unlock()
		// Register in the shared dedup map so the proc scanner does not
		// re-emit this connection on its next poll cycle.
		dedup.Record(je.Process.Pid, je.Network.Protocol, je.Source.IP, je.Source.Port, je.Destination.IP, je.Destination.Port)
	}

	log.Println("ebpf-tracker stopped")
}
