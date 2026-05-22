// Package events decodes raw BPF ring buffer records and formats them as JSON.
// It has no dependency on the cilium/ebpf runtime or any Linux-specific
// syscall, so it can be compiled and tested on any platform.
package events

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ProtoTCP uint8 = 6
	ProtoUDP uint8 = 17
	AFINET   uint8 = 2
	AFINET6  uint8 = 10

	// RawPayloadSize is the number of meaningful bytes read from a ring buffer
	// record. The C struct net_event has 2 bytes of tail padding on amd64
	// (sizeof == 80), but those bytes carry no data and are intentionally
	// ignored during parsing.
	RawPayloadSize = 78
)

// RawEvent mirrors the C struct net_event from network_tracker.h.
type RawEvent struct {
	TimestampNs uint64
	SrcIP4      uint32
	DstIP4      uint32
	SrcIP6      [16]byte
	DstIP6      [16]byte
	SrcPort     uint16
	DstPort     uint16
	Pid         uint32
	Uid         uint32
	Proto       uint8
	Af          uint8
	Comm        [16]byte
}

// JSONEvent is the canonical JSONL record written to the output file.
type JSONEvent struct {
	Timestamp    string `json:"timestamp"`
	RunID        string `json:"run_id"`
	Repository   string `json:"repository"`
	WorkflowName string `json:"workflow_name"`
	Protocol     string `json:"protocol"`
	SrcIP        string `json:"src_ip"`
	SrcPort      uint16 `json:"src_port"`
	DstIP        string `json:"dst_ip"`
	DstPort      uint16 `json:"dst_port"`
	Pid          uint32 `json:"pid"`
	ProcessName  string `json:"process_name"`
	Uid          uint32 `json:"uid"`
}

// Parse decodes a raw ring buffer byte slice into a RawEvent.
// The slice must be at least RawEventSize bytes long.
func Parse(b []byte) (RawEvent, error) {
	if len(b) < RawPayloadSize {
		return RawEvent{}, fmt.Errorf("record too short: got %d bytes, need %d", len(b), RawPayloadSize)
	}

	var e RawEvent
	e.TimestampNs = binary.LittleEndian.Uint64(b[0:8])
	e.SrcIP4 = binary.LittleEndian.Uint32(b[8:12])
	e.DstIP4 = binary.LittleEndian.Uint32(b[12:16])
	copy(e.SrcIP6[:], b[16:32])
	copy(e.DstIP6[:], b[32:48])
	e.SrcPort = binary.LittleEndian.Uint16(b[48:50])
	e.DstPort = binary.LittleEndian.Uint16(b[50:52])
	e.Pid = binary.LittleEndian.Uint32(b[52:56])
	e.Uid = binary.LittleEndian.Uint32(b[56:60])
	e.Proto = b[60]
	e.Af = b[61]
	copy(e.Comm[:], b[62:78])
	return e, nil
}

// Format converts a RawEvent to its JSONEvent representation.
// bootTime is the wall-clock time at which the system last booted; the kernel
// timestamp (bpf_ktime_get_boot_ns, nanoseconds since boot) is added to it to
// produce a real UTC time. runID, repository, and workflowName are stamped on
// every event for correlation with the exact workflow run.
func Format(e RawEvent, bootTime time.Time, runID, repository, workflowName string) JSONEvent {
	ts := bootTime.Add(time.Duration(e.TimestampNs)).UTC()

	var srcIP, dstIP string
	if e.Af == AFINET {
		srcIP = ip4str(e.SrcIP4)
		dstIP = ip4str(e.DstIP4)
	} else {
		srcIP = ip6str(e.SrcIP6)
		dstIP = ip6str(e.DstIP6)
	}

	return JSONEvent{
		Timestamp:    ts.Format(time.RFC3339),
		RunID:        runID,
		Repository:   repository,
		WorkflowName: workflowName,
		Protocol:     protoName(e.Proto),
		SrcIP:       srcIP,
		SrcPort:     e.SrcPort,
		DstIP:       dstIP,
		DstPort:     e.DstPort,
		Pid:         e.Pid,
		ProcessName: commStr(e.Comm),
		Uid:         e.Uid,
	}
}

// Marshal serialises a JSONEvent to a JSON line (no trailing newline).
// HTML escaping is disabled so characters like < > & are preserved literally,
// matching the output of the json.Encoder used in the main writer.
func Marshal(j JSONEvent) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(j); err != nil {
		return nil, err
	}
	// Encoder appends a newline; strip it so callers control line endings.
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// BootTime reads the system boot time from /proc/stat (Linux only).
// It returns the UTC wall-clock time at which the kernel last booted.
// This is used to convert bpf_ktime_get_boot_ns values to real timestamps.
func BootTime() (time.Time, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return time.Time{}, fmt.Errorf("open /proc/stat: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			break
		}
		sec, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse btime: %w", err)
		}
		return time.Unix(sec, 0).UTC(), nil
	}
	return time.Time{}, fmt.Errorf("btime not found in /proc/stat")
}

// --- helpers ----------------------------------------------------------------

func protoName(p uint8) string {
	switch p {
	case ProtoTCP:
		return "TCP"
	case ProtoUDP:
		return "UDP"
	default:
		return fmt.Sprintf("unknown(%d)", p)
	}
}

func commStr(b [16]byte) string {
	n := 0
	for n < len(b) && b[n] != 0 {
		n++
	}
	s := string(b[:n])
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, string(utf8.RuneError))
	}
	return s
}

func ip4str(raw uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, raw)
	return net.IP(b).String()
}

func ip6str(raw [16]byte) string {
	return net.IP(raw[:]).String()
}
