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

	// RawPayloadSize is the number of meaningful bytes in a ring buffer record.
	// Layout (amd64): timestamp_ns(8) src_ip4(4) dst_ip4(4) src_ip6(16)
	// dst_ip6(16) src_port(2) dst_port(2) pid(4) uid(4) ret(4) proto(1) af(1)
	// comm(16) = 82 bytes. sizeof(net_event) == 88 (6 bytes tail padding).
	RawPayloadSize = 82
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
	Ret         int32  // kernel return value; TCP: 0/-EINPROGRESS/error; UDP: 0
	Proto       uint8
	Af          uint8
	Comm        [16]byte
}

// The following types follow the Elastic Common Schema (ECS) namespace
// structure. Each nested struct maps to one top-level ECS namespace.

// NetworkFields holds ECS network.* fields.
type NetworkFields struct {
	Protocol string `json:"protocol"` // "tcp", "udp", or "unknown(<n>)"
}

// EndpointFields holds ECS source.* / destination.* fields.
type EndpointFields struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

// ProcessFields holds ECS process.* fields.
type ProcessFields struct {
	Pid      uint32 `json:"pid"`
	Name     string `json:"name"`
	ExitCode int32  `json:"exit_code"` // kernel return value: 0 = success, negative = errno
}

// UserFields holds ECS user.* fields.
type UserFields struct {
	ID string `json:"id"` // Linux UID as string (ECS keyword type)
}

// EventFields holds ECS event.* fields.
type EventFields struct {
	ID   string `json:"id"`   // GitHub run ID
	Type string `json:"type"` // always "connection"
}

// GitHubFields holds custom github.* fields for workflow correlation.
type GitHubFields struct {
	URL           string `json:"url"`             // e.g. https://github.com/org/repo/actions/runs/123/
	Repository    string `json:"repository"`      // GITHUB_REPOSITORY
	WorkflowID    string `json:"workflow_id"`     // GITHUB_WORKFLOW
	WorkflowRunID string `json:"workflow_run_id"` // GITHUB_RUN_ID (mirrors event.id)
}

// JSONEvent is the canonical JSONL record written to the output file.
// Field names are ECS-aligned for direct ingestion into Elastic SIEM.
type JSONEvent struct {
	Timestamp   string         `json:"timestamp"`
	Network     NetworkFields  `json:"network"`
	Source      EndpointFields `json:"source"`
	Destination EndpointFields `json:"destination"`
	Process     ProcessFields  `json:"process"`
	User        UserFields     `json:"user"`
	Event       EventFields    `json:"event"`
	GitHub      GitHubFields   `json:"github"`
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
	e.Ret = int32(binary.LittleEndian.Uint32(b[60:64]))
	e.Proto = b[64]
	e.Af = b[65]
	copy(e.Comm[:], b[66:82])
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

	ghURL := ""
	if repository != "" && runID != "" && runID != "local" {
		ghURL = "https://github.com/" + repository + "/actions/runs/" + runID + "/"
	}

	return JSONEvent{
		Timestamp: ts.Format(time.RFC3339),
		Network: NetworkFields{
			Protocol: protoName(e.Proto),
		},
		Source: EndpointFields{
			IP:   srcIP,
			Port: e.SrcPort,
		},
		Destination: EndpointFields{
			IP:   dstIP,
			Port: e.DstPort,
		},
		Process: ProcessFields{
			Pid:      e.Pid,
			Name:     commStr(e.Comm),
			ExitCode: e.Ret,
		},
		User: UserFields{
			ID: strconv.FormatUint(uint64(e.Uid), 10),
		},
		Event: EventFields{
			ID:   runID,
			Type: "connection",
		},
		GitHub: GitHubFields{
			URL:           ghURL,
			Repository:    repository,
			WorkflowID:    workflowName,
			WorkflowRunID: runID,
		},
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
		return "tcp"
	case ProtoUDP:
		return "udp"
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
