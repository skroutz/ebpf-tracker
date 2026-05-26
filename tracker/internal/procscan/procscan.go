//go:build linux

// Package procscan supplements eBPF-based connection tracking by polling
// /proc/net/{tcp,tcp6,udp,udp6}. This catches connections that were
// established before the eBPF hooks were attached — for example, TLS
// handshakes performed by steps that ran before the tracker action step.
package procscan

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skroutz/ebpf-tracker/internal/events"
)

// interestingTCPStates are the only TCP states we report.
//
//   - ESTABLISHED (01): active connection
//   - TIME_WAIT   (06): recently closed — kernel holds ~60 s, lets us
//     retroactively detect connections made before the tracker started
//   - CLOSE_WAIT  (08): remote side closed, local side still open
var interestingTCPStates = map[string]bool{
	"01": true,
	"06": true,
	"08": true,
}

// ---------------------------------------------------------------------------
// Dedup — shared between the eBPF reader and the proc scanner
// ---------------------------------------------------------------------------

// Dedup prevents duplicate events when both the eBPF path and the proc scanner
// observe the same connection. The eBPF reader calls Record after emitting an
// event; the proc scanner calls SeenAndRecord, which is an atomic check-and-set.
type Dedup struct {
	mu  sync.Mutex
	m   map[string]time.Time
	ttl time.Duration
}

// NewDedup creates a Dedup with the given TTL.
// A TTL of 5 minutes is appropriate for most GHA jobs.
func NewDedup(ttl time.Duration) *Dedup {
	return &Dedup{m: make(map[string]time.Time), ttl: ttl}
}

func dedupKey(pid uint32, proto, srcIP string, srcPort uint16, dstIP string, dstPort uint16) string {
	if pid != 0 {
		// eBPF source ports can be unreliable (may be 0 pre-bind), so for
		// known PIDs we key on (pid, proto, dst) only — same granularity as
		// the BPF-level UDP LRU map.
		return fmt.Sprintf("%d|%s|%s|%d", pid, proto, dstIP, dstPort)
	}
	// Unknown PID (e.g. TIME_WAIT after process exit): use full 5-tuple.
	return fmt.Sprintf("0|%s|%s|%d|%s|%d", proto, srcIP, srcPort, dstIP, dstPort)
}

// Record marks a connection as already emitted by the eBPF path.
func (d *Dedup) Record(pid uint32, proto, srcIP string, srcPort uint16, dstIP string, dstPort uint16) {
	k := dedupKey(pid, proto, srcIP, srcPort, dstIP, dstPort)
	d.mu.Lock()
	d.m[k] = time.Now()
	d.mu.Unlock()
}

// SeenAndRecord atomically checks if a connection is within the dedup window
// and, if not, records it. Returns true if the event should be suppressed
// (i.e. already emitted recently by either source).
func (d *Dedup) SeenAndRecord(pid uint32, proto, srcIP string, srcPort uint16, dstIP string, dstPort uint16) bool {
	k := dedupKey(pid, proto, srcIP, srcPort, dstIP, dstPort)
	d.mu.Lock()
	defer d.mu.Unlock()
	if t, ok := d.m[k]; ok && time.Since(t) < d.ttl {
		return true
	}
	d.m[k] = time.Now()
	return false
}

// Purge removes expired entries. Call periodically to bound map growth.
func (d *Dedup) Purge() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, t := range d.m {
		if time.Since(t) >= d.ttl {
			delete(d.m, k)
		}
	}
}

// ---------------------------------------------------------------------------
// /proc/net parsing helpers
// ---------------------------------------------------------------------------

// parseIPv4 decodes a little-endian 32-bit hex word to dotted-decimal.
// e.g. "0100007F" → "127.0.0.1"
func parseIPv4(hexIP string) string {
	n, err := strconv.ParseUint(hexIP, 16, 32)
	if err != nil {
		return "0.0.0.0"
	}
	return fmt.Sprintf("%d.%d.%d.%d",
		n&0xff, (n>>8)&0xff, (n>>16)&0xff, (n>>24)&0xff)
}

// parseIPv6 decodes four consecutive little-endian 32-bit hex words to a
// canonical IPv6 address string.
// e.g. "00470626..." → "2606:4700:..."
func parseIPv6(hexIP string) string {
	if len(hexIP) != 32 {
		return "::"
	}
	var b [16]byte
	for i := 0; i < 4; i++ {
		n, _ := strconv.ParseUint(hexIP[i*8:i*8+8], 16, 32)
		// LE storage → big-endian (network) byte order
		b[i*4+0] = byte(n & 0xff)
		b[i*4+1] = byte((n >> 8) & 0xff)
		b[i*4+2] = byte((n >> 16) & 0xff)
		b[i*4+3] = byte((n >> 24) & 0xff)
	}
	return net.IP(b[:]).String()
}

// unmapIPv4 extracts the dotted-decimal IPv4 from an IPv4-mapped IPv6 string
// (::ffff:x.x.x.x), or returns "" for genuine IPv6 addresses.
func unmapIPv4(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	// To4() succeeds for both plain IPv4 and IPv4-mapped IPv6. Only remap if
	// the original string was in IPv6 notation (contains a colon).
	if v4 := ip.To4(); v4 != nil && strings.Contains(ipStr, ":") {
		return v4.String()
	}
	return ""
}

// ---------------------------------------------------------------------------
// Inode → process mapping
// ---------------------------------------------------------------------------

type inodeInfo struct {
	pid  uint32
	uid  uint32
	comm string
}

// buildInodeMap scans /proc/<pid>/fd/ symlinks to build a map of socket
// inode string → process info. Running as root gives access to all processes.
func buildInodeMap() map[string]inodeInfo {
	m := make(map[string]inodeInfo)

	procs, err := os.ReadDir("/proc")
	if err != nil {
		return m
	}

	for _, proc := range procs {
		if !proc.IsDir() {
			continue
		}
		pidStr := proc.Name()
		if _, err := strconv.ParseUint(pidStr, 10, 32); err != nil {
			continue // skip non-numeric /proc entries
		}

		fdDir := filepath.Join("/proc", pidStr, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // process may have exited
		}

		var comm string
		if b, err := os.ReadFile(filepath.Join("/proc", pidStr, "comm")); err == nil {
			comm = strings.TrimSpace(string(b))
		}

		// Read the effective UID from the first Uid: line in /proc/<pid>/status.
		var uid uint32
		if b, err := os.ReadFile(filepath.Join("/proc", pidStr, "status")); err == nil {
			for _, line := range strings.SplitN(string(b), "\n", 60) {
				if strings.HasPrefix(line, "Uid:") {
					if fields := strings.Fields(line); len(fields) >= 2 {
						if v, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
							uid = uint32(v)
						}
					}
					break
				}
			}
		}

		pid64, _ := strconv.ParseUint(pidStr, 10, 32)
		pid := uint32(pid64)

		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			// Socket symlinks have the form "socket:[<inode>]".
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				inode := target[8 : len(target)-1]
				m[inode] = inodeInfo{pid: pid, uid: uid, comm: comm}
			}
		}
	}
	return m
}

// ---------------------------------------------------------------------------
// /proc/net file parsing
// ---------------------------------------------------------------------------

type connEntry struct {
	proto   string // "TCP" or "UDP"
	srcIP   string
	srcPort uint16
	dstIP   string
	dstPort uint16
	pid     uint32
	uid     uint32
	comm    string
}

// parseProcNet parses one /proc/net/{tcp,tcp6,udp,udp6} file and returns
// entries that pass the state/connectivity filter.
//
// /proc/net/tcp column layout (space-separated after trim):
//
//	[0] sl  [1] local_addr:port  [2] rem_addr:port  [3] state  [4] tx:rx_queue
//	[5] timer  [6] retransmit  [7] uid  [8] timeout  [9] inode  …
func parseProcNet(path string, isIPv6, isUDP bool, inodes map[string]inodeInfo) []connEntry {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // file absent on kernels without IPv6 etc.
	}

	zeroRemote := "00000000"
	if isIPv6 {
		zeroRemote = strings.Repeat("0", 32)
	}
	proto := "tcp"
	if isUDP {
		proto = "udp"
	}

	var out []connEntry
	for i, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if i == 0 {
			continue // header row
		}
		cols := strings.Fields(strings.TrimSpace(line))
		if len(cols) < 10 {
			continue
		}

		localParts := strings.SplitN(cols[1], ":", 2)
		remoteParts := strings.SplitN(cols[2], ":", 2)
		if len(localParts) != 2 || len(remoteParts) != 2 {
			continue
		}
		localAddrHex, localPortHex := localParts[0], localParts[1]
		remoteAddrHex, remotePortHex := remoteParts[0], remoteParts[1]
		stateHex := strings.ToUpper(cols[3])
		inode := cols[9]

		if isUDP {
			// Only connected UDP sockets (remote address is non-zero).
			if remoteAddrHex == zeroRemote {
				continue
			}
		} else {
			if !interestingTCPStates[stateHex] {
				continue
			}
		}

		var srcIP, dstIP string
		if isIPv6 {
			srcIP = parseIPv6(localAddrHex)
			dstIP = parseIPv6(remoteAddrHex)
			// Collapse IPv4-mapped IPv6 (::ffff:x.x.x.x) to plain IPv4,
			// matching what the eBPF path reports.
			if mapped := unmapIPv4(dstIP); mapped != "" {
				dstIP = mapped
			}
			if mapped := unmapIPv4(srcIP); mapped != "" {
				srcIP = mapped
			}
		} else {
			srcIP = parseIPv4(localAddrHex)
			dstIP = parseIPv4(remoteAddrHex)
		}

		srcPortN, _ := strconv.ParseUint(localPortHex, 16, 16)
		dstPortN, _ := strconv.ParseUint(remotePortHex, 16, 16)

		e := connEntry{
			proto:   proto,
			srcIP:   srcIP,
			srcPort: uint16(srcPortN),
			dstIP:   dstIP,
			dstPort: uint16(dstPortN),
		}
		if info, ok := inodes[inode]; ok {
			e.pid = info.pid
			e.uid = info.uid
			e.comm = info.comm
		}
		out = append(out, e)
	}
	return out
}

// ---------------------------------------------------------------------------
// Scanner
// ---------------------------------------------------------------------------

// Scanner polls /proc/net/* at a configurable interval and emits JSONEvents
// for connections not already reported by the eBPF path.
type Scanner struct {
	interval     time.Duration
	dedup        *Dedup
	w            *bufio.Writer
	mu           *sync.Mutex
	runID        string
	repository   string
	workflowName string
}

// NewScanner creates a Scanner. w and mu must be the same writer and mutex
// used by the eBPF read loop so that output is serialised correctly.
func NewScanner(
	interval time.Duration,
	dedup *Dedup,
	w *bufio.Writer,
	mu *sync.Mutex,
	runID, repository, workflowName string,
) *Scanner {
	return &Scanner{
		interval:     interval,
		dedup:        dedup,
		w:            w,
		mu:           mu,
		runID:        runID,
		repository:   repository,
		workflowName: workflowName,
	}
}

// Run blocks, polling every s.interval, until ctx is cancelled.
func (s *Scanner) Run(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	purgeN := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.poll()
			purgeN++
			if purgeN%50 == 0 { // purge expired entries every ~10 s at 200 ms
				s.dedup.Purge()
			}
		}
	}
}

func (s *Scanner) poll() {
	inodes := buildInodeMap()
	now := time.Now().UTC().Format(time.RFC3339)

	sources := []struct {
		path   string
		isIPv6 bool
		isUDP  bool
	}{
		{"/proc/net/tcp", false, false},
		{"/proc/net/tcp6", true, false},
		{"/proc/net/udp", false, true},
		{"/proc/net/udp6", true, true},
	}

	ghURL := ""
	if s.repository != "" && s.runID != "" && s.runID != "local" {
		ghURL = "https://github.com/" + s.repository + "/actions/runs/" + s.runID + "/"
	}

	var lines [][]byte
	for _, src := range sources {
		for _, e := range parseProcNet(src.path, src.isIPv6, src.isUDP, inodes) {
			if s.dedup.SeenAndRecord(e.pid, e.proto, e.srcIP, e.srcPort, e.dstIP, e.dstPort) {
				continue
			}
			je := events.JSONEvent{
				Timestamp: now,
				Network: events.NetworkFields{
					Protocol: e.proto,
				},
				Source: events.EndpointFields{
					IP:   e.srcIP,
					Port: e.srcPort,
				},
				Destination: events.EndpointFields{
					IP:   e.dstIP,
					Port: e.dstPort,
				},
				Process: events.ProcessFields{
					Pid:      e.pid,
					Name:     e.comm,
					ExitCode: 0,
				},
				User: events.UserFields{
					ID: strconv.FormatUint(uint64(e.uid), 10),
				},
				Event: events.EventFields{
					ID:   s.runID,
					Type: "connection",
				},
				GitHub: events.GitHubFields{
					URL:           ghURL,
					Repository:    s.repository,
					WorkflowID:    s.workflowName,
					WorkflowRunID: s.runID,
				},
			}
			line, err := events.Marshal(je)
			if err != nil {
				log.Printf("procscan: marshal: %v", err)
				continue
			}
			lines = append(lines, line)
		}
	}

	if len(lines) == 0 {
		return
	}

	// Write all new events under the shared mutex so eBPF and proc-scan
	// output is interleaved correctly without torn writes.
	s.mu.Lock()
	for _, line := range lines {
		s.w.Write(line)
		s.w.WriteByte('\n')
	}
	s.w.Flush()
	s.mu.Unlock()
}
