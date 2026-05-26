package events_test

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/skroutz/ebpf-tracker/internal/events"
)

// buildRaw constructs a raw byte slice matching the struct net_event layout.
func buildRaw(
	tsNs uint64,
	srcIP4, dstIP4 uint32,
	srcIP6, dstIP6 [16]byte,
	srcPort, dstPort uint16,
	pid, uid uint32,
	ret int32,
	proto, af uint8,
	comm string,
) []byte {
	b := make([]byte, events.RawPayloadSize)
	binary.LittleEndian.PutUint64(b[0:8], tsNs)
	binary.LittleEndian.PutUint32(b[8:12], srcIP4)
	binary.LittleEndian.PutUint32(b[12:16], dstIP4)
	copy(b[16:32], srcIP6[:])
	copy(b[32:48], dstIP6[:])
	binary.LittleEndian.PutUint16(b[48:50], srcPort)
	binary.LittleEndian.PutUint16(b[50:52], dstPort)
	binary.LittleEndian.PutUint32(b[52:56], pid)
	binary.LittleEndian.PutUint32(b[56:60], uid)
	binary.LittleEndian.PutUint32(b[60:64], uint32(ret))
	b[64] = proto
	b[65] = af
	copy(b[66:82], []byte(comm))
	return b
}

// ip4le encodes a dotted-quad string as little-endian uint32 (kernel layout).
func ip4le(a, b2, c, d byte) uint32 {
	return uint32(a) | uint32(b2)<<8 | uint32(c)<<16 | uint32(d)<<24
}

// fixedBoot is the simulated system boot time used in all Format tests.
var fixedBoot = time.Date(2026, 5, 22, 11, 0, 0, 0, time.UTC)

// fixedNow is one hour after boot. Tests that want the formatted timestamp to
// equal fixedNow must pass uint64(time.Hour) as TimestampNs.
var fixedNow = fixedBoot.Add(time.Hour)

// oneHourNs is the TimestampNs value (nanoseconds since boot) that corresponds
// to fixedNow given fixedBoot.
const oneHourNs = uint64(time.Hour)

// -----------------------------------------------------------------------
// Parse tests
// -----------------------------------------------------------------------

func TestParse_TCP4(t *testing.T) {
	raw := buildRaw(
		1_000_000_000, // 1 s since boot
		ip4le(10, 1, 0, 5), ip4le(93, 184, 216, 34),
		[16]byte{}, [16]byte{},
		54321, 443,
		1234, 1001,
		0,
		events.ProtoTCP, events.AFINET,
		"curl",
	)

	e, err := events.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if e.Pid != 1234 {
		t.Errorf("pid: got %d, want 1234", e.Pid)
	}
	if e.Uid != 1001 {
		t.Errorf("uid: got %d, want 1001", e.Uid)
	}
	if e.SrcPort != 54321 {
		t.Errorf("src_port: got %d, want 54321", e.SrcPort)
	}
	if e.DstPort != 443 {
		t.Errorf("dst_port: got %d, want 443", e.DstPort)
	}
	if e.Proto != events.ProtoTCP {
		t.Errorf("proto: got %d, want %d", e.Proto, events.ProtoTCP)
	}
	if e.Af != events.AFINET {
		t.Errorf("af: got %d, want %d", e.Af, events.AFINET)
	}
}

func TestParse_UDP4(t *testing.T) {
	raw := buildRaw(
		500_000_000,
		ip4le(192, 168, 1, 10), ip4le(8, 8, 8, 8),
		[16]byte{}, [16]byte{},
		12345, 53,
		999, 0,
		0,
		events.ProtoUDP, events.AFINET,
		"systemd-resolve",
	)

	e, err := events.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if e.Proto != events.ProtoUDP {
		t.Errorf("proto: got %d, want UDP", e.Proto)
	}
	if e.DstPort != 53 {
		t.Errorf("dst_port: got %d, want 53", e.DstPort)
	}
}

func TestParse_IPv6(t *testing.T) {
	var src6, dst6 [16]byte
	// ::1
	src6[15] = 1
	// 2606:4700:4700::1111
	dst6[0] = 0x26
	dst6[1] = 0x06
	dst6[6] = 0x47
	dst6[7] = 0x00
	dst6[14] = 0x11
	dst6[15] = 0x11

	raw := buildRaw(
		200_000_000,
		0, 0,
		src6, dst6,
		33333, 443,
		555, 100,
		0,
		events.ProtoTCP, events.AFINET6,
		"wget",
	)

	e, err := events.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if e.Af != events.AFINET6 {
		t.Errorf("af: got %d, want AF_INET6", e.Af)
	}
	if e.SrcIP6 != src6 {
		t.Errorf("src_ip6 mismatch")
	}
}

func TestParse_TooShort(t *testing.T) {
	_, err := events.Parse(make([]byte, events.RawPayloadSize-1))
	if err == nil {
		t.Fatal("expected error for short record, got nil")
	}
}

func TestParse_ExactSize(t *testing.T) {
	raw := buildRaw(0, 0, 0, [16]byte{}, [16]byte{}, 0, 0, 0, 0, 0, events.ProtoTCP, events.AFINET, "")
	_, err := events.Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error for exact-size record: %v", err)
	}
}

func TestParse_LongerThanMinimum(t *testing.T) {
	// Ring buffer may pad records; Parse must tolerate extra bytes.
	padded := make([]byte, events.RawPayloadSize+32)
	raw := buildRaw(0, 0, 0, [16]byte{}, [16]byte{}, 0, 0, 0, 0, 0, events.ProtoTCP, events.AFINET, "")
	copy(padded, raw)
	_, err := events.Parse(padded)
	if err != nil {
		t.Fatalf("unexpected error for padded record: %v", err)
	}
}

// -----------------------------------------------------------------------
// Format / JSON schema tests
// -----------------------------------------------------------------------

func TestFormat_Schema_TCP4(t *testing.T) {
	raw := buildRaw(
		oneHourNs, // 1h since boot → timestamp equals fixedNow (fixedBoot + 1h)
		ip4le(10, 1, 0, 5), ip4le(93, 184, 216, 34),
		[16]byte{}, [16]byte{},
		54321, 443,
		1234, 1001,
		0,
		events.ProtoTCP, events.AFINET,
		"curl",
	)
	e, _ := events.Parse(raw)
	j := events.Format(e, fixedBoot, "test-run-id", "skroutz/my-repo", "CI")

	if j.Network.Protocol != "tcp" {
		t.Errorf("network.protocol: got %q, want \"tcp\"", j.Network.Protocol)
	}
	if j.Source.IP != "10.1.0.5" {
		t.Errorf("source.ip: got %q, want \"10.1.0.5\"", j.Source.IP)
	}
	if j.Destination.IP != "93.184.216.34" {
		t.Errorf("destination.ip: got %q, want \"93.184.216.34\"", j.Destination.IP)
	}
	if j.Source.Port != 54321 {
		t.Errorf("source.port: got %d, want 54321", j.Source.Port)
	}
	if j.Destination.Port != 443 {
		t.Errorf("destination.port: got %d, want 443", j.Destination.Port)
	}
	if j.Process.Pid != 1234 {
		t.Errorf("process.pid: got %d, want 1234", j.Process.Pid)
	}
	if j.Process.Name != "curl" {
		t.Errorf("process.name: got %q, want \"curl\"", j.Process.Name)
	}
	if j.User.ID != "1001" {
		t.Errorf("user.id: got %q, want \"1001\"", j.User.ID)
	}
	if j.Event.ID != "test-run-id" {
		t.Errorf("event.id: got %q, want \"test-run-id\"", j.Event.ID)
	}
	if j.GitHub.Repository != "skroutz/my-repo" {
		t.Errorf("github.repository: got %q, want \"skroutz/my-repo\"", j.GitHub.Repository)
	}
	if j.GitHub.WorkflowID != "CI" {
		t.Errorf("github.workflow_id: got %q, want \"CI\"", j.GitHub.WorkflowID)
	}
}

func TestFormat_RunID_Propagated(t *testing.T) {
	raw := buildRaw(0, 0, 0, [16]byte{}, [16]byte{}, 0, 0, 0, 0, 0, events.ProtoTCP, events.AFINET, "")
	e, _ := events.Parse(raw)

	for _, id := range []string{"12345678", "local", ""} {
		j := events.Format(e, fixedBoot,id, "skroutz/my-repo", "CI")
		if j.Event.ID != id {
			t.Errorf("event.id: got %q, want %q", j.Event.ID, id)
		}
	}
}

func TestFormat_RepositoryAndWorkflow_Propagated(t *testing.T) {
	raw := buildRaw(0, 0, 0, [16]byte{}, [16]byte{}, 0, 0, 0, 0, 0, events.ProtoTCP, events.AFINET, "")
	e, _ := events.Parse(raw)

	j := events.Format(e, fixedBoot, "42", "skroutz/ebpf-tracker", "Build and Publish")
	if j.GitHub.Repository != "skroutz/ebpf-tracker" {
		t.Errorf("github.repository: got %q, want \"skroutz/ebpf-tracker\"", j.GitHub.Repository)
	}
	if j.GitHub.WorkflowID != "Build and Publish" {
		t.Errorf("github.workflow_id: got %q, want \"Build and Publish\"", j.GitHub.WorkflowID)
	}
}

func TestFormat_Protocol_UDP(t *testing.T) {
	raw := buildRaw(0, 0, 0, [16]byte{}, [16]byte{}, 0, 53, 1, 0, 0, events.ProtoUDP, events.AFINET, "dig")
	e, _ := events.Parse(raw)
	j := events.Format(e, fixedBoot, "test-run-id", "skroutz/my-repo", "CI")
	if j.Network.Protocol != "udp" {
		t.Errorf("network.protocol: got %q, want \"udp\"", j.Network.Protocol)
	}
}

func TestFormat_Protocol_Unknown(t *testing.T) {
	// Any protocol value other than TCP(6) or UDP(17) must produce a
	// descriptive string rather than silently misreporting as "UDP".
	raw := buildRaw(0, 0, 0, [16]byte{}, [16]byte{}, 0, 0, 0, 0, 0, 132 /* SCTP */, events.AFINET, "")
	e, _ := events.Parse(raw)
	j := events.Format(e, fixedBoot, "", "", "")
	if j.Network.Protocol == "udp" || j.Network.Protocol == "tcp" {
		t.Errorf("unknown protocol silently mapped to %q, want \"unknown(132)\"", j.Network.Protocol)
	}
	if j.Network.Protocol != "unknown(132)" {
		t.Errorf("network.protocol: got %q, want \"unknown(132)\"", j.Network.Protocol)
	}
}

func TestFormat_CommInvalidUTF8(t *testing.T) {
	// A process can set its comm to arbitrary bytes via prctl(PR_SET_NAME).
	// Invalid UTF-8 sequences must be replaced, not passed through raw.
	raw := buildRaw(0, 0, 0, [16]byte{}, [16]byte{}, 0, 0, 0, 0, 0, events.ProtoTCP, events.AFINET, "")
	// Inject invalid UTF-8 bytes directly into the comm field of the raw record.
	raw[66] = 0xff
	raw[67] = 0xfe
	raw[68] = 0x00 // null terminator
	e, _ := events.Parse(raw)
	j := events.Format(e, fixedBoot, "", "", "")

	if !utf8.ValidString(j.Process.Name) {
		t.Errorf("process.name %q is not valid UTF-8", j.Process.Name)
	}
	// The replacement rune must appear in place of the invalid bytes.
	if !strings.Contains(j.Process.Name, string(utf8.RuneError)) {
		t.Errorf("expected replacement rune in process.name, got %q", j.Process.Name)
	}
}

func TestFormat_Timestamp_NotEpoch(t *testing.T) {
	// Regression test for the boot-offset bug. A TimestampNs of 30 minutes
	// (realistic for an event captured shortly after boot) must not produce a
	// timestamp near the Unix epoch (1970). With the old formula it would.
	thirtyMinNs := uint64(30 * time.Minute)
	raw := buildRaw(thirtyMinNs, 0, 0, [16]byte{}, [16]byte{}, 0, 0, 0, 0, 0, events.ProtoTCP, events.AFINET, "")
	e, _ := events.Parse(raw)
	j := events.Format(e, fixedBoot, "r", "repo", "wf")

	ts, err := time.Parse(time.RFC3339, j.Timestamp)
	if err != nil {
		t.Fatalf("not RFC3339: %v", err)
	}
	epoch := time.Unix(0, 0).UTC()
	if ts.Before(epoch.Add(24 * time.Hour)) {
		t.Errorf("timestamp %q is near the Unix epoch — boot-offset bug regression", j.Timestamp)
	}
	want := fixedBoot.Add(30 * time.Minute)
	if !ts.Equal(want) {
		t.Errorf("timestamp: got %v, want %v", ts, want)
	}
}

func TestFormat_Timestamp_RFC3339_UTC(t *testing.T) {
	raw := buildRaw(oneHourNs, 0, 0, [16]byte{}, [16]byte{}, 0, 0, 0, 0, 0, events.ProtoTCP, events.AFINET, "")
	e, _ := events.Parse(raw)
	j := events.Format(e, fixedBoot, "test-run-id", "skroutz/my-repo", "CI")

	ts, err := time.Parse(time.RFC3339, j.Timestamp)
	if err != nil {
		t.Fatalf("timestamp %q is not RFC3339: %v", j.Timestamp, err)
	}
	if ts.Location() != time.UTC {
		t.Errorf("timestamp not in UTC: %v", ts.Location())
	}
	// Must end with Z, not +00:00, for strict SIEM parsers.
	if !strings.HasSuffix(j.Timestamp, "Z") {
		t.Errorf("timestamp %q does not end with Z", j.Timestamp)
	}
}

func TestFormat_CommNullTerminated(t *testing.T) {
	// Kernel fills comm with null bytes after the name.
	raw := buildRaw(0, 0, 0, [16]byte{}, [16]byte{}, 0, 0, 0, 0, 0, events.ProtoTCP, events.AFINET, "python3")
	e, _ := events.Parse(raw)
	j := events.Format(e, fixedBoot, "test-run-id", "skroutz/my-repo", "CI")
	if j.Process.Name != "python3" {
		t.Errorf("process.name: got %q, want \"python3\"", j.Process.Name)
	}
}

func TestFormat_CommFull16Bytes(t *testing.T) {
	// A 15-char name with no null terminator within the 16-byte field.
	var comm [16]byte
	copy(comm[:], "systemd-resolved") // exactly 16 bytes
	raw := buildRaw(0, 0, 0, [16]byte{}, [16]byte{}, 0, 0, 0, 0, 0, events.ProtoTCP, events.AFINET, "")
	copy(raw[66:82], comm[:])
	e, _ := events.Parse(raw)
	j := events.Format(e, fixedBoot, "test-run-id", "skroutz/my-repo", "CI")
	if j.Process.Name != "systemd-resolved" {
		t.Errorf("process.name: got %q, want \"systemd-resolved\"", j.Process.Name)
	}
}

func TestFormat_IPv6Addresses(t *testing.T) {
	var src6 [16]byte
	src6[15] = 1 // ::1
	var dst6 [16]byte
	copy(dst6[:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}) // 2001:db8::1

	raw := buildRaw(0, 0, 0, src6, dst6, 0, 443, 0, 0, 0, events.ProtoTCP, events.AFINET6, "curl")
	e, _ := events.Parse(raw)
	j := events.Format(e, fixedBoot, "test-run-id", "skroutz/my-repo", "CI")

	if j.Source.IP != "::1" {
		t.Errorf("source.ip: got %q, want \"::1\"", j.Source.IP)
	}
	if j.Destination.IP != "2001:db8::1" {
		t.Errorf("destination.ip: got %q, want \"2001:db8::1\"", j.Destination.IP)
	}
}

// -----------------------------------------------------------------------
// Marshal / JSONL shape tests
// -----------------------------------------------------------------------

func TestMarshal_IsValidJSON(t *testing.T) {
	raw := buildRaw(
		oneHourNs,
		ip4le(10, 0, 0, 1), ip4le(1, 1, 1, 1),
		[16]byte{}, [16]byte{},
		55000, 443,
		42, 0,
		0,
		events.ProtoTCP, events.AFINET,
		"node",
	)
	e, _ := events.Parse(raw)
	j := events.Format(e, fixedBoot, "test-run-id", "skroutz/my-repo", "CI")
	b, err := events.Marshal(j)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw: %s", err, b)
	}
}

func TestMarshal_RequiredFieldsPresent(t *testing.T) {
	required := []string{
		"timestamp", "network", "source", "destination",
		"process", "user", "event", "github",
	}

	raw := buildRaw(0, 0, 0, [16]byte{}, [16]byte{}, 0, 0, 0, 0, 0, events.ProtoTCP, events.AFINET, "")
	e, _ := events.Parse(raw)
	j := events.Format(e, fixedBoot, "test-run-id", "skroutz/my-repo", "CI")
	b, _ := events.Marshal(j)

	var m map[string]any
	json.Unmarshal(b, &m)

	for _, field := range required {
		if _, ok := m[field]; !ok {
			t.Errorf("missing required field %q in JSON output", field)
		}
	}
}

func TestMarshal_NoHTMLEscaping(t *testing.T) {
	// Characters like < > & must appear literally, not as < / > / &.
	// This matters for SIEM ingestion where unicode escapes can break field parsing.
	raw := buildRaw(0, 0, 0, [16]byte{}, [16]byte{}, 0, 0, 0, 0, 0, events.ProtoTCP, events.AFINET, "a<b>c")
	e, _ := events.Parse(raw)
	j := events.Format(e, fixedBoot, "test-run-id", "skroutz/my-repo", "CI")
	b, _ := events.Marshal(j)
	out := string(b)
	// With HTML escaping ON, Go encodes < > & as < > &.
	// Confirm those escaped sequences are absent (i.e. escaping is disabled).
	if strings.Contains(out, "\\u003c") || strings.Contains(out, "\\u003e") || strings.Contains(out, "\\u0026") {
		t.Errorf("output contains HTML unicode escapes: %s", out)
	}
	// And confirm the characters are present literally.
	if !strings.Contains(out, "a<b>c") {
		t.Errorf("expected literal a<b>c in output, got: %s", out)
	}
}
