# ebpf-tracker

A GitHub Action that uses eBPF to track every TCP and UDP network connection attempt made by a GitHub Actions runner — including failed ones — and uploads the log to S3 at the end of the job.

## How it works

```
┌──────────────────────────────────────────────────────────────┐
│                      GitHub Runner                            │
│                                                               │
│  main.js                                                      │
│  ├── pulls ebpf-tracker binary from ghcr.io via ORAS         │
│  ├── writes a sudoers drop-in (NOPASSWD + env_keep for       │
│  │   GITHUB_* vars + !use_pty so sudo exec()s the binary)    │
│  ├── spawns tracker as root in the background (detached)     │
│  └── polls /tmp/ebpf-tracker.pid until the tracker confirms  │
│      it is live, then saves the exact PID in action state    │
│                                                               │
│  ebpf-tracker (Go binary, runs as root)                      │
│  ├── removes the memlock rlimit, loads BPF CO-RE objects     │
│  ├── writes its own PID to /tmp/ebpf-tracker.pid             │
│  ├── attaches BPF programs:                                   │
│  │     fexit/tcp_v4_connect   — TCP/IPv4 (captures ret code) │
│  │     fexit/tcp_v6_connect   — TCP/IPv6 (captures ret code) │
│  │     fentry/udp_sendmsg     — UDP/IPv4 send  (deduplicated)│
│  │     fentry/udp_recvmsg     — UDP/IPv4 recv  (deduplicated)│
│  │     kprobe/udpv6_sendmsg   — UDP/IPv6 send  (best-effort) │
│  │     kprobe/udpv6_recvmsg   — UDP/IPv6 recv  (best-effort) │
│  └── reads ring buffer → writes JSONL to output              │
│                                                               │
│  post.js  (runs automatically after the job)                 │
│  ├── sends SIGTERM to the exact tracker PID (graceful flush)  │
│  ├── waits up to 15 s; escalates to SIGKILL if needed        │
│  └── aws s3 cp → s3://<bucket>/<repo>/<workflow>/<run-id>-network.json │
└──────────────────────────────────────────────────────────────┘
```

The BPF program uses CO-RE (Compile Once, Run Everywhere) so the same binary runs on any kernel with BTF enabled (Linux 5.8+, which covers all current `ubuntu-*` GitHub-hosted runners). The `fexit`/`fentry` program types require kernel 5.5+.

### BPF hook strategy

| Hook type | Programs | Why |
|---|---|---|
| `fexit` | `tcp_v4_connect`, `tcp_v6_connect` | Fires after the kernel sets the destination address and returns; lets us capture both the destination (from the `uaddr` kernel-stack copy, always reliable) and the kernel return code (`0`/`-EINPROGRESS` = SYN queued, negative = error). |
| `fentry` | `udp_sendmsg`, `udp_recvmsg` | Fires before the kernel modifies arguments; lets us read `msg_name` for unconnected sockets (e.g. DNS queries). Events are deduplicated per `(pid, dst_ip, dst_port)` within a 1-second window via an LRU hash map to suppress burst repetition. |
| `kprobe` | `udpv6_sendmsg`, `udpv6_recvmsg` | IPv6 UDP; best-effort (not present on all kernels). Also deduplicated. |

**All connection attempts are recorded**, including those that fail with `EHOSTUNREACH`, `ECONNREFUSED`, `ETIMEDOUT`, etc. Only pure argument errors (`EINVAL`, `EAFNOSUPPORT`) are silently dropped. This is intentional: malware commonly tries to connect to domains/IPs that become active later in a campaign.

## Log format

One JSON object per line (JSONL), SIEM-compatible:

```json
{"timestamp":"2026-05-21T21:20:09Z","run_id":"12345678","repository":"skroutz/my-repo","workflow_name":"CI","protocol":"TCP","src_ip":"10.1.0.5","src_port":54321,"dst_ip":"93.184.216.34","dst_port":443,"pid":1234,"process_name":"curl","uid":1001,"ret":0}
```

| Field | Type | Description |
|---|---|---|
| `timestamp` | string | RFC3339 UTC |
| `run_id` | string | `GITHUB_RUN_ID` — correlates the event with an exact workflow run (`"local"` when run outside Actions) |
| `repository` | string | `GITHUB_REPOSITORY` (e.g. `skroutz/my-repo`) |
| `workflow_name` | string | `GITHUB_WORKFLOW` (e.g. `CI`) |
| `protocol` | string | `TCP` or `UDP` |
| `src_ip` | string | Source IP (v4 or v6) |
| `src_port` | number | Source port |
| `dst_ip` | string | Destination IP (v4 or v6) |
| `dst_port` | number | Destination port |
| `pid` | number | Process ID |
| `process_name` | string | Process name (`comm`, max 15 chars) |
| `uid` | number | User ID |
| `ret` | number | Kernel return value. TCP: `0` or `-EINPROGRESS` = connection initiated; negative errno = failed attempt. UDP: always `0`. |


## Usage

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    permissions:
      id-token: write   # required for OIDC → AWS
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Track network connections
        uses: skroutz/ebpf-tracker@main
        with:
          s3-bucket: my-security-logs-bucket

      # ... your normal job steps ...
```

The action starts the tracker before your steps run and stops it automatically via the `post` hook after the job completes.

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `s3-bucket` | When `output` is `s3` | — | S3 bucket name where the log file is uploaded |
| `output` | No | `s3` | `s3` — upload to S3 at job end; `stdio` — print events to the runner log (no S3 needed, useful for testing) |

### S3 output path

```
s3://<bucket>/<github-repository>/<workflow-name>/<run-id>-network.json
```

Example: `s3://my-bucket/skroutz/my-repo/ci/12345678-network.json`

The workflow name is lowercased and non-alphanumeric characters are replaced with `-` to produce a safe path component.

### Stdio mode (for testing/debugging)

```yaml
- uses: skroutz/ebpf-tracker@main
  with:
    output: stdio
```

Events are printed directly to the Actions run log. No S3 credentials required.

### AWS credentials

The runner must have permission to call `s3:PutObject` on the target bucket. The recommended approach is OIDC:

```yaml
permissions:
  id-token: write

- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/github-actions-s3-logs
    aws-region: eu-west-1
```

## Repository structure

```
.
├── action.yml                          # Action metadata
├── src/
│   ├── main.js                         # Pulls binary, starts tracker
│   └── post.js                         # Stops tracker, uploads to S3
├── tracker/
│   ├── bpf/
│   │   ├── network_tracker.c           # eBPF CO-RE program (C)
│   │   └── network_tracker.h           # Shared struct definitions
│   ├── cmd/
│   │   └── main.go                     # Go userspace program
│   ├── internal/events/
│   │   ├── events.go                   # Event parsing & JSON formatting
│   │   └── events_test.go              # Unit tests (runs on any OS)
│   └── go.mod
└── .github/workflows/
    └── build-and-publish.yml           # Builds binary, pushes to ghcr.io
```

## Building

### Prerequisites (Linux only)

```bash
sudo apt-get install clang llvm libelf-dev libbpf-dev linux-headers-$(uname -r)
# bpftool: package name depends on kernel flavour (generic, azure, aws, …)
sudo apt-get install "linux-tools-$(uname -r)" || \
  sudo apt-get install "linux-tools-$(uname -r | sed 's/.*-//')"
go install github.com/cilium/ebpf/cmd/bpf2go@v0.17.0
```

### Build the tracker binary

```bash
make build
# → tracker/ebpf-tracker  (static ELF, no dependencies)
```

### Run unit tests (any OS)

```bash
cd tracker
go test ./internal/events/...
```

### Build the JS action dist

```bash
npm install
npm run build
# → dist/main.js  dist/post.js
```

## CI/CD

Pushing to `main` triggers `.github/workflows/build-and-publish.yml`, which runs two isolated jobs:

**`build`** (`permissions: contents: read, packages: write`):
1. Generates `vmlinux.h` from the runner kernel's BTF
2. Compiles the C eBPF program and generates the Go skeleton via `bpf2go`
3. Runs unit tests (`go test ./internal/...`)
4. Builds a fully static Go binary (`CGO_ENABLED=0`)
5. Pushes the binary to `ghcr.io/skroutz/ebpf-tracker:latest` as an OCI artifact via [ORAS](https://oras.land)
6. Builds the Node.js action dist and uploads it as a workflow artifact

**`publish-dist`** (`permissions: contents: write`):
7. Downloads the dist artifact and commits it back to `main`

The jobs are intentionally split so the build environment (which runs external tools) cannot push to the repository.

## Requirements

- Runner OS: Linux (Ubuntu 22.04+ recommended)
- Kernel: 5.8+ with BTF enabled (`/sys/kernel/btf/vmlinux` must exist); `fexit`/`fentry` hooks require 5.5+ (both conditions are satisfied by any current `ubuntu-*` GitHub-hosted runner)
- Runner must have `CAP_BPF` and `CAP_NET_ADMIN` (GitHub-hosted runners run as root)
- AWS CLI available on the runner (pre-installed on all GitHub-hosted runners)
- ORAS CLI available on the runner (installed by the action at startup)
