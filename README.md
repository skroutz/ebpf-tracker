# ebpf-tracker

A GitHub Action that uses eBPF to track all TCP and UDP network connections made by a GitHub Actions runner, and uploads the log to S3 at the end of the job.

## How it works

```
┌─────────────────────────────────────────────────────┐
│                  GitHub Runner                       │
│                                                      │
│  main.js                                             │
│  ├── pulls ebpf-tracker binary from ghcr.io via ORAS │
│  └── spawns it in the background (detached)          │
│                                                      │
│  ebpf-tracker (Go binary)                            │
│  ├── loads BPF program into the kernel               │
│  ├── hooks: tcp_v4/v6_connect, udp_send/recvmsg,      │
  │          udpv6_send/recvmsg (best-effort)           │
│  └── writes JSONL → /tmp/ebpf-network-events.json    │
│                                                      │
│  post.js  (runs automatically after the job)         │
│  ├── sends SIGTERM to the tracker (graceful flush)    │
│  └── aws s3 cp → s3://<bucket>/<repo>/<workflow>/<run-id>-network.json │
└─────────────────────────────────────────────────────┘
```

The BPF program uses CO-RE (Compile Once, Run Everywhere) so the same binary runs on any kernel with BTF enabled (Linux 5.8+, which covers all current `ubuntu-*` GitHub-hosted runners).

## Log format

One JSON object per line (JSONL), SIEM-compatible:

```json
{"timestamp":"2026-05-21T21:20:09Z","run_id":"12345678","repository":"skroutz/my-repo","workflow_name":"CI","protocol":"TCP","src_ip":"10.1.0.5","src_port":54321,"dst_ip":"93.184.216.34","dst_port":443,"pid":1234,"process_name":"curl","uid":1001}
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
- Kernel: 5.8+ with BTF enabled (`/sys/kernel/btf/vmlinux` must exist)
- Runner must have `CAP_BPF` and `CAP_NET_ADMIN` (GitHub-hosted runners run as root)
- AWS CLI available on the runner (pre-installed on all GitHub-hosted runners)
- ORAS CLI available on the runner (installed by the action at startup)
