# ebpf-tracker

A GitHub Action that uses eBPF to track every TCP and UDP network connection attempt made by a GitHub Actions runner — including failed ones — and uploads the log to S3 at the end of the job.

## How it works

```
┌──────────────────────────────────────────────────────────────┐
│                      GitHub Runner                            │
│                                                               │
│  main.js                                                      │
│  ├── pulls ebpf-tracker binary from ghcr.io via ORAS         │
│  ├── writes a sudoers drop-in (NOPASSWD + !use_pty so sudo   │
│  │   exec()s directly + env_keep for GITHUB_* vars)          │
│  ├── spawns the tracker as root in the background (detached) │
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
│  └── reads ring buffer → writes JSONL to /tmp/ebpf-network-events.json │
│                                                               │
│  post.js  (runs automatically after all job steps)           │
│  ├── sends SIGTERM to the exact tracker PID (graceful flush)  │
│  ├── waits up to 15 s for clean exit; escalates to SIGKILL   │
│  └── aws s3 cp /tmp/ebpf-network-events.json → s3://…       │
│      (if s3-bucket is omitted, prints the file to the log)   │
└──────────────────────────────────────────────────────────────┘
```

The BPF program uses CO-RE (Compile Once, Run Everywhere) so the same binary runs on any kernel with BTF enabled (Linux 5.8+, which covers all current `ubuntu-*` GitHub-hosted runners). The `fexit`/`fentry` program types require kernel 5.5+.

### BPF hook strategy

| Hook type | Programs | Why |
|---|---|---|
| `fexit` | `tcp_v4_connect`, `tcp_v6_connect` | Fires after the kernel returns; lets us capture the destination (read from the kernel-stack copy of `uaddr`, always reliable) and the return code (`0`/`-EINPROGRESS` = SYN queued, negative errno = failed attempt). |
| `fentry` | `udp_sendmsg`, `udp_recvmsg` | Fires before the kernel modifies arguments. Reads `msg_name` with a kernel-pointer probe first (the path taken by `sendto()`), falling back to a user-pointer probe (the path taken by `sendmsg()`, e.g. `dig`). Events are deduplicated per `(pid, dst_ip, dst_port)` within a 1-second window via an LRU hash map. |
| `kprobe` | `udpv6_sendmsg`, `udpv6_recvmsg` | IPv6 UDP; best-effort (not present on all kernels). Also deduplicated. |

**All connection attempts are recorded**, including those that fail with `EHOSTUNREACH`, `ECONNREFUSED`, `ETIMEDOUT`, etc. Only pure argument errors (`EINVAL`, `EAFNOSUPPORT`) are silently dropped. This is intentional: malware commonly tries to connect to domains/IPs that become active later in a campaign.

## Log format

One JSON object per line (JSONL), written to `/tmp/ebpf-network-events.json` (world-readable, `0644`):

```json
{"timestamp":"2026-05-22T23:13:01Z","run_id":"26316400895","repository":"skroutz/ebpf-tracker","workflow_name":"Test eBPF Tracker","protocol":"TCP","src_ip":"10.1.0.145","src_port":8332,"dst_ip":"172.66.147.243","dst_port":443,"pid":2314,"process_name":"curl","uid":1001,"ret":0}
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

The action starts the tracker before your steps run and stops it automatically via the `post` hook after all steps complete.

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `s3-bucket` | No | — | S3 bucket name. If omitted, the events file is printed to the Actions log instead of uploaded. |
| `output` | No | `s3` | `s3` — write events to file and upload to S3 at job end (or print to log if `s3-bucket` is omitted); `stdio` — write events directly to the runner log. |

### S3 output path

```
s3://<bucket>/<github-repository>/<workflow-name-slug>/<run-id>-network.json
```

Example: `s3://my-bucket/skroutz/my-repo/ci/26316400895-network.json`

The workflow name is lowercased and non-alphanumeric characters are replaced with `-`.

### Testing without S3

Omit `s3-bucket` to have `post.js` print the captured events directly to the Actions log:

```yaml
- uses: skroutz/ebpf-tracker@main
  with:
    output: s3
    # s3-bucket omitted — events are printed to the log at job end
```

### Pinning the binary version

By default the binary tag is resolved from the action ref (`GITHUB_ACTION_REF`), so `uses: skroutz/ebpf-tracker@v1.2.0` pulls the `v1.2.0` binary. The `version` input overrides this when the binary version needs to be decoupled from the action version:

```yaml
- uses: skroutz/ebpf-tracker@v1.2.0
  with:
    version: latest   # pull the latest published binary regardless of action ref
```

### AWS credentials

The runner must have `s3:PutObject` on the target bucket. The recommended approach is OIDC:

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
│   └── post.js                         # Stops tracker, uploads/prints events
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
    ├── build-and-publish.yml           # Builds binary, pushes to ghcr.io
    ├── check-dist.yml                  # Verifies dist/ is up-to-date on PRs
    └── test-tracker.yml                # End-to-end test on a real runner
```

## Building

### Prerequisites (Linux only)

```bash
sudo apt-get install clang llvm libelf-dev libbpf-dev linux-headers-$(uname -r)
# bpftool: locate the real binary (the wrapper script can fail on some kernels)
BPFTOOL=$(find /usr/lib/linux-tools -name bpftool 2>/dev/null | head -1)
sudo ln -sf "$BPFTOOL" /usr/local/bin/bpftool

go install github.com/cilium/ebpf/cmd/bpf2go@v0.21.0
```

### Build the tracker binary

```bash
make build
# → tracker/ebpf-tracker  (static ELF, no dependencies)
```

### Run unit tests (any OS)

```bash
cd tracker
go test ./internal/...
```

### Build the JS action dist

```bash
npm install
npm run build
# → dist/main/index.js  dist/post/index.js
```

## CI/CD

Pushing to `main` (excluding changes to `test-tracker.yml`) or to a `v*` tag triggers `.github/workflows/build-and-publish.yml`:

**`build`** (`permissions: contents: read, packages: write`):
1. Generates `vmlinux.h` from the runner kernel's BTF
2. Compiles the C eBPF program and generates the Go skeleton via `bpf2go@v0.21.0`
3. Runs unit tests (`go test ./internal/...`)
4. Builds a fully static Go binary (`CGO_ENABLED=0`)
5. Pushes the binary to `ghcr.io/skroutz/ebpf-tracker:latest` as an OCI artifact via [ORAS](https://oras.land)
6. Rebuilds the Node.js action dist and verifies it compiles cleanly

`.github/workflows/check-dist.yml` runs on every PR and push to `main` to ensure the checked-in `dist/` matches what `npm run build` produces. PRs that modify `src/` **must** include a rebuilt `dist/`.

## Contributing

### Workflow

1. Fork the repo and create a feature branch off `main`.
2. Make your changes.
3. If you touched anything under `src/`, rebuild the action dist and include it in your commit:
   ```bash
   npm install
   npm run build
   git add dist/
   ```
   The `check-dist` CI job will fail the PR if `dist/` is out of sync.
4. If you touched anything under `tracker/`, run the unit tests locally:
   ```bash
   cd tracker
   go test ./internal/...
   ```
5. Open a pull request against `main`.

### Releasing

The `dist/` directory must be committed **before** tagging. The tag points to a commit that already contains the built dist — CI does not commit it back automatically.

```bash
# 1. Rebuild and commit dist
npm run build
git add dist/
git commit -m "chore: rebuild dist for vX.Y.Z"
git push

# 2. Tag
git tag vX.Y.Z
git push --tags
```

Pushing the tag triggers the `build-and-publish` workflow which publishes the new Go binary to `ghcr.io/skroutz/ebpf-tracker:latest`.

## Requirements

- Runner OS: Linux (Ubuntu 22.04+ / kernel 5.8+)
- Kernel must have BTF enabled (`/sys/kernel/btf/vmlinux` must exist); `fexit`/`fentry` hooks require 5.5+. Both conditions are satisfied by any current `ubuntu-*` GitHub-hosted runner.
- AWS CLI available on the runner (pre-installed on all GitHub-hosted runners) — only required when `s3-bucket` is set
- ORAS CLI — installed by the action at startup if not already on `PATH`
