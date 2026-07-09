const core = require('@actions/core');
const exec = require('@actions/exec');
const fs = require('fs');
const dns = require('dns');

const EVENTS_FILE = '/tmp/ebpf-network-events.json';
const SHUTDOWN_TIMEOUT_MS = 15000;
const POLL_INTERVAL_MS = 100;
const AWS_ENV_STATE_PREFIX = 'AWS_ENV_';
const AWS_ENV_NAMES = [
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
  'AWS_REGION',
  'AWS_DEFAULT_REGION',
  'AWS_PROFILE',
  'AWS_SHARED_CREDENTIALS_FILE',
  'AWS_CONFIG_FILE',
];
const AWS_SECRET_ENV_NAMES = new Set([
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
]);

function isAlive() {
  // Check by process name: this is the only reliable signal because the saved
  // PID belongs to the sudo parent (root-owned), so kill(pid, 0) always returns
  // EPERM while sudo is alive — even after the tracker child has already exited.
  try {
    const { execSync } = require('child_process');
    const out = execSync('pgrep -x ebpf-tracker 2>/dev/null || true').toString().trim();
    return out.length > 0;
  } catch {
    return false;
  }
}

function getSavedAwsEnv() {
  const savedEnv = {};
  for (const name of AWS_ENV_NAMES) {
    const value = core.getState(`${AWS_ENV_STATE_PREFIX}${name}`);
    if (!value) continue;
    if (AWS_SECRET_ENV_NAMES.has(name)) {
      core.setSecret(value);
    }
    savedEnv[name] = value;
  }
  return savedEnv;
}

function hasSavedAwsCredentialSource(savedAwsEnv) {
  return (
    (savedAwsEnv.AWS_ACCESS_KEY_ID && savedAwsEnv.AWS_SECRET_ACCESS_KEY) ||
    savedAwsEnv.AWS_PROFILE
  );
}

function buildS3UploadEnv() {
  const savedAwsEnv = getSavedAwsEnv();
  if (!hasSavedAwsCredentialSource(savedAwsEnv)) {
    return process.env;
  }

  const uploadEnv = { ...process.env };
  for (const name of AWS_ENV_NAMES) {
    delete uploadEnv[name];
    delete uploadEnv[`STATE_${AWS_ENV_STATE_PREFIX}${name}`];
  }
  Object.assign(uploadEnv, savedAwsEnv);
  core.info('Using captured AWS environment for S3 upload');
  return uploadEnv;
}

async function waitForExit() {
  const deadline = Date.now() + SHUTDOWN_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (!isAlive()) return true;
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  return false;
}

// Reverse-DNS cache shared across all resolutions in one post run.
const _dnsCache = new Map();

// Best-effort reverse DNS: dns.reverse → dns.lookupService → IP fallback.
function resolveDomain(ip) {
  return new Promise((resolve) => {
    if (_dnsCache.has(ip)) { resolve(_dnsCache.get(ip)); return; }
    dns.reverse(ip, (err, hostnames) => {
      if (err || !hostnames || hostnames.length === 0) {
        dns.lookupService(ip, 443, (err2, hostname) => {
          const result = err2 ? ip : hostname;
          _dnsCache.set(ip, result);
          resolve(result);
        });
      } else {
        _dnsCache.set(ip, hostnames[0]);
        resolve(hostnames[0]);
      }
    });
  });
}

// Resolve destination IPs for every event (parallel, best-effort).
// Returns a new array where each event has destination.domain populated.
async function resolveEventDomains(events) {
  const uniqueIPs = [...new Set(events.map((e) => e.destination?.ip).filter(Boolean))];
  core.info(`Resolving domains for ${uniqueIPs.length} unique destination IP(s)…`);
  await Promise.all(
    uniqueIPs.map(async (ip) => {
      try { await resolveDomain(ip); } catch { _dnsCache.set(ip, ip); }
    }),
  );
  return events.map((e) => {
    const ip = e.destination?.ip;
    if (!ip) return e;
    return { ...e, destination: { ...e.destination, domain: _dnsCache.get(ip) || ip } };
  });
}

// Serialise an enriched events array back to NDJSON (overwrites the file).
// The file is owned by root (the tracker ran under sudo), so we pipe through
// `sudo tee` rather than writing directly with fs.writeFileSync.
function writeEventsNDJSON(filePath, events) {
  try {
    const { execSync } = require('child_process');
    const content = events.map((e) => JSON.stringify(e)).join('\n') + '\n';
    execSync(`sudo tee "${filePath}" > /dev/null`, { input: content });
  } catch (err) {
    core.warning(`Could not write enriched events file: ${err.message}`);
  }
}

// Parse an NDJSON file into an array of objects, skipping blank/invalid lines.
function parseEventsNDJSON(filePath) {
  try {
    return fs
      .readFileSync(filePath, 'utf8')
      .split('\n')
      .filter((l) => l.trim())
      .map((l) => {
        try { return JSON.parse(l); } catch { return null; }
      })
      .filter(Boolean);
  } catch (err) {
    core.warning(`Could not read events file: ${err.message}`);
    return [];
  }
}

// Collapse events into one row per distinct connection (same protocol,
// source/destination IP, destination port+domain, process, UID, exit code) —
// repeated connections (e.g. keep-alive requests with a new ephemeral source
// port each time) differ only in timestamp/source port/pid, which is what's
// aggregated here. Process/UID/exit code are kept as grouping keys (not
// collapsed): exit code distinguishes a successful connection from a refused
// one (must never merge into the same row), and process name is the signal
// this tracker exists to surface — though process.name is attacker-settable
// (prctl/argv0), so raw PIDs are also retained per group (see formatCompactSet)
// as a kernel-verified identity that a spoofed comm name can't hide behind.
// Returns groups sorted by count descending.
function groupEvents(events) {
  const groups = new Map();
  for (const e of events) {
    const protocol   = e.network?.protocol   || 'N/A';
    const sourceIp   = e.source?.ip          || 'N/A';
    const destIp     = e.destination?.ip     || 'N/A';
    const destPort   = e.destination?.port   ?? 'N/A';
    const destDomain = e.destination?.domain || 'N/A';
    const proc       = e.process?.name       || 'N/A';
    const uid        = e.user?.id            || 'N/A';
    const exitCode   = e.process?.exit_code  ?? 'N/A';
    const key = [protocol, sourceIp, destIp, destPort, destDomain, proc, uid, exitCode].join(' ');

    let g = groups.get(key);
    if (!g) {
      g = {
        protocol, sourceIp, destIp, destPort, destDomain, process: proc, uid, exitCode,
        count: 0, srcPorts: new Set(), pids: new Set(), firstSeen: null, lastSeen: null,
      };
      groups.set(key, g);
    }
    g.count += 1;
    if (e.source?.port !== undefined && e.source?.port !== null) g.srcPorts.add(e.source.port);
    if (e.process?.pid !== undefined && e.process?.pid !== null) g.pids.add(e.process.pid);
    const ts = e.timestamp;
    if (ts) {
      if (g.firstSeen === null || ts < g.firstSeen) g.firstSeen = ts;
      if (g.lastSeen === null || ts > g.lastSeen) g.lastSeen = ts;
    }
  }
  return [...groups.values()].sort((a, b) => b.count - a.count);
}

// Exact values for low-cardinality sets (source ports, PIDs); a count for the
// rest, so the cell never becomes an unreadable pile of unrelated numbers.
function formatCompactSet(values) {
  if (values.size === 0) return 'N/A';
  if (values.size <= 3) return [...values].sort((a, b) => a - b).join(', ');
  return `${values.size} distinct`;
}

// Neutralizes markdown table-breaking characters in attacker-influenced
// fields (process name is set via prctl/argv0; domain comes from a reverse-DNS
// PTR record — both are outside our control) before they go into a table row.
function escapeMdCell(value) {
  return String(value)
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\r\n|\r|\n/g, ' ');
}

// Leaves headroom under GitHub's 1024 KiB step-summary hard limit.
const STEP_SUMMARY_BUDGET_BYTES = 900 * 1024;

// Write a markdown summary table to GITHUB_STEP_SUMMARY.
// `fullDataLocation` (an S3 URI or "the job log") is referenced if the table
// still has to be cut down to fit the size limit.
function printStepSummary(events, fullDataLocation) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;

  const repo     = process.env.GITHUB_REPOSITORY || 'N/A';
  const workflow = process.env.GITHUB_WORKFLOW   || 'N/A';
  const runId    = process.env.GITHUB_RUN_ID     || 'N/A';

  const groups = groupEvents(events);

  // Aggregate stats.
  const uniqueDsts = new Set(events.map((e) => e.destination?.ip)).size;
  const byProto = {};
  for (const e of events) {
    const p = e.network?.protocol || 'unknown';
    byProto[p] = (byProto[p] || 0) + 1;
  }
  const protoLine =
    Object.entries(byProto)
      .sort(([, a], [, b]) => b - a)
      .map(([k, v]) => `\`${k}\`:${v}`)
      .join(', ') || 'none';

  // Header / metadata block.
  const metadataMd =
    '## eBPF Network Tracker Report\n\n' +
    '| Repository | Workflow | Run ID |\n' +
    '| --- | --- | --- |\n' +
    `| ${repo} | ${workflow} | ${runId} |\n\n` +
    '| Total Events | Unique Connections | Unique Destination IPs | Protocols |\n' +
    '| --- | --- | --- | --- |\n' +
    `| ${events.length} | ${groups.length} | ${uniqueDsts} | ${protoLine} |\n\n` +
    '---\n\n';

  // Connection table: one row per distinct connection, not per raw event.
  const columns = [
    'Protocol', 'Source IP', 'Destination IP', 'Dst Port', 'Dst Domain',
    'Process', 'PIDs', 'UID', 'Exit Code', 'Count', 'Src Ports',
    'First Seen (UTC)', 'Last Seen (UTC)',
  ];
  const headerLines = [
    `| ${columns.join(' | ')} |`,
    `| ${columns.map(() => '---').join(' | ')} |`,
  ];
  const rowLines = groups.map((g) => {
    const row = [
      g.protocol, g.sourceIp, g.destIp, g.destPort, g.destDomain,
      g.process, formatCompactSet(g.pids), g.uid, g.exitCode, g.count,
      formatCompactSet(g.srcPorts), g.firstSeen || 'N/A', g.lastSeen || 'N/A',
    ].map(escapeMdCell);
    return `| ${row.join(' | ')} |`;
  });

  const sectionHeader = '## Network Events\n\n';
  const footer = '\n\n---\n';

  // Safety net: only trims in genuinely high-cardinality cases (e.g. many
  // one-off unique destinations), since grouping already collapses repeats.
  const fixedBytes = Buffer.byteLength(
    metadataMd + sectionHeader + headerLines.join('\n') + '\n' + footer, 'utf8',
  );
  const budgetForRows = STEP_SUMMARY_BUDGET_BYTES - fixedBytes;

  let usedBytes = 0;
  const includedRows = [];
  for (const line of rowLines) {
    const lineBytes = Buffer.byteLength(line + '\n', 'utf8');
    if (usedBytes + lineBytes > budgetForRows) break;
    includedRows.push(line);
    usedBytes += lineBytes;
  }

  const omittedCount = rowLines.length - includedRows.length;
  const truncationNote = omittedCount > 0
    ? `\n> ${omittedCount} of ${rowLines.length} connections omitted to stay under the step summary size limit — full data is in ${fullDataLocation}.\n`
    : '';

  try {
    fs.appendFileSync(summaryPath, metadataMd);
    fs.appendFileSync(summaryPath, sectionHeader);
    fs.appendFileSync(summaryPath, [...headerLines, ...includedRows].join('\n'));
    fs.appendFileSync(summaryPath, truncationNote);
    fs.appendFileSync(summaryPath, footer);
  } catch (err) {
    core.warning(`Could not write step summary: ${err.message}`);
  }
}

async function run() {
  const pidStr = core.getState('TRACKER_PID');
  const outputMode = core.getState('OUTPUT_MODE') || 's3';
  const s3Bucket = core.getState('S3_BUCKET');

  if (!pidStr) {
    core.warning('No tracker PID found in state; skipping teardown');
    return;
  }

  const pid = parseInt(pidStr, 10);
  if (pid <= 1) {
    core.warning(`Refusing to signal suspicious PID ${pid}; skipping teardown`);
    return;
  }

  // Signal ebpf-tracker by its exact PID written to the PID file.
  core.info(`Sending SIGTERM to ebpf-tracker (PID ${pid})`);
  try {
    await exec.exec('sudo', ['kill', '-TERM', String(pid)]);
  } catch (err) {
    core.warning(`kill SIGTERM failed: ${err.message}`);
  }

  // Poll for exit; escalate to SIGKILL if the process hasn't stopped in time.
  const exited = await waitForExit();
  if (!exited) {
    core.warning(`Tracker did not exit within ${SHUTDOWN_TIMEOUT_MS}ms; sending SIGKILL`);
    try {
      await exec.exec('sudo', ['pkill', '-KILL', '-x', 'ebpf-tracker']);
    } catch {
      // Already gone — that is fine.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  if (outputMode === 'stdio') {
    core.info('Output mode is stdio; skipping S3 upload');
    return;
  }

  // Compute the S3 destination up front (pure string-building, no I/O) so the
  // step summary can name it if its connection table has to be truncated.
  let s3Uri = null;
  if (s3Bucket) {
    const repo = process.env.GITHUB_REPOSITORY || 'unknown-repo';
    const workflow = process.env.GITHUB_WORKFLOW || 'unknown-workflow';
    const runId = process.env.GITHUB_RUN_ID || 'unknown-run';
    const workflowSlug = workflow.toLowerCase().replace(/[^a-z0-9-_]/g, '-');
    const s3Key = `${repo}/${workflowSlug}/${runId}-network.json`;
    s3Uri = `s3://${s3Bucket}/${s3Key}`;
  }
  const fullDataLocation = s3Uri ? `the uploaded artifact (\`${s3Uri}\`)` : 'the job log output for this step';

  // Resolve domains, enrich the artifact in-place, then print step summary.
  if (fs.existsSync(EVENTS_FILE)) {
    const events = parseEventsNDJSON(EVENTS_FILE);
    const enriched = await resolveEventDomains(events);
    writeEventsNDJSON(EVENTS_FILE, enriched);
    printStepSummary(enriched, fullDataLocation);
  }

  if (!s3Bucket) {
    core.warning('S3_BUCKET state is missing — printing events file to log instead of uploading');
    try {
      core.info(`=== captured events (${EVENTS_FILE}) ===`);
      process.stdout.write(fs.readFileSync(EVENTS_FILE, 'utf8'));
      core.info('=== end of events ===');
    } catch (e) {
      core.warning(`Could not read ${EVENTS_FILE}: ${e.message}`);
    }
    return;
  }

  // M5: verify the file exists before attempting the upload.
  if (!fs.existsSync(EVENTS_FILE)) {
    core.warning(`${EVENTS_FILE} not found — tracker may not have started or produced no events`);
    return;
  }

  core.info(`Uploading ${EVENTS_FILE} to ${s3Uri}`);

  try {
    await exec.exec('aws', [
      's3', 'cp',
      EVENTS_FILE,
      s3Uri,
      '--content-type', 'application/x-ndjson',
    ], { env: buildS3UploadEnv() });
    core.info('Upload complete');
    try {
      // EVENTS_FILE is root-owned (written via `sudo tee`) and /tmp has the
      // sticky bit set, so only root can unlink it
      await exec.exec('sudo', ['rm', '-f', EVENTS_FILE]);
    } catch (cleanupErr) {
      core.warning(`Could not delete ${EVENTS_FILE}: ${cleanupErr.message}`);
    }
  } catch (err) {
    core.setFailed(`S3 upload failed: ${err.message}`);
  }
}

run();
