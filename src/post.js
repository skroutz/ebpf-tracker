import * as core from '@actions/core';
import * as exec from '@actions/exec';
import fs from 'fs';
import dns from 'dns';
import { execSync } from 'child_process';

const EVENTS_FILE = '/tmp/ebpf-network-events.json';
const SHUTDOWN_TIMEOUT_MS = 15000;
const POLL_INTERVAL_MS = 100;

function isAlive() {
  // Check by process name: this is the only reliable signal because the saved
  // PID belongs to the sudo parent (root-owned), so kill(pid, 0) always returns
  // EPERM while sudo is alive — even after the tracker child has already exited.
  try {
    const out = execSync('pgrep -x ebpf-tracker 2>/dev/null || true').toString().trim();
    return out.length > 0;
  } catch {
    return false;
  }
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

// Write a markdown summary table to GITHUB_STEP_SUMMARY.
function printStepSummary(events) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (!summaryPath) return;

  const repo     = process.env.GITHUB_REPOSITORY || 'N/A';
  const workflow = process.env.GITHUB_WORKFLOW   || 'N/A';
  const runId    = process.env.GITHUB_RUN_ID     || 'N/A';

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
    '| Total Events | Unique Destination IPs | Protocols |\n' +
    '| --- | --- | --- |\n' +
    `| ${events.length} | ${uniqueDsts} | ${protoLine} |\n\n` +
    '---\n\n';

  // Connection table.
  const columns = [
    'Timestamp', 'Protocol',
    'Source IP', 'Src Port',
    'Destination IP', 'Dst Port', 'Dst Domain',
    'PID', 'Process', 'UID',
  ];

  const mdRows = [];
  mdRows.push(`| ${columns.join(' | ')} |`);
  mdRows.push(`| ${columns.map(() => '---').join(' | ')} |`);

  for (const e of events) {
    const row = [
      e.timestamp                  || 'N/A',
      e.network?.protocol          || 'N/A',
      e.source?.ip                 || 'N/A',
      e.source?.port               ?? 'N/A',
      e.destination?.ip            || 'N/A',
      e.destination?.port          ?? 'N/A',
      e.destination?.domain        || 'N/A',
      e.process?.pid               ?? 'N/A',
      e.process?.name              || 'N/A',
      e.user?.id                   || 'N/A',
    ];
    mdRows.push(`| ${row.join(' | ')} |`);
  }

  try {
    fs.appendFileSync(summaryPath, metadataMd);
    fs.appendFileSync(summaryPath, '## Network Events\n\n');
    fs.appendFileSync(summaryPath, mdRows.join('\n'));
    fs.appendFileSync(summaryPath, '\n\n---\n');
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

  // Resolve domains, enrich the artifact in-place, then print step summary.
  if (fs.existsSync(EVENTS_FILE)) {
    const events = parseEventsNDJSON(EVENTS_FILE);
    const enriched = await resolveEventDomains(events);
    writeEventsNDJSON(EVENTS_FILE, enriched);
    printStepSummary(enriched);
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

  const repo = process.env.GITHUB_REPOSITORY || 'unknown-repo';
  const workflow = process.env.GITHUB_WORKFLOW || 'unknown-workflow';
  const runId = process.env.GITHUB_RUN_ID || 'unknown-run';

  const workflowSlug = workflow.toLowerCase().replace(/[^a-z0-9-_]/g, '-');
  const s3Key = `${repo}/${workflowSlug}/${runId}-network.json`;
  const s3Uri = `s3://${s3Bucket}/${s3Key}`;

  core.info(`Uploading ${EVENTS_FILE} to ${s3Uri}`);

  try {
    await exec.exec('aws', [
      's3', 'cp',
      EVENTS_FILE,
      s3Uri,
      '--content-type', 'application/x-ndjson',
    ]);
    core.info('Upload complete');
    try {
      fs.unlinkSync(EVENTS_FILE);
    } catch (cleanupErr) {
      core.warning(`Could not delete ${EVENTS_FILE}: ${cleanupErr.message}`);
    }
  } catch (err) {
    core.setFailed(`S3 upload failed: ${err.message}`);
  }
}

run();
