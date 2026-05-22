const core = require('@actions/core');
const exec = require('@actions/exec');
const fs = require('fs');

const EVENTS_FILE = '/tmp/ebpf-network-events.json';
const SHUTDOWN_TIMEOUT_MS = 5000;
const POLL_INTERVAL_MS = 100;

function isAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    // EPERM: process exists but is owned by root — still alive.
    // ESRCH: process is gone.
    return err.code === 'EPERM';
  }
}

async function waitForExit(pid) {
  const deadline = Date.now() + SHUTDOWN_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (!isAlive(pid)) return true;
    await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
  }
  return false;
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

  // The tracker runs as root (tamper-resistant). Use sudo kill to signal it.
  core.info(`Sending SIGTERM to tracker PID ${pid}`);
  try {
    await exec.exec('sudo', ['kill', '-TERM', String(pid)], { silent: true });
  } catch (err) {
    core.warning(`Could not signal PID ${pid}: ${err.message}`);
  }

  // Poll for exit; escalate to SIGKILL if the process hasn't stopped in time.
  const exited = await waitForExit(pid);
  if (!exited) {
    core.warning(`Tracker did not exit within ${SHUTDOWN_TIMEOUT_MS}ms; sending SIGKILL`);
    try {
      await exec.exec('sudo', ['kill', '-KILL', String(pid)], { silent: true });
    } catch {
      // Already gone — that is fine.
    }
    // Brief wait for the OS to reap the process after SIGKILL.
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  if (outputMode === 'stdio') {
    core.info('Output mode is stdio; skipping S3 upload');
    return;
  }

  if (!s3Bucket) {
    core.setFailed('S3_BUCKET state is missing; cannot upload logs');
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
