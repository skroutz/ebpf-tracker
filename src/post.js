const core = require('@actions/core');
const exec = require('@actions/exec');

const EVENTS_FILE = '/tmp/ebpf-network-events.json';

async function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function run() {
  const pidStr = core.getState('TRACKER_PID');
  const s3Bucket = core.getState('S3_BUCKET');

  if (!pidStr) {
    core.warning('No tracker PID found in state; skipping teardown');
    return;
  }

  const pid = parseInt(pidStr, 10);
  core.info(`Sending SIGTERM to tracker PID ${pid}`);

  try {
    process.kill(pid, 'SIGTERM');
  } catch (err) {
    // Process may have already exited; that is fine.
    core.warning(`Could not signal PID ${pid}: ${err.message}`);
  }

  // Allow the tracker time to flush its ring buffer and close cleanly.
  await sleep(2000);

  if (!s3Bucket) {
    core.setFailed('S3_BUCKET state is missing; cannot upload logs');
    return;
  }

  const repo = process.env.GITHUB_REPOSITORY || 'unknown-repo';
  const runId = process.env.GITHUB_RUN_ID || 'unknown-run';
  const s3Key = `${repo}/${runId}-network.json`;
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
  } catch (err) {
    core.setFailed(`S3 upload failed: ${err.message}`);
  }
}

run();
