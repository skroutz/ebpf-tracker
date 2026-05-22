const core = require('@actions/core');
const exec = require('@actions/exec');
const { spawn } = require('child_process');
const fs = require('fs');

const TRACKER_PATH = '/tmp/ebpf-tracker';
const IMAGE = 'ghcr.io/skroutz/ebpf-tracker:latest';

async function run() {
  try {
    const s3Bucket = core.getInput('s3-bucket', { required: true });
    core.saveState('S3_BUCKET', s3Bucket);

    // Pull the binary artifact from ghcr.io using ORAS CLI.
    core.info(`Pulling eBPF tracker binary from ${IMAGE}`);
    await exec.exec('oras', ['pull', IMAGE, '--output', '/tmp']);

    // The artifact is pushed as a single file named 'ebpf-tracker'.
    fs.chmodSync(TRACKER_PATH, 0o755);
    core.info('Tracker binary ready at ' + TRACKER_PATH);

    // Spawn the tracker detached so it survives main.js exiting.
    const child = spawn(TRACKER_PATH, [], {
      detached: true,
      stdio: 'ignore',
    });

    child.on('error', (err) => {
      core.error(`Failed to start tracker: ${err.message}`);
    });

    const pid = child.pid;
    if (!pid) {
      core.setFailed('Tracker process did not start');
      return;
    }

    core.saveState('TRACKER_PID', String(pid));
    core.info(`eBPF tracker started with PID ${pid}`);

    // Detach so the runner process does not wait on this child.
    child.unref();
  } catch (err) {
    core.setFailed(err.message);
  }
}

run();
