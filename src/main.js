const core = require('@actions/core');
const exec = require('@actions/exec');
const { spawn } = require('child_process');
const fs = require('fs');

const TRACKER_PATH = '/tmp/ebpf-tracker';
const IMAGE = 'ghcr.io/skroutz/ebpf-tracker:latest';

async function run() {
  try {
    const outputMode = core.getInput('output');

    if (outputMode !== 's3' && outputMode !== 'stdio') {
      core.setFailed(`Invalid output mode "${outputMode}". Must be "s3" or "stdio".`);
      return;
    }

    const s3Bucket = core.getInput('s3-bucket');

    if (outputMode === 's3' && !s3Bucket) {
      core.setFailed('s3-bucket input is required when output is "s3"');
      return;
    }

    core.saveState('OUTPUT_MODE', outputMode);
    core.saveState('S3_BUCKET', s3Bucket);

    // Pull the binary artifact from ghcr.io using ORAS CLI.
    core.info(`Pulling eBPF tracker binary from ${IMAGE}`);
    await exec.exec('oras', ['pull', IMAGE, '--output', '/tmp']);

    // The artifact is pushed as a single file named 'ebpf-tracker'.
    fs.chmodSync(TRACKER_PATH, 0o755);
    core.info('Tracker binary ready at ' + TRACKER_PATH);

    // In stdio mode the binary writes to stdout, which we capture via a pipe
    // and forward to the Actions log so it shows up inline in the run.
    const isStdio = outputMode === 'stdio';
    const args = isStdio ? ['--output', '-'] : [];

    const child = spawn(TRACKER_PATH, args, {
      detached: true,
      stdio: isStdio ? ['ignore', 'pipe', 'pipe'] : 'ignore',
    });

    child.on('error', (err) => {
      core.error(`Failed to start tracker: ${err.message}`);
    });

    if (isStdio) {
      child.stdout.on('data', (data) => core.info(data.toString().trim()));
      child.stderr.on('data', (data) => core.info(data.toString().trim()));
    }

    const pid = child.pid;
    if (!pid) {
      core.setFailed('Tracker process did not start');
      return;
    }

    core.saveState('TRACKER_PID', String(pid));
    core.info(`eBPF tracker started with PID ${pid} (output: ${outputMode})`);

    child.unref();
  } catch (err) {
    core.setFailed(err.message);
  }
}

run();
