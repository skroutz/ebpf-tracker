const core = require('@actions/core');
const exec = require('@actions/exec');
const tc = require('@actions/tool-cache');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

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

    // Install ORAS CLI if not already on PATH.
    let orasPath = 'oras';
    try {
      await exec.exec('oras', ['version'], { silent: true });
    } catch {
      core.info('ORAS not found on PATH; downloading...');
      const ORAS_VERSION = '1.2.3';
      const url = `https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz`;
      const tarball = await tc.downloadTool(url);
      const extractedDir = await tc.extractTar(tarball);
      orasPath = path.join(extractedDir, 'oras');
      core.addPath(extractedDir);
      core.info(`ORAS installed at ${orasPath}`);
    }

    // Pull the binary artifact from ghcr.io using ORAS CLI.
    core.info(`Pulling eBPF tracker binary from ${IMAGE}`);
    await exec.exec('oras', ['pull', IMAGE, '--output', '/tmp']);

    // The artifact is pushed as a single file named 'ebpf-tracker'.
    fs.chmodSync(TRACKER_PATH, 0o755);
    core.info('Tracker binary ready at ' + TRACKER_PATH);

    // The tracker must run as root so that monitored code (potentially
    // malicious third-party actions) cannot kill it. Ubuntu 24.04 enables
    // use_pty in sudoers by default, which makes sudo fork a child in a new
    // session — breaking PID tracking. We disable it for this binary only via
    // a sudoers drop-in, which causes sudo to exec() the binary directly
    // (replacing its own process image). The PID returned by spawn() is then
    // the tracker's actual PID running as root.
    const sudoersLine =
      'runner ALL=(root) NOPASSWD:NOSETENV: ' + TRACKER_PATH + '\n' +
      'Defaults!' + TRACKER_PATH + ' !use_pty\n';
    await exec.exec('sudo', ['tee', '/etc/sudoers.d/ebpf-tracker'], {
      input: Buffer.from(sudoersLine),
      silent: true,
    });
    await exec.exec('sudo', ['visudo', '-c', '-f', '/etc/sudoers.d/ebpf-tracker']);

    const isStdio = outputMode === 'stdio';
    const args = isStdio ? ['--output', '-'] : [];

    // In stdio mode use 'inherit' so the tracker writes directly to the
    // runner's stdout/stderr. Using 'pipe' would keep the Node.js event loop
    // alive indefinitely via open pipe refs.
    const child = spawn('sudo', ['-n', TRACKER_PATH, ...args], {
      detached: true,
      stdio: isStdio ? ['ignore', 'inherit', 'inherit'] : 'ignore',
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
    core.info(`eBPF tracker started with PID ${pid} (output: ${outputMode})`);

    child.unref();
  } catch (err) {
    core.setFailed(err.message);
  }
}

run();
