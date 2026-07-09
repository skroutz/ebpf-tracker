const core = require('@actions/core');
const exec = require('@actions/exec');
const tc = require('@actions/tool-cache');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const TRACKER_PATH = '/tmp/ebpf-tracker';
const PID_FILE = '/tmp/ebpf-tracker.pid';
const EVENTS_FILE = '/tmp/ebpf-network-events.json';
const ORAS_VERSION = '1.2.3';
const ORAS_FILENAME = `oras_${ORAS_VERSION}_linux_amd64.tar.gz`;
const ORAS_LINUX_AMD64_SHA256 = 'b4efc97a91f471f323f193ea4b4d63d8ff443ca3aab514151a30751330852827';
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
// Resolve the binary tag from the action ref so that
// `uses: skroutz/ebpf-tracker@v1.2.3` always pulls the v1.2.3 binary.
// Falls back to 'latest' when run outside of Actions (e.g. local testing).
const actionRef = process.env.GITHUB_ACTION_REF || 'latest';
const IMAGE = `ghcr.io/skroutz/ebpf-tracker:${actionRef}`;

function sha256File(filePath) {
  return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
}

function verifyOrasTarball(tarball) {
  const actual = sha256File(tarball);
  if (actual !== ORAS_LINUX_AMD64_SHA256) {
    throw new Error(
      `ORAS checksum verification failed: expected ${ORAS_LINUX_AMD64_SHA256}, got ${actual}`,
    );
  }
  core.info(`Verified ORAS ${ORAS_VERSION} checksum (${actual})`);
}

function saveAwsEnvState() {
  let saved = 0;
  for (const name of AWS_ENV_NAMES) {
    const value = process.env[name];
    if (!value) continue;
    if (AWS_SECRET_ENV_NAMES.has(name)) {
      core.setSecret(value);
    }
    core.saveState(`${AWS_ENV_STATE_PREFIX}${name}`, value);
    saved += 1;
  }

  if (saved > 0) {
    core.info('Captured AWS environment for post S3 upload');
  }
}

/**
 * Poll until the tracker has written its PID file, or the timeout expires.
 * Returns the PID as a number, or null if the file never appeared.
 */
async function waitForPidFile(timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fs.existsSync(PID_FILE)) {
      const content = fs.readFileSync(PID_FILE, 'utf8').trim();
      const pid = parseInt(content, 10);
      if (pid > 1) return pid;
    }
    await new Promise(r => setTimeout(r, 100));
  }
  return null;
}

async function run() {
  try {
    const outputMode = core.getInput('output');

    if (outputMode !== 's3' && outputMode !== 'stdio') {
      core.setFailed(`Invalid output mode "${outputMode}". Must be "s3" or "stdio".`);
      return;
    }

    const s3Bucket = core.getInput('s3-bucket');

    core.saveState('OUTPUT_MODE', outputMode);
    core.saveState('S3_BUCKET', s3Bucket);
    if (outputMode === 's3' && s3Bucket) {
      saveAwsEnvState();
    }

    // Install ORAS CLI if not already on PATH.
    let orasPath = 'oras';
    try {
      await exec.exec('oras', ['version'], { silent: true });
    } catch {
      core.info('ORAS not found on PATH; downloading...');
      const url = `https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/${ORAS_FILENAME}`;
      const tarball = await tc.downloadTool(url);
      verifyOrasTarball(tarball);
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
      'Defaults!' + TRACKER_PATH + ' !use_pty, env_keep += "GITHUB_RUN_ID GITHUB_REPOSITORY GITHUB_WORKFLOW"\n';
    await exec.exec('sudo', ['tee', '/etc/sudoers.d/ebpf-tracker'], {
      input: Buffer.from(sudoersLine),
      silent: true,
    });
    await exec.exec('sudo', ['visudo', '-c', '-f', '/etc/sudoers.d/ebpf-tracker']);

    const isStdio = outputMode === 'stdio';
    const procScan = core.getInput('proc-scan') !== 'false';
    const args = [
      ...(isStdio ? ['--output', '-'] : []),
      ...(procScan ? [] : ['--proc-scan-interval', '0']),
    ];

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

    child.unref();

    // The binary writes its own PID (as root) to a file after BPF loading
    // succeeds. Use that for a reliable SIGTERM target in the post step.
    const trackerPid = await waitForPidFile(10000);
    if (trackerPid) {
      core.saveState('TRACKER_PID', String(trackerPid));
      core.info(`Tracker confirmed running with PID ${trackerPid} (output: ${outputMode})`);
    } else {
      core.warning('Tracker PID file not written within 10 s; falling back to sudo PID');
      core.saveState('TRACKER_PID', String(pid));
      core.info(`eBPF tracker started with sudo PID ${pid} (output: ${outputMode})`);
    }
  } catch (err) {
    core.setFailed(err.message);
  }
}

run();
