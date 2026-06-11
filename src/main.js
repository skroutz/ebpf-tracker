import * as core from '@actions/core';
import * as exec from '@actions/exec';
import * as tc from '@actions/tool-cache';
import * as cache from '@actions/cache';
import { spawn } from 'child_process';
import fs from 'fs';
import path from 'path';

const TRACKER_PATH = '/tmp/ebpf-tracker';
const PID_FILE = '/tmp/ebpf-tracker.pid';
const EVENTS_FILE = '/tmp/ebpf-network-events.json';
const IMAGE_REPO = 'ghcr.io/skroutz/ebpf-tracker';
const ORAS_VERSION = '1.2.3';

/**
 * Resolve the binary tag to pull. The `version` input is an explicit override;
 * otherwise the tag follows the action ref so that
 * `uses: skroutz/ebpf-tracker@v1.2.3` always pulls the v1.2.3 binary.
 * Falls back to 'latest' when run outside of Actions (e.g. local testing).
 */
function resolveVersion() {
  return core.getInput('version') || process.env.GITHUB_ACTION_REF || 'latest';
}

/**
 * Make the ORAS CLI available on PATH, fastest source first:
 *   1. already on PATH
 *   2. runner tool cache (persists between jobs on self-hosted runners)
 *   3. GitHub Actions cache (persists between jobs on hosted runners)
 *   4. download from GitHub releases
 * After a download the binary is registered in the tool cache and saved to
 * the Actions cache so subsequent jobs hit a cache instead of the network.
 * Returns the source the binary came from: 'path' | 'tool-cache' | 'cache' |
 * 'download' (also exposed as the oras-source action output).
 */
async function installOras() {
  try {
    await exec.exec('oras', ['version'], { silent: true });
    return 'path';
  } catch {
    core.info('ORAS not found on PATH; resolving from cache or download...');
  }

  let toolDir = tc.find('oras', ORAS_VERSION);
  if (toolDir) {
    core.info(`ORAS ${ORAS_VERSION} found in runner tool cache`);
    core.addPath(toolDir);
    return 'tool-cache';
  }

  const cacheKey = `oras-${ORAS_VERSION}-${process.platform}-${process.arch}`;
  const stagingDir = path.join(process.env.RUNNER_TEMP || '/tmp', `oras-${ORAS_VERSION}`);

  let restoredKey;
  try {
    restoredKey = await cache.restoreCache([stagingDir], cacheKey);
  } catch (err) {
    core.warning(`Actions cache restore failed: ${err.message}`);
  }

  if (restoredKey && fs.existsSync(path.join(stagingDir, 'oras'))) {
    core.info(`ORAS ${ORAS_VERSION} restored from Actions cache (key: ${restoredKey})`);
    toolDir = await tc.cacheDir(stagingDir, 'oras', ORAS_VERSION);
    core.addPath(toolDir);
    return 'cache';
  }

  core.info(`Downloading ORAS ${ORAS_VERSION}...`);
  const url = `https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz`;
  const tarball = await tc.downloadTool(url);
  const extractedDir = await tc.extractTar(tarball);
  toolDir = await tc.cacheDir(extractedDir, 'oras', ORAS_VERSION);
  core.addPath(toolDir);
  core.info(`ORAS installed at ${toolDir}`);

  try {
    fs.mkdirSync(stagingDir, { recursive: true });
    fs.copyFileSync(path.join(toolDir, 'oras'), path.join(stagingDir, 'oras'));
    fs.chmodSync(path.join(stagingDir, 'oras'), 0o755);
    await cache.saveCache([stagingDir], cacheKey);
    core.info(`ORAS saved to Actions cache (key: ${cacheKey})`);
  } catch (err) {
    // ReserveCacheError (a parallel job already saved this key) or transient
    // service errors — never fail the action over a cache write.
    core.warning(`Actions cache save failed: ${err.message}`);
  }
  return 'download';
}

/**
 * Resolve the manifest digest the given tag currently points to.
 * Returns e.g. "sha256:abc..." or null if resolution fails.
 */
async function resolveImageDigest(image) {
  let stdout = '';
  try {
    await exec.exec('oras', ['resolve', image], {
      silent: true,
      listeners: { stdout: (data) => { stdout += data.toString(); } },
    });
    const digest = stdout.trim();
    return /^sha256:[0-9a-f]{64}$/.test(digest) ? digest : null;
  } catch (err) {
    core.warning(`Could not resolve digest for ${image}: ${err.message}`);
    return null;
  }
}

/**
 * Fetch the tracker binary to TRACKER_PATH. A mutable tag ("latest") can move
 * between runs, so the tag alone is never a safe cache key — instead resolve
 * the digest the tag points to right now and key the Actions cache on that.
 * Same digest → restore the cached binary; new digest → fresh oras pull and
 * cache it under the new key.
 * Returns 'cache' | 'pull' (also exposed as the tracker-source action output).
 */
async function installTracker(version) {
  const image = `${IMAGE_REPO}:${version}`;
  const digest = await resolveImageDigest(image);

  let cacheKey;
  if (digest) {
    cacheKey = `ebpf-tracker-${digest}-${process.platform}-${process.arch}`;
    try {
      const restoredKey = await cache.restoreCache([TRACKER_PATH], cacheKey);
      if (restoredKey && fs.existsSync(TRACKER_PATH)) {
        core.info(`Tracker binary restored from Actions cache (digest ${digest})`);
        fs.chmodSync(TRACKER_PATH, 0o755);
        return 'cache';
      }
    } catch (err) {
      core.warning(`Actions cache restore failed: ${err.message}`);
    }
  }

  // Pull by digest when we have one, so the binary we run is exactly the one
  // we cache — even if the tag moves between resolve and pull.
  const pullRef = digest ? `${IMAGE_REPO}@${digest}` : image;
  core.info(`Pulling eBPF tracker binary from ${pullRef}`);
  await exec.exec('oras', ['pull', pullRef, '--output', '/tmp']);

  // The artifact is pushed as a single file named 'ebpf-tracker'.
  fs.chmodSync(TRACKER_PATH, 0o755);
  core.info('Tracker binary ready at ' + TRACKER_PATH);

  if (cacheKey) {
    try {
      await cache.saveCache([TRACKER_PATH], cacheKey);
      core.info(`Tracker binary saved to Actions cache (key: ${cacheKey})`);
    } catch (err) {
      core.warning(`Actions cache save failed: ${err.message}`);
    }
  }
  return 'pull';
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

    const orasSource = await installOras();
    core.setOutput('oras-source', orasSource);

    const trackerSource = await installTracker(resolveVersion());
    core.setOutput('tracker-source', trackerSource);

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
