#!/usr/bin/env node
/**
 * Tracefinity's repo-owned signed release controller.
 *
 * Prepare builds the exact merged source into one container image, pins the image ID, the source
 * and the full operator-owned target, and writes approval bytes for the operator's Ed25519
 * signature. Submit verifies that signature and hands the candidate to a durable systemd job. The
 * job re-verifies before every mutation, replaces one container on a remote Unraid Docker host over
 * pinned-host-key SSH, and only records `deployed` after the running container proves the signed
 * image ID, the forced auth environment and health. It never signs, never reads a private key, never
 * changes a tunnel and never rolls back without a fresh signature.
 *
 * Trust comes only from the fixed operator policy file (see `policyPath`); there is no environment
 * or command-line override. The exports other than `main` are for tests and for the acceptance verifier.
 */
import { createHash, createPublicKey, randomBytes, verify as verifySignature } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createReadStream, constants as fsConstants } from 'node:fs';
import { readFile, readdir, readlink, writeFile, mkdir, mkdtemp, rename, copyFile, chmod, lstat, realpath, rm, open } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const SELF = fileURLToPath(import.meta.url);
const POLICY_FILE = 'tracefinity-release-policy.json';
const SHA = /^[a-f0-9]{40}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const IMAGE_ID = /^sha256:[a-f0-9]{64}$/;
const ID = /^[a-z0-9][a-z0-9-]{0,47}$/;
const SERVICE = 'tracefinity';
const CHILD_PATH = '/usr/local/bin:/usr/bin:/bin';
/** How long a signing approval lasts. It starts after the image is built and the checks passed (Station Zero's one-hour convention). */
export const APPROVAL_LIFETIME_MS = 60 * 60_000;
/** Attempts, one second apart, for the replaced container to pass live verification. */
const BOOT_ATTEMPTS = 180;
const BASE_ARTIFACTS = ['image.tar', 'image-config.json', 'source.tar', 'checks.json', 'trusted-check.sh', 'release-controller.mjs'];
/** The files a candidate must carry: a public exposure also carries its signed ingress plan. */
const artifactsFor = (target) => (target.exposure.mode === 'public' ? [...BASE_ARTIFACTS, 'ingress-plan.json'] : BASE_ARTIFACTS);
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const iso = () => new Date().toISOString();
const short = (sha) => sha.slice(0, 8);
const need = (condition, message) => { if (!condition) throw new Error(message); };
const fatal = (message) => Object.assign(new Error(message), { fatal: true });
const json = async (file) => JSON.parse(await readFile(file, 'utf8'));
const encode = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
/** Stable serialisation: key order never changes what is compared or hashed. */
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).filter((key) => value[key] !== undefined).sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}
const same = (left, right) => canonical(left) === canonical(right);
/** The passwd-database home, never `$HOME`: an environment cannot redirect trust. */
const homeDirectory = () => os.userInfo().homedir;
/** The one place trust is read from. */
export const policyPath = () => path.join(homeDirectory(), '.config/station-zero', POLICY_FILE);

// ---------------------------------------------------------------------------------------------
// Process execution
// ---------------------------------------------------------------------------------------------
const childEnv = () => ({ PATH: CHILD_PATH, HOME: homeDirectory(), LANG: 'C', LC_ALL: 'C', DOCKER_BUILDKIT: '1',
  XDG_RUNTIME_DIR: `/run/user/${process.getuid()}` });
/**
 * The sandbox for everything that executes source: the trusted `.ade/check`, pip, corepack and pnpm installs. It runs in a throwaway
 * container with no host environment (every variable is a fixed literal below), no HOME, no SSH agent or identity, no Docker or any
 * runtime socket, no policy, receipts or target paths, and no host mount except the candidate's own source copy, a scratch tools dir,
 * a generated one-line-per-user passwd file and the read-only gate script. Capabilities are dropped, privileges cannot grow, the root
 * filesystem is read-only, and pids, memory and CPU are capped so a runaway dependency cannot starve the live services on this host.
 * Dependency installs get the default bridge network (no host networking); the gate itself runs with no network at all.
 * Threat boundary: kernel-level container escape and anything reachable over the bridge network from the install steps are out of
 * scope; a hostile gate can still lie about its own result, which is why the image is built by a separate, signed-evidence step.
 */
export const GATE_DOCKERFILE = ['FROM node:20-slim AS node', 'FROM python:3.12-slim',
  'COPY --from=node /usr/local/bin/node /usr/local/bin/node', 'COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules',
  'RUN ln -s ../lib/node_modules/corepack/dist/corepack.js /usr/local/bin/corepack && ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx',
  'RUN apt-get update && apt-get install -y --no-install-recommends make git ca-certificates libgl1 libsm6 libxext6 libxrender1 libheif-dev && (apt-get install -y --no-install-recommends libglib2.0-0t64 2>/dev/null || apt-get install -y --no-install-recommends libglib2.0-0) && rm -rf /var/lib/apt/lists/*',
  ''].join('\n');
export const gateImageTag = () => `tracefinity-gate:${hash(GATE_DOCKERFILE).slice(0, 12)}`;
const GATE_ENV = { PATH: '/work/backend/venv/bin:/tools/bin:/usr/local/bin:/usr/bin:/bin', HOME: '/tmp', LANG: 'C', LC_ALL: 'C', CI: 'true', COREPACK_HOME: '/tools/corepack',
  COREPACK_ENABLE_DOWNLOAD_PROMPT: '0', PNPM_HOME: '/tools/pnpm-home', PIP_DISABLE_PIP_VERSION_CHECK: '1', PIP_NO_CACHE_DIR: '1', npm_config_cache: '/tmp/npm', U2NET_HOME: '/tools/models' };
const MODEL_FETCH = 'import hashlib\nfrom rembg.sessions.u2netp import U2netpSession\nprint(hashlib.sha256(open(U2netpSession.download_models(), "rb").read()).hexdigest())';
export const GATE_LIMITS = { memory: '8g', cpus: '4', pids: '2048', tmp: '4g' };
const within = (child, parent) => { const relative = path.relative(parent, child); return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative)); };
/** The exact `docker run` argv for one sandboxed step. Refuses any mount outside the candidate or covering a host secret or control socket. */
export function gateRunArgs({ image, network, workSource, toolsDir, passwdFile, gateFile = null, workdir = '/work', argv, candidateDir, policy }) {
  need(['bridge', 'none'].includes(network), 'sandbox network must be bridge or none');
  need(IMAGE_ID.test(image) && /^\/work(\/[A-Za-z0-9_.-]+)*$/.test(workdir) && Array.isArray(argv) && argv.length > 0, 'invalid sandbox step');
  const mounts = [[workSource, '/work', false], [toolsDir, '/tools', false], [passwdFile, '/etc/passwd', true], ...(gateFile ? [[gateFile, '/gate/check', true]] : [])];
  const secrets = [policy.target.ssh.identityFile, policy.target.receiptsRoot, policyPath(), homeDirectory(), '/var/run/docker.sock', '/run/docker.sock', '/var/run', '/run',
    ...(policy.target.exposure.ingress ? [policy.target.exposure.ingress.apiTokenFile] : []),
    ...[policy.acceptance?.cookieFile, policy.acceptance?.publish?.tokenFile].filter(Boolean)];
  for (const [source] of mounts) {
    need(path.isAbsolute(source) && within(source, candidateDir), 'sandbox mount is outside the candidate directory');
    for (const secret of secrets) need(!within(secret, source), 'sandbox mount would expose a host secret or control socket');
  }
  return ['run', '--rm', '--pull', 'never', '--user', `${process.getuid()}:${process.getgid()}`, '--network', network, '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
    '--read-only', '--tmpfs', `/tmp:rw,exec,nosuid,mode=1777,size=${GATE_LIMITS.tmp}`, '--memory', GATE_LIMITS.memory, '--memory-swap', GATE_LIMITS.memory, '--cpus', GATE_LIMITS.cpus,
    '--pids-limit', GATE_LIMITS.pids, '--ipc', 'private', '--workdir', workdir, '--label', 'io.tracefinity.release.gate=1',
    ...mounts.flatMap(([source, target, readOnly]) => ['--mount', `type=bind,source=${source},target=${target}${readOnly ? ',readonly' : ''}`]),
    ...Object.entries(GATE_ENV).flatMap(([key, value]) => ['--env', `${key}=${value}`]), image, ...argv];
}
/**
 * Run one program with a fixed minimal environment. Resolves to trimmed stdout. A failure carries
 * `code` and `stderr`. `input` or `stdinFile` feed stdin; `stdinSha256` demands the streamed bytes
 * hash to the signed value.
 */
export function run(file, args, cwd, options = {}) {
  const { input, stdinFile, stdinSha256, timeoutMs = 30 * 60_000, env = childEnv(), maxOutput = 32 * 1024 * 1024, mergeStderr = false } = options;
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { cwd, env, stdio: [input !== undefined || stdinFile ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
    const out = [];
    let size = 0;
    let err = Buffer.alloc(0);
    let sent = null;
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(Object.assign(error, { stderr: error.stderr ?? err.toString('utf8') }));
      else resolve(value);
    };
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish(new Error(`${path.basename(file)} timed out after ${timeoutMs} ms`)); }, timeoutMs);
    child.stdout.on('data', (chunk) => {
      size += chunk.length;
      if (size > maxOutput) { child.kill('SIGKILL'); finish(new Error(`${path.basename(file)} output exceeded ${maxOutput} bytes`)); return; }
      out.push(chunk);
    });
    child.stderr.on('data', (chunk) => {
      err = Buffer.concat([err, chunk]);
      if (err.length > 65536) err = err.subarray(err.length - 65536);
      if (mergeStderr) { size += chunk.length; if (size > maxOutput) { child.kill('SIGKILL'); finish(new Error(`${path.basename(file)} output exceeded ${maxOutput} bytes`)); return; } out.push(chunk); }
    });
    child.on('error', (error) => finish(error));
    if (stdinFile) {
      const hasher = createHash('sha256');
      const source = createReadStream(stdinFile);
      child.stdin.on('error', () => {});
      source.on('data', (chunk) => hasher.update(chunk));
      source.on('end', () => { sent = hasher.digest('hex'); });
      source.on('error', (error) => { child.kill('SIGKILL'); finish(error); });
      source.pipe(child.stdin);
    } else if (input !== undefined) {
      child.stdin.on('error', () => {});
      child.stdin.end(input);
    }
    child.on('close', (code, signal) => {
      if (code !== 0) {
        finish(Object.assign(new Error(`${path.basename(file)} exited ${code ?? signal}: ${err.toString('utf8').trim().slice(-2000)}`), { code }));
        return;
      }
      if (stdinSha256 !== undefined && sent !== stdinSha256) {
        finish(new Error('streamed input does not match the signed artifact digest'));
        return;
      }
      finish(null, Buffer.concat(out).toString('utf8').trim());
    });
  });
}
const q = (value) => (/^[A-Za-z0-9_@%+=:,./-]+$/.test(value) ? value : `'${value.replaceAll("'", "'\\''")}'`);
export const shellQuote = q;

// ---------------------------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------------------------
/** Owner-owned regular file that nobody else can write; never a link. */
async function regularInfo(file) {
  const info = await lstat(file);
  need(info.isFile() && !info.isSymbolicLink(), `not a regular file: ${path.basename(file)}`);
  need(info.uid === process.getuid() && (info.mode & 0o022) === 0, `file is not owner-owned or is group/world writable: ${path.basename(file)}`);
  return info;
}
async function regular(file) { await regularInfo(file); return readFile(file); }
async function hashFile(file) {
  await regularInfo(file);
  const hasher = createHash('sha256');
  for await (const chunk of createReadStream(file)) hasher.update(chunk);
  return hasher.digest('hex');
}
async function syncPath(target) {
  const handle = await open(target, 'r');
  try { await handle.sync(); } finally { await handle.close(); }
}
async function atomic(file, value) {
  await writeFile(`${file}.tmp`, encode(value), { mode: 0o600 });
  await syncPath(`${file}.tmp`);
  await rename(`${file}.tmp`, file);
  await syncPath(path.dirname(file));
}
async function sourceFingerprint(root) {
  const digest = createHash('sha256');
  async function walk(relative) {
    const entries = await readdir(path.join(root, relative), { withFileTypes: true });
    for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      const file = path.join(root, name);
      digest.update(`${name}\0`);
      if (entry.isDirectory()) { digest.update('directory\0'); await walk(name); }
      else if (entry.isSymbolicLink()) digest.update(`link\0${await readlink(file)}\0`);
      else if (entry.isFile()) digest.update(`file\0${hash(await readFile(file))}\0`);
      else throw new Error(`unsupported source entry: ${name}`);
    }
  }
  await walk('');
  return digest.digest('hex');
}

// ---------------------------------------------------------------------------------------------
// Operator policy
// ---------------------------------------------------------------------------------------------
const isPath = (v) => typeof v === 'string' && v.length < 200 && /^\/[A-Za-z0-9_./-]+$/.test(v) && path.posix.normalize(v) === v && !v.endsWith('/');
/** Host paths that may never be mounted into the container: runtime sockets, kernel and system trees, the boot flash, credentials. */
const DANGEROUS_HOST = /(^\/(var\/run|run|proc|sys|dev|boot|etc|root|usr|bin|sbin|lib|lib64|var\/lib\/docker)(\/|$))|docker\.sock/;
const safeHostPath = (v) => isPath(v) && !DANGEROUS_HOST.test(v);
const isHost = (v) => typeof v === 'string' && /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/.test(v);
const isPort = (v) => Number.isInteger(v) && v >= 1 && v <= 65535;
const isIPv4 = (v) => typeof v === 'string' && /^\d+\.\d+\.\d+\.\d+$/.test(v) && v.split('.').every((o) => /^(0|[1-9]\d{0,2})$/.test(o) && Number(o) <= 255);
const MANAGED_ENV = ['AUTH_MODE', 'AUTH_SETUP_ENABLED', 'AUTH_COOKIE_SECURE', 'AUTH_ALLOW_ACCOUNT_DATA_WITHOUT_LOGIN', 'SHOW_APP_VERSION', 'STORAGE_PATH', 'PUID', 'PGID'];
function exact(value, required, optional, label) {
  need(value && typeof value === 'object' && !Array.isArray(value), `${label} must be an object`);
  for (const key of Object.keys(value)) need(required.includes(key) || optional.includes(key), `${label}: unknown field ${key}`);
  for (const key of required) need(key in value, `${label}: ${key} is required`);
}
function url(value, protocol, label) {
  need(typeof value === 'string', `${label} must be a URL`);
  let parsed;
  try { parsed = new URL(value); } catch { throw new Error(`${label} must be a URL`); }
  need(parsed.protocol === protocol && !parsed.username && !parsed.password && !parsed.search && !parsed.hash && parsed.pathname === '/' && parsed.href === value,
    `${label} must be a canonical ${protocol.slice(0, -1)} origin URL ending in /`);
}
/** Validate the operator policy shape. Every string that can reach a command line is pattern-checked. */
export function validatePolicy(p) {
  exact(p, ['schemaVersion', 'kind', 'publicKeyBase64', 'source', 'build', 'target'], ['acceptance'], 'policy');
  need(p.schemaVersion === 1 && p.kind === 'tracefinity.release-policy', 'missing/unsupported operator release policy');
  const raw = Buffer.from(p.publicKeyBase64 ?? '', 'base64');
  need(raw.length === 32 && raw.toString('base64') === p.publicKeyBase64, 'explicit trusted Ed25519 public key required');
  exact(p.source, ['repository', 'branch'], [], 'source');
  need(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(p.source.repository) && /^[A-Za-z0-9][A-Za-z0-9._/-]{0,62}$/.test(p.source.branch), 'invalid source repository/branch');
  exact(p.build, ['platform', 'imageRepository'], [], 'build');
  need(['linux/amd64', 'linux/arm64'].includes(p.build.platform) && /^[a-z0-9][a-z0-9._-]{0,63}$/.test(p.build.imageRepository), 'invalid build platform/imageRepository');
  const t = p.target;
  exact(t, ['kind', 'nodePath', 'receiptsRoot', 'dockerPath', 'ssh', 'container', 'exposure'], [], 'target');
  need(t.kind === 'unraid-docker', 'target must be unraid-docker');
  for (const key of ['nodePath', 'receiptsRoot', 'dockerPath']) need(isPath(t[key]), `invalid target ${key}`);
  exact(t.ssh, ['host', 'port', 'user', 'identityFile', 'hostKey'], [], 'ssh');
  need(isHost(t.ssh.host) && isPort(t.ssh.port) && /^[a-z_][a-z0-9_-]{0,31}$/.test(t.ssh.user) && isPath(t.ssh.identityFile), 'invalid ssh target');
  need(/^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/]{20,2000}={0,3}$/.test(t.ssh.hostKey), 'ssh.hostKey must be one pinned public host key line (type and base64 only)');
  const c = t.container;
  exact(c, ['name', 'hostPort', 'storagePath', 'puid', 'pgid'], ['envFile', 'env', 'mounts', 'memory', 'cpus'], 'container');
  need(/^[a-z0-9][a-z0-9_.-]{0,47}$/.test(c.name) && isPort(c.hostPort) && safeHostPath(c.storagePath), 'invalid container name/hostPort/storagePath (storagePath may not be a system or socket path)');
  need(Number.isInteger(c.puid) && c.puid > 0 && c.puid < 65536 && Number.isInteger(c.pgid) && c.pgid > 0 && c.pgid < 65536, 'container puid/pgid must be non-root ids');
  if (c.envFile !== undefined) need(safeHostPath(c.envFile), 'invalid container envFile (may not be a system or socket path)');
  if (c.memory !== undefined) need(/^[1-9]\d{0,5}[mg]$/.test(c.memory), 'invalid container memory');
  if (c.cpus !== undefined) need(/^(0\.\d{1,2}|[1-9]\d?(\.\d{1,2})?)$/.test(c.cpus), 'invalid container cpus');
  for (const [key, value] of Object.entries(c.env ?? {})) {
    need(/^[A-Z][A-Z0-9_]{0,63}$/.test(key) && typeof value === 'string' && /^[\x20-\x7e]{0,512}$/.test(value), `invalid container env ${key}`);
    need(!MANAGED_ENV.includes(key), `container env ${key} is controller-managed and cannot be set`);
    need(!/SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL/i.test(key), `container env ${key} looks secret; secrets belong in the remote envFile, never in this policy`);
  }
  const mounts = c.mounts ?? [];
  need(Array.isArray(mounts) && mounts.length <= 8, 'container mounts must be a short list');
  const targets = new Set();
  for (const mount of mounts) {
    exact(mount, ['hostPath', 'containerPath'], ['readOnly'], 'mount');
    need(safeHostPath(mount.hostPath), 'mount hostPath is not allowed');
    need(/^\/(config|secrets)\/[A-Za-z0-9_./-]+$/.test(mount.containerPath) && path.posix.normalize(mount.containerPath) === mount.containerPath && !targets.has(mount.containerPath),
      'mount containerPath must be a unique normalized path under /config or /secrets');
    need(mount.readOnly === undefined || typeof mount.readOnly === 'boolean', 'mount readOnly must be boolean');
    targets.add(mount.containerPath);
  }
  const x = t.exposure;
  need(x && typeof x === 'object' && ['private', 'public'].includes(x.mode), 'exposure.mode must be private or public');
  if (x.mode === 'private') exact(x, ['mode'], [], 'exposure');
  else {
    exact(x, ['mode', 'publishAddress', 'lanUrl', 'publicUrl', 'publicStatus', 'ingress'], ['sensitiveStatuses'], 'exposure');
    need(isIPv4(x.publishAddress) && !x.publishAddress.startsWith('127.') && x.publishAddress !== '0.0.0.0', 'public exposure needs one specific non-loopback LAN publishAddress (never 0.0.0.0)');
    url(x.lanUrl, 'http:', 'exposure.lanUrl');
    url(x.publicUrl, 'https:', 'exposure.publicUrl');
    need([200, 301, 302, 303, 307, 308, 401, 403].includes(x.publicStatus), 'explicit exposure.publicStatus required');
    need(x.sensitiveStatuses === undefined || (Array.isArray(x.sensitiveStatuses) && x.sensitiveStatuses.length > 0 && x.sensitiveStatuses.every((s) => [301, 302, 303, 307, 308, 401, 403].includes(s))),
      'exposure.sensitiveStatuses may only list non-success statuses');
    const g = x.ingress;
    exact(g, ['provider', 'accountId', 'zoneId', 'tunnelId', 'hostname', 'service', 'apiTokenFile', 'singleWriter'], [], 'exposure.ingress');
    need(g.provider === 'cloudflare-tunnel' && /^[a-f0-9]{32}$/.test(g.accountId) && /^[a-f0-9]{32}$/.test(g.zoneId)
      && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(g.tunnelId), 'invalid exposure.ingress identifiers');
    need(isHost(g.hostname) && g.hostname.includes('.') && new URL(x.publicUrl).hostname === g.hostname.toLowerCase(), 'exposure.ingress.hostname must be the hostname of exposure.publicUrl');
    need(typeof g.service === 'string' && g.service === `http://${g.service.slice(7).split(':')[0]}:${c.hostPort}` && isHost(g.service.slice(7).split(':')[0]),
      'exposure.ingress.service must be http://HOST:hostPort for the container host port');
    need(isPath(g.apiTokenFile), 'invalid exposure.ingress.apiTokenFile');
    need(g.singleWriter === true, "exposure.ingress.singleWriter must be true: Cloudflare's tunnel configuration PUT replaces the whole configuration and documents no precondition, so a deployment may only change the tunnel when the operator attests that nothing else writes its configuration");
  }
  if (p.acceptance !== undefined) {
    exact(p.acceptance, [], ['cookieFile', 'publish', 'timeoutMs'], 'acceptance');
    need(p.acceptance.cookieFile === undefined || isPath(p.acceptance.cookieFile), 'invalid acceptance cookieFile');
    need(p.acceptance.timeoutMs === undefined || (Number.isInteger(p.acceptance.timeoutMs) && p.acceptance.timeoutMs >= 1000 && p.acceptance.timeoutMs <= 120_000), 'invalid acceptance timeoutMs');
    if (p.acceptance.publish !== undefined) {
      exact(p.acceptance.publish, ['repository', 'stateBranch', 'tokenFile'], ['verifier', 'verifierApp'], 'acceptance.publish');
      const pub = p.acceptance.publish;
      need((pub.verifier === undefined) !== (pub.verifierApp === undefined), 'acceptance.publish needs exactly one of verifier (GitHub login) or verifierApp (GitHub App id)');
      need(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(pub.repository) && pub.stateBranch === 'production-state' && isPath(pub.tokenFile)
        && (pub.verifier === undefined || /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(pub.verifier)) && (pub.verifierApp === undefined || (Number.isInteger(pub.verifierApp) && pub.verifierApp > 0)),
      'invalid acceptance publish (stateBranch must be production-state; verifier is a GitHub login, verifierApp a positive GitHub App id)');
    }
  }
  return p;
}
/** What the signature binds: everything that decides the deployment, nothing about acceptance. */
export const signedPolicy = (p) => ({ schemaVersion: p.schemaVersion, kind: p.kind, publicKeyBase64: p.publicKeyBase64, source: p.source, build: p.build, target: p.target });
export const policyDigest = (p) => hash(canonical(signedPolicy(p)));
/** The pinned operator policy: an owner-only regular file in an owner-controlled directory, outside the repo. */
export async function loadPolicy(file = policyPath()) {
  let bytes;
  try { bytes = await regular(file); } catch (error) { throw new Error(`public trust/target setup missing or unsafe: ${path.basename(file)} (${error.message})`); }
  need(await realpath(file) === file, 'release policy path may not traverse symlinks');
  const info = await lstat(file);
  need((info.mode & 0o077) === 0, 'release policy must be mode 0600: it names private hosts');
  const directory = await lstat(path.dirname(file));
  need(directory.isDirectory() && directory.uid === process.getuid() && (directory.mode & 0o022) === 0, 'release policy directory must be owner-owned and not group/world writable');
  const policy = validatePolicy(JSON.parse(bytes));
  return { policy, policySha256: policyDigest(policy) };
}
/** Hide private target details from anything printed, stored in a receipt or shown to a dashboard. */
export function makeRedactor(policy) {
  const t = policy.target;
  const words = [`${t.ssh.user}@${t.ssh.host}`, t.ssh.host, t.ssh.identityFile, t.ssh.hostKey, t.container.storagePath, t.container.envFile,
    ...(t.container.mounts ?? []).map((m) => m.hostPath), t.receiptsRoot,
    ...(t.exposure.mode === 'public' ? [t.exposure.lanUrl, t.exposure.publicUrl, new URL(t.exposure.publicUrl).host, new URL(t.exposure.lanUrl).host,
      t.exposure.ingress.hostname, t.exposure.ingress.accountId, t.exposure.ingress.zoneId, t.exposure.ingress.tunnelId, t.exposure.ingress.service, t.exposure.ingress.apiTokenFile] : [])]
    .filter((word) => typeof word === 'string' && word.length >= 5).sort((a, b) => b.length - a.length);
  return (text) => words.reduce((acc, word) => acc.split(word).join('<redacted>'), String(text));
}

// ---------------------------------------------------------------------------------------------
// Signature
// ---------------------------------------------------------------------------------------------
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
/** The Ed25519 group order. A signature whose scalar is not below it is a malleated copy. */
const ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;
/** True only for a canonical 64-byte detached Ed25519 signature by exactly the pinned key over exactly these bytes. */
export function verifyDetachedSignature(message, signatureText, publicKeyBase64) {
  const text = Buffer.isBuffer(signatureText) ? signatureText.toString('utf8').trim() : String(signatureText).trim();
  const signature = Buffer.from(text, 'base64');
  need(signature.length === 64 && signature.toString('base64') === text, 'invalid detached signature');
  const rawKey = Buffer.from(publicKeyBase64, 'base64');
  need(rawKey.length === 32 && rawKey.toString('base64') === publicKeyBase64, 'invalid trusted public key');
  let scalar = 0n;
  for (let i = 63; i >= 32; i--) scalar = (scalar << 8n) | BigInt(signature[i]);
  need(scalar < ORDER, 'signature is not canonical');
  const key = createPublicKey({ key: Buffer.concat([SPKI_PREFIX, rawKey]), format: 'der', type: 'spki' });
  need(verifySignature(null, message, key, signature), 'signature is not from the explicitly trusted operator');
  return true;
}
export function handoff(approvalBytes) {
  const a = JSON.parse(approvalBytes);
  const b64 = approvalBytes.toString('base64');
  return { schemaVersion: 1, kind: 'wds.production-approval-signing-handoff',
    candidateId: a.candidateId, sourceSha: a.sourceSha, services: a.services,
    manifestSha256: a.manifestSha256, expiresAt: a.expiresAt,
    approval: { mediaType: 'application/json', bytesBase64: b64, byteLength: approvalBytes.length,
      utf8CharacterCount: approvalBytes.toString('utf8').length, base64CharacterCount: b64.length, sha256: hash(approvalBytes) },
    responseContract: { mediaType: 'application/vnd.wds.production-approval-signature+json',
      allowedFields: ['approvalSha256', 'signatureBase64'], detachedSignatureBytes: 64, privateKeyFieldsAllowed: false } };
}

// ---------------------------------------------------------------------------------------------
// Container specification, probes and engines
// ---------------------------------------------------------------------------------------------
const managedEnv = (c) => ({ AUTH_MODE: 'native', AUTH_SETUP_ENABLED: 'false', AUTH_COOKIE_SECURE: 'true',
  AUTH_ALLOW_ACCOUNT_DATA_WITHOUT_LOGIN: 'false', SHOW_APP_VERSION: 'true', STORAGE_PATH: '/app/storage', PUID: String(c.puid), PGID: String(c.pgid) });
const sorted = (object) => Object.entries(object).sort(([a], [b]) => a.localeCompare(b, 'en'));
/**
 * The exact container the signature authorizes, derived only from the pinned policy and the signed
 * image. Nothing a candidate carries can add a mount, port, capability or environment variable.
 */
export function buildContainerSpec(target, image, { candidate, sourceSha }) {
  const c = target.container;
  const x = target.exposure;
  const address = x.mode === 'public' ? x.publishAddress : '127.0.0.1';
  const env = { ...(c.env ?? {}), ...managedEnv(c) };
  const mounts = [{ source: c.storagePath, destination: '/app/storage', readOnly: false },
    ...(c.mounts ?? []).map((m) => ({ source: m.hostPath, destination: m.containerPath, readOnly: m.readOnly === true }))];
  const labels = { 'io.tracefinity.release.candidate': candidate, 'io.tracefinity.release.image': image.imageId, 'io.tracefinity.release.source': sourceSha };
  const nextName = `${c.name}-next-${candidate}`;
  const prevName = `${c.name}-prev-${candidate}`;
  const createArgs = ['create', '--name', nextName, '--pull', 'never', '--restart', 'unless-stopped',
    '--publish', `${address}:${c.hostPort}:3000/tcp`, '--security-opt', 'no-new-privileges:true'];
  for (const m of mounts) createArgs.push('--mount', `type=bind,source=${m.source},target=${m.destination}${m.readOnly ? ',readonly' : ''}`);
  if (c.envFile) createArgs.push('--env-file', c.envFile);
  for (const [key, value] of sorted(env)) createArgs.push('--env', `${key}=${value}`);
  for (const [key, value] of sorted(labels)) createArgs.push('--label', `${key}=${value}`);
  if (c.memory) createArgs.push('--memory', c.memory);
  if (c.cpus) createArgs.push('--cpus', c.cpus);
  createArgs.push(image.imageId);
  return { name: c.name, nextName, prevName, address, hostPort: c.hostPort, env, mounts, labels, createArgs,
    specSha256: hash(canonical({ name: c.name, createArgs })) };
}
/**
 * Paths requested through nginx on container port 3000. nginx proxies only /api/ and /storage/ to the
 * backend and sends everything else to Next.js, so a health answer through nginx is /api/auth/status,
 * never /health. /health is asked of the backend process directly on port 8000, from inside the container.
 */
export const NGINX_PROBE_PATHS = { authStatus: '/api/auth/status', sensitive: '/api/api-keys', version: '/api/version', frontend: '/' };
export const BACKEND_DIRECT_PROBE = { port: 8000, path: '/health' };
const PROBE_SCRIPT = ['import json, urllib.request as r, urllib.error as e',
  'o = r.build_opener(r.ProxyHandler({}))',
  'def get(port, p):', '    try:', "        x = o.open('http://127.0.0.1:%d%s' % (port, p), timeout=5)",
  "        return [x.status, x.read(65536).decode('utf-8', 'replace')]",
  '    except e.HTTPError as h:', "        return [h.code, '']", '    except Exception:', "        return [0, '']",
  'def js(t):', '    try:', '        return json.loads(t)', '    except Exception:', '        return None',
  `b = get(${BACKEND_DIRECT_PROBE.port}, '${BACKEND_DIRECT_PROBE.path}')`, `a = get(3000, '${NGINX_PROBE_PATHS.authStatus}')`, `s = get(3000, '${NGINX_PROBE_PATHS.sensitive}')`,
  `f = get(3000, '${NGINX_PROBE_PATHS.frontend}')`, `v = get(3000, '${NGINX_PROBE_PATHS.version}')`,
  "print(json.dumps({'backendDirect': b[0], 'frontend': f[0], 'authStatus': a[0], 'auth': js(a[1]), 'sensitive': s[0], 'versionStatus': v[0], 'version': js(v[1])}))",
].join('\n') + '\n';
/** Read-only count of the native account store: never prints an account, a hash or a secret. */
const ADMIN_SCRIPT = ['import json, sys', 'try:', "    d = json.load(open('/app/storage/users.json'))", 'except FileNotFoundError:', '    d = {}',
  'if not isinstance(d, dict):', '    sys.exit(3)', 'n = 0', 'for v in d.values():',
  "    if isinstance(v, dict) and v.get('is_admin') is True and not v.get('disabled'):", '        n += 1',
  "print(json.dumps({'accounts': len(d), 'enabledAdmins': n}))"].join('\n') + '\n';
/** The container answers like a native-auth Tracefinity at the signed source, with the first-run door closed. */
function checkProbe(result, sourceSha) {
  need(result && result.backendDirect === 200 && result.frontend === 200, `app is not serving (backend ${result?.backendDirect}, frontend ${result?.frontend})`);
  need(result.authStatus === 200 && result.auth?.mode === 'native', 'app is not in native auth mode');
  if (result.auth.setup_required !== false) throw fatal('first-run setup is reachable (setup_required is not false)');
  need(result.sensitive === 401, `an unauthenticated sensitive endpoint answered ${result.sensitive}, not 401`);
  need(result.versionStatus === 200 && result.version?.version === sourceSha, 'running app version does not equal the signed source SHA');
  return { backendDirect: result.backendDirect, frontend: result.frontend, authStatus: result.authStatus, mode: result.auth.mode,
    setupRequired: result.auth.setup_required, sensitiveStatus: result.sensitive, version: result.version.version };
}
const parseCounts = (text) => {
  const value = JSON.parse(text);
  need(Number.isInteger(value.accounts) && value.accounts >= 0 && Number.isInteger(value.enabledAdmins) && value.enabledAdmins >= 0, 'unreadable account store summary');
  return { verified: value.enabledAdmins >= 1, accounts: value.accounts, enabledAdmins: value.enabledAdmins };
};
const localEngine = (command, cwd) => ({ docker: (args, options) => command('docker', args, cwd, options), close: async () => {} });
/** Prepare may only observe the remote. Anything else is refused before a command is built. */
const READ_ONLY_REMOTE = new Set(['version', 'info', 'container inspect', 'image inspect']);
function readOnlyEngine(engine) {
  return { close: () => engine.close(), docker: (args, options) => {
    need(READ_ONLY_REMOTE.has(args[0]) || READ_ONLY_REMOTE.has(`${args[0]} ${args[1]}`), `preparation may not run docker ${args[0]} on the target`);
    return engine.docker(args, options);
  } };
}
/** Docker over SSH with a controller-owned known_hosts, no ssh config, no agent and no forwarding. */
export async function openRemote(trust, command = run) {
  const t = trust.policy.target;
  await mkdir(t.receiptsRoot, { recursive: true, mode: 0o700 });
  const dir = await mkdtemp(path.join(t.receiptsRoot, '.ssh-'));
  const [keyType, keyData] = t.ssh.hostKey.split(' ');
  const hostName = t.ssh.port === 22 ? t.ssh.host : `[${t.ssh.host}]:${t.ssh.port}`;
  const knownHosts = path.join(dir, 'known_hosts');
  await writeFile(knownHosts, `${hostName} ${keyType} ${keyData}\n`, { mode: 0o600 });
  const base = ['-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-o', 'StrictHostKeyChecking=yes',
    '-o', `UserKnownHostsFile=${knownHosts}`, '-o', 'GlobalKnownHostsFile=/dev/null', '-o', `HostKeyAlgorithms=${keyType}`, '-o', 'ConnectTimeout=15',
    '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=4', '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
    '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no', '-o', 'RequestTTY=no', '-o', 'ControlMaster=no',
    '-o', 'ControlPath=none', '-o', 'ProxyCommand=none', '-o', 'LogLevel=ERROR', '-p', String(t.ssh.port), '-i', t.ssh.identityFile, `${t.ssh.user}@${t.ssh.host}`];
  return {
    docker: (args, options) => command('ssh', [...base, [t.dockerPath, ...args].map(q).join(' ')], undefined, { timeoutMs: 180_000, ...options }),
    close: () => rm(dir, { recursive: true, force: true }),
  };
}
async function inspectOrNull(engine, args) {
  try { return JSON.parse(await engine.docker(args)); }
  catch (error) {
    if (error.code === 1 && /No such (container|image|object)/i.test(error.stderr ?? '')) return null;
    throw error; // an unreachable host is never "absent"
  }
}
const containerInspect = (engine, ref) => inspectOrNull(engine, ['container', 'inspect', '--format', '{{json .}}', ref]);
const imageInspect = (engine, ref) => inspectOrNull(engine, ['image', 'inspect', '--format', '{{json .}}', ref]);
/** The identity of whatever container currently owns a name: what the approval signs as `previous`. */
async function snapshotContainer(engine, name) {
  const info = await containerInspect(engine, name);
  if (!info) return { present: false };
  need(SHA256.test(info.Id ?? '') && IMAGE_ID.test(info.Image ?? ''), 'target returned an unreadable container identity');
  return { present: true, containerId: info.Id, imageId: info.Image, running: info.State?.Running === true };
}
const samePrevious = (live, signed) => live.present === signed.present
  && (!live.present || (live.containerId === signed.containerId && live.imageId === signed.imageId));
function envMap(info) {
  return Object.fromEntries((info.Config?.Env ?? []).map((entry) => { const i = entry.indexOf('='); return [entry.slice(0, i), entry.slice(i + 1)]; }));
}
/** Prove a created or running container is exactly the signed image under exactly the signed settings. */
function verifyContainer(info, spec, name, image, { running }) {
  if (info.Image !== image.imageId) throw fatal(`container uses image ${info.Image}, not the signed ${image.imageId}`);
  const fail = (message) => { throw fatal(message); };
  if (info.Name !== `/${name}`) fail(`container is named ${info.Name}, not /${name}`);
  const env = envMap(info);
  for (const [key, value] of Object.entries(spec.env)) if (env[key] !== value) fail(`effective environment ${key} is not the signed value`);
  const expectedMounts = spec.mounts.map((m) => `bind|${m.source}|${m.destination}|${m.readOnly ? 'ro' : 'rw'}`).sort();
  const actualMounts = (info.Mounts ?? []).map((m) => `${m.Type}|${m.Source}|${m.Destination}|${m.RW ? 'rw' : 'ro'}`).sort();
  if (!same(actualMounts, expectedMounts)) fail('container mounts are not exactly the signed mounts');
  const host = info.HostConfig ?? {};
  if (!same(host.PortBindings, { '3000/tcp': [{ HostIp: spec.address, HostPort: String(spec.hostPort) }] })) fail('container port bindings are not exactly the signed publish');
  if (host.Privileged !== false || host.PublishAllPorts !== false || (host.CapAdd ?? []).length || (host.Devices ?? []).length || (host.PidMode ?? '') !== '') fail('container has privileges the signed spec does not grant');
  if (!['bridge', 'default'].includes(host.NetworkMode)) fail('container network mode is not the default bridge');
  if (host.RestartPolicy?.Name !== 'unless-stopped') fail('container restart policy is not the signed policy');
  if (!(host.SecurityOpt ?? []).some((opt) => /^no-new-privileges(?:[:=]true)?$/.test(opt))) fail('container does not set no-new-privileges');
  if (running) {
    const s = info.State ?? {};
    need(s.Running === true && s.Status === 'running' && !s.Restarting && !s.Dead && !s.OOMKilled, `container is not running (${s.Status})`);
    if ((info.RestartCount ?? 0) !== 0) fail(`container restarted ${info.RestartCount} time(s) since it started`);
  }
}
function verifyImage(info, image) {
  const fail = (message) => { throw fatal(message); };
  if (info?.Id !== image.imageId) fail(`target image ID ${info?.Id ?? 'absent'} is not the signed ${image.imageId} (a containerd image store reports different IDs and is unsupported)`);
  if (!same(info.RootFS?.Layers, image.diffIds)) fail('target image layers are not the signed layers');
  if (`${info.Os}/${info.Architecture}` !== image.platform) fail('target image platform is not the signed platform');
}
async function probeContainer(engine, ref, sourceSha) {
  const text = await engine.docker(['exec', '-i', ref, 'python', '-'], { input: PROBE_SCRIPT, timeoutMs: 60_000 });
  return checkProbe(JSON.parse(text), sourceSha);
}
const adminOneShot = async (engine, imageRef, storagePath) => parseCounts(await engine.docker(['run', '--rm', '--pull', 'never', '--network', 'none',
  '--security-opt', 'no-new-privileges:true', '--entrypoint', 'python', '--mount', `type=bind,source=${storagePath},target=/app/storage,readonly`, '-i', imageRef, '-'],
{ input: ADMIN_SCRIPT, timeoutMs: 120_000 }));
const adminExec = async (engine, ref) => parseCounts(await engine.docker(['exec', '-i', ref, 'python', '-'], { input: ADMIN_SCRIPT, timeoutMs: 60_000 }));
const NONCE_SCRIPT = (nonce) => `import urllib.request as r\nr.build_opener(r.ProxyHandler({})).open('http://127.0.0.1:3000${NGINX_PROBE_PATHS.authStatus}?tf_route_probe=${nonce}', timeout=5).read()\n`;
/** The public route proof reads the nginx access log: prove, for each image, that it exists and records a request made through nginx. */
async function proveAccessLog(engine, name) {
  const nonce = randomBytes(16).toString('hex');
  await engine.docker(['exec', '-i', name, 'python', '-'], { input: NONCE_SCRIPT(nonce), timeoutMs: 60_000 });
  let seen = 0;
  try { seen = Number.parseInt(await engine.docker(['exec', name, 'grep', '-F', '-c', nonce, '/var/log/nginx/access.log']), 10); }
  catch (error) { if (error.code !== 1) throw error; }
  if (!(seen >= 1)) throw fatal('the image does not record requests in /var/log/nginx/access.log, which the public route proof depends on');
}
const SEED_SCRIPT = 'for f in users.json auth_secret auth_tokens.json; do if [ -f "/seed/$f" ]; then cp -p "/seed/$f" "/app/storage/$f"; fi; done';
/**
 * Start the image once with no network and wait for it to answer correctly. Local (preparation): only the forced auth
 * environment and empty tmpfs storage. Staged (deployment): the PRODUCTION configuration (env file, extra environment, extra
 * mounts read-only) on a private volume seeded from read-only copies of the credential files, so production-only startup
 * failures appear before the live service is touched and the live storage never has a second writer. `authorize` runs
 * immediately before each mutating docker call.
 */
async function runCanary(engine, { ref, name, target, sourceSha, sleep, authorize = async () => {}, staged = null, attempts = 120 }) {
  const common = ['--pull', 'never', '--network', 'none', '--security-opt', 'no-new-privileges:true', '--label', 'io.tracefinity.release.canary=1'];
  const volume = `${name}-storage`;
  let runArgs;
  if (staged) {
    const { spec } = staged;
    await authorize();
    await engine.docker(['volume', 'create', volume]);
    await authorize();
    await engine.docker(['run', '--rm', '--pull', 'never', '--network', 'none', '--entrypoint', 'sh', '--mount', `type=bind,source=${target.container.storagePath},target=/seed,readonly`,
      '--mount', `type=volume,source=${volume},target=/app/storage`, ref, '-c', SEED_SCRIPT], { timeoutMs: 120_000 });
    const extra = spec.mounts.filter((m) => m.destination !== '/app/storage').flatMap((m) => ['--mount', `type=bind,source=${m.source},target=${m.destination},readonly`]);
    runArgs = ['run', '-d', '--name', name, ...common, '--mount', `type=volume,source=${volume},target=/app/storage`, ...extra,
      ...(target.container.envFile ? ['--env-file', target.container.envFile] : []), ...sorted(spec.env).flatMap(([key, value]) => ['--env', `${key}=${value}`]), ref];
  } else {
    const env = Object.entries(managedEnv(target.container)).flatMap(([key, value]) => ['--env', `${key}=${value}`]);
    runArgs = ['run', '-d', '--name', name, ...common, '--tmpfs', '/app/storage:rw,mode=1777', ...env, ref];
  }
  try {
    await authorize();
    await engine.docker(runArgs);
    let reason = 'not ready';
    for (let attempt = 1; attempt <= attempts; attempt++) {
      let probed = null;
      try { probed = await probeContainer(engine, name, sourceSha); }
      catch (error) { if (error.fatal) throw error; reason = error.message; }
      if (probed) { await proveAccessLog(engine, name); return { ...probed, accessLogProof: true, productionConfig: staged !== null }; }
      await sleep(1000);
    }
    throw new Error(`canary never became healthy: ${reason}`);
  } finally {
    await engine.docker(['rm', '-f', name]).catch(() => {});
    if (staged) await engine.docker(['volume', 'rm', '-f', volume]).catch(() => {});
  }
}
const defaultProbe = async (url) => {
  const response = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(5000) });
  return { status: response.status, body: (await response.text()).slice(0, 65536) };
};
// ---------------------------------------------------------------------------------------------
// Cloudflare tunnel ingress (remotely managed tunnels only)
// ---------------------------------------------------------------------------------------------
const CF_API = 'https://api.cloudflare.com/client/v4';
/** Drop empty values so a provider filling in defaults is not mistaken for drift. */
export function normalizeConfig(value) {
  if (Array.isArray(value)) return value.map(normalizeConfig);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      const clean = normalizeConfig(item);
      if (clean === null || clean === undefined || (typeof clean === 'object' && !Array.isArray(clean) && Object.keys(clean).length === 0)) continue;
      out[key] = clean;
    }
    return out;
  }
  return value;
}
export const configDigest = (config) => hash(canonical(normalizeConfig(config)));
const ingressPath = (g) => `/accounts/${g.accountId}/cfd_tunnel/${g.tunnelId}/configurations`;
/**
 * Cloudflare API access for the one tunnel the policy names. The bearer token is read from the
 * owner-only file the policy names at the moment of each call and never stored, logged or returned.
 * `fetchImpl` exists so tests never reach the network.
 */
export function openCloudflare(trust, fetchImpl = fetch) {
  const g = trust.policy.target.exposure.ingress;
  need(g, 'this policy has no ingress to manage');
  const call = async (method, pathname, body) => {
    const info = await regularInfo(g.apiTokenFile);
    need((info.mode & 0o077) === 0, 'Cloudflare API token file must be mode 0600');
    const token = (await readFile(g.apiTokenFile, 'utf8')).trim();
    need(/^[A-Za-z0-9_-]{20,200}$/.test(token), 'Cloudflare API token file does not hold a token');
    const response = await fetchImpl(`${CF_API}${pathname}`, { method, redirect: 'error', signal: AbortSignal.timeout(20_000),
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    const payload = await response.json().catch(() => null);
    if (!response.ok || payload?.success !== true) {
      throw new Error(`Cloudflare API ${method} failed (HTTP ${response.status}${Array.isArray(payload?.errors) ? `, codes ${payload.errors.map((e) => e.code).join(',')}` : ''})`);
    }
    return payload.result;
  };
  return { get: (pathname) => call('GET', pathname), put: (pathname, body) => call('PUT', pathname, body) };
}
/** Preparation gets only the reading half: it can never change a tunnel. */
const readOnlyCloudflare = (cf) => ({ get: cf.get });
async function readTunnelState(cf, g) {
  const result = await cf.get(ingressPath(g));
  need(result && result.tunnel_id === g.tunnelId, 'Cloudflare returned a different tunnel than the policy names');
  need(result.source === 'cloudflare', 'the tunnel is not remotely managed (its config source is not cloudflare), so its ingress cannot be changed through the API');
  const config = result.config && typeof result.config === 'object' ? result.config : {};
  const ingress = Array.isArray(config.ingress) && config.ingress.length ? config.ingress : [{ service: 'http_status:404' }];
  const last = ingress[ingress.length - 1];
  need(!last.hostname && /^http_status:\d{3}$/.test(last.service ?? ''), 'the tunnel ingress does not end with a catch-all http_status rule');
  return { config: { ...config, ingress }, version: Number.isInteger(result.version) ? result.version : null };
}
export const readTunnelConfig = async (cf, g) => (await readTunnelState(cf, g)).config;
/** The signed hostname must already be a proxied CNAME to this tunnel: the controller never creates DNS records. */
export async function checkTunnelDns(cf, g) {
  const records = await cf.get(`/zones/${g.zoneId}/dns_records?type=CNAME&name=${encodeURIComponent(g.hostname)}`);
  need(Array.isArray(records) && records.length === 1 && records[0].content === `${g.tunnelId}.cfargotunnel.com` && records[0].proxied === true,
    'the hostname must already be one proxied DNS CNAME to the tunnel; the controller never creates DNS records');
}
const wildcardMatches = (rule, hostname) => rule.includes('*') && new RegExp(`^${rule.split('*').map((part) => part.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.+')}$`).test(hostname);
/**
 * The route-absent configuration (`safe`) and the route-present one (`planned`) for this hostname, each differing from `base`
 * only by our one rule. `add`: base has no rule, planned inserts it before the catch-all. `replace`: base already routes the
 * hostname to the signed service, so the replacement could be reached through it the moment it starts: the deployment withdraws
 * the rule for the cutover (`safe`) and restores it (`planned`, equal to base) only after the replacement is proven. A hostname
 * routed elsewhere, or shadowed by a wildcard, is a refusal, never an edit.
 */
export function planIngress(base, g) {
  const rules = base.ingress;
  const mine = rules.filter((rule) => rule.hostname === g.hostname);
  need(mine.length <= 1, 'the tunnel has several rules for the hostname');
  if (mine.length === 1) {
    need(mine[0].service === g.service && mine[0].path === undefined, 'the hostname already routes to a different service; the controller never repoints an existing rule');
    return { action: 'replace', safe: { ...base, ingress: rules.filter((rule) => rule !== mine[0]) }, planned: base };
  }
  need(!rules.some((rule) => typeof rule.hostname === 'string' && wildcardMatches(rule.hostname, g.hostname)), 'an existing wildcard rule would shadow the hostname');
  return { action: 'add', safe: base, planned: { ...base, ingress: [...rules.slice(0, -1), { hostname: g.hostname, service: g.service }, rules[rules.length - 1]] } };
}
/** What the approval binds about ingress: identifiers, the change, the single-writer attestation and the digests of the three configurations. */
export function ingressSummary(g, action, base, safe, planned) {
  return { provider: g.provider, accountId: g.accountId, zoneId: g.zoneId, tunnelId: g.tunnelId, hostname: g.hostname, service: g.service, action,
    singleWriterAttested: g.singleWriter === true, baseConfigSha256: configDigest(base), safeConfigSha256: configDigest(safe), plannedConfigSha256: configDigest(planned) };
}
/**
 * Cloudflare documents no precondition (no If-Match, no version argument) on the whole-configuration PUT, so there is no
 * compare-and-swap. This is therefore NOT safe against another writer and relies on the signed single-writer attestation
 * in the policy. It narrows the window (read, authorize, write) and refuses unless the live configuration is exactly the
 * state this signed step expects; afterwards it requires the stored configuration to be ours and, when Cloudflare reports a
 * version, that the version advanced by exactly one (a larger jump means a concurrent write was lost). Unrelated rules are
 * preserved as of the read immediately before the write, not guaranteed by the provider.
 */
async function writeIngress(cf, g, { expectSha256, config, authorize, onBeforePut = () => {} }) {
  const before = await readTunnelState(cf, g);
  need(configDigest(before.config) === expectSha256, 'the tunnel ingress is not the state this signed step expects; refusing to overwrite it');
  try { await authorize(); } catch (error) { throw Object.assign(error, { unauthorized: true }); }
  onBeforePut();
  await cf.put(ingressPath(g), { config });
  const after = await readTunnelState(cf, g);
  need(configDigest(after.config) === configDigest(config), 'Cloudflare did not store the planned ingress configuration');
  if (before.version !== null && after.version !== null) need(after.version === before.version + 1, 'the tunnel configuration version advanced by more than this change: a concurrent writer is suspected and its change may have been overwritten');
  return { versionBefore: before.version, versionAfter: after.version };
}
/**
 * Everything observable about the container that owns the production name, as it is right now: the
 * signed image ID, the signed settings, answers from inside, the native account store and, for a public
 * exposure, the LAN answers. Throws (`fatal` when no waiting can help).
 */
async function observeRuntime({ remote, spec, image, sourceSha, target, containerId, probe }) {
  const info = await containerInspect(remote, containerId);
  need(info, 'container is gone');
  verifyContainer(info, spec, spec.name, image, { running: true });
  const imageInfo = await imageInspect(remote, info.Image);
  verifyImage(imageInfo, image);
  const internal = await probeContainer(remote, containerId, sourceSha);
  const appVersion = await remote.docker(['exec', containerId, 'printenv', 'APP_VERSION']);
  if (appVersion !== sourceSha) throw fatal('APP_VERSION inside the running container is not the signed source SHA');
  // setup_required is false whenever setup is disabled, so it proves nothing about an administrator: count the store.
  const administrator = await adminExec(remote, containerId);
  const x = target.exposure;
  const health = { internal };
  if (x.mode === 'public') {
    if (!administrator.verified) throw fatal('public exposure requires a verified enabled administrator in the native account store');
    const lan = await probe(`${x.lanUrl}${NGINX_PROBE_PATHS.authStatus.slice(1)}`);
    const lanAuth = JSON.parse(lan.body || 'null');
    need(lan.status === 200 && lanAuth?.mode === 'native' && lanAuth.setup_required === false, 'LAN auth status is not native with first-run setup closed');
    const lanSensitive = await probe(`${x.lanUrl}${NGINX_PROBE_PATHS.sensitive.slice(1)}`);
    need(lanSensitive.status === 401, `LAN unauthenticated sensitive endpoint answered ${lanSensitive.status}, not 401`);
    health.lan = { authStatus: lan.status, sensitiveStatus: lanSensitive.status };
  }
  return { runtime: { containerId: info.Id, containerName: spec.name, imageId: info.Image, repoDigests: imageInfo.RepoDigests ?? [], startedAt: info.State.StartedAt,
    restartCount: info.RestartCount ?? 0, appVersion, publishAddress: spec.address, hostPort: spec.hostPort }, administrator, health };
}
/**
 * Prove the public hostname reaches THIS container, not merely something that answers like it: send one
 * unauthenticated request carrying a fresh random nonce through the public URL, then find that nonce in
 * the inspected container's own nginx access log. A spoofed or misrouted origin cannot put a nonce it never
 * received into that log. Fails closed: if the public path cannot be probed (for example an access gate that
 * blocks unauthenticated requests) the binding is unproven.
 */
async function proveRouteToContainer({ remote, containerId, probe, publicUrl }) {
  const nonce = randomBytes(16).toString('hex');
  const response = await probe(`${publicUrl}${NGINX_PROBE_PATHS.authStatus.slice(1)}?tf_route_probe=${nonce}`);
  let auth = null;
  try { auth = JSON.parse(response.body || 'null'); } catch { auth = null; }
  need(response.status === 200 && auth?.mode === 'native' && auth.setup_required === false, 'the public hostname did not answer the unauthenticated auth status, so its route to the container cannot be proven');
  let seen = 0;
  try { seen = Number.parseInt(await remote.docker(['exec', containerId, 'grep', '-F', '-c', nonce, '/var/log/nginx/access.log']), 10); }
  catch (error) { if (error.code !== 1) throw error; }
  need(seen >= 1, 'the public hostname did not reach the inspected container: the probe nonce is absent from its nginx access log');
}
/**
 * Public routing as seen from outside: the signed ingress is the active one, the public hostname answers
 * safely, and a nonce sent through it demonstrably lands in the inspected container.
 */
async function observePublic({ probe, target, cf, plannedConfigSha256, remote, containerId }) {
  const x = target.exposure;
  const active = configDigest(await readTunnelConfig(cf, x.ingress));
  need(active === plannedConfigSha256, 'the live tunnel ingress is not the signed planned configuration');
  const root = await probe(x.publicUrl);
  need(root.status === x.publicStatus, `public URL answered ${root.status}, expected ${x.publicStatus}`);
  const sensitive = await probe(`${x.publicUrl}${NGINX_PROBE_PATHS.sensitive.slice(1)}`);
  need((x.sensitiveStatuses ?? [401]).includes(sensitive.status), `public unauthenticated sensitive endpoint answered ${sensitive.status}`);
  await proveRouteToContainer({ remote, containerId, probe, publicUrl: x.publicUrl });
  return { ingress: { provider: x.ingress.provider, activeConfigSha256: active }, public: { rootStatus: root.status, sensitiveStatus: sensitive.status, routeProof: 'nonce-in-container-access-log' } };
}

// ---------------------------------------------------------------------------------------------
// Prepare
// ---------------------------------------------------------------------------------------------
const gitEnv = (home, gitDir) => ({ PATH: CHILD_PATH, HOME: home, LANG: 'C', LC_ALL: 'C', GIT_NO_REPLACE_OBJECTS: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null',
  GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0', GIT_ATTR_NOSYSTEM: '1', ...(gitDir ? { GIT_DIR: gitDir } : {}) });
/**
 * A newly initialised bare repository with no configuration, no replacement objects and no alternates, used for every source
 * operation. A Task checkout's refs/replace, grafts, alternates or configuration could otherwise make `git archive SHA` yield a
 * tree other than the one the SHA names.
 */
export async function isolatedGit(command, parent) {
  const scratch = await mkdtemp(path.join(parent, '.git-'));
  const gitDir = path.join(scratch, 'repo');
  const home = path.join(scratch, 'home');
  await mkdir(home);
  await command('git', ['init', '--bare', '--quiet', gitDir], scratch, { env: gitEnv(home) });
  const env = gitEnv(home, gitDir);
  return { gitDir, git: (args, extra = {}) => command('git', args, scratch, { env, ...extra }), close: () => rm(scratch, { recursive: true, force: true }) };
}
/** Fetch exactly this commit, with object checking, into the isolated repository and prove it is that commit. */
export async function fetchSource(iso, repoUrl, sourceSha) {
  await iso.git(['-c', 'transfer.fsckObjects=true', 'fetch', '--no-tags', repoUrl, sourceSha]);
  need(await iso.git(['cat-file', '-t', sourceSha]) === 'commit' && await iso.git(['rev-parse', '--verify', `${sourceSha}^{commit}`]) === sourceSha, 'the fetched object is not the requested commit');
}
export async function ancestry(iso, sourceSha, triggeringMerge) {
  need(SHA.test(sourceSha) && SHA.test(triggeringMerge), 'full source and triggering merge SHAs required');
  await iso.git(['merge-base', '--is-ancestor', triggeringMerge, sourceSha]);
  const parents = await iso.git(['rev-list', '--parents', '-n', '1', triggeringMerge]);
  need(parents.split(/\s+/).length >= 3, 'triggering commit must be a merge');
}
const PREPARATION_TIMING_FIELDS = ['releaseRequestedAt', 'candidateQueuedAt', 'candidateStartedAt', 'evidenceCompletedAt', 'approvalCreatedAt'];
async function candidateTiming(dir, manifest) {
  const record = await regular(path.join(dir, 'timing.json')).then((bytes) => JSON.parse(bytes)).catch(() => null);
  if (!record || record.candidateId !== manifest.candidateId || record.sourceSha !== manifest.sourceSha || record.triggeringMerge !== manifest.triggeringMerge) return {};
  return Object.fromEntries(PREPARATION_TIMING_FIELDS.filter((key) => typeof record.timing?.[key] === 'string' && Number.isFinite(Date.parse(record.timing[key]))).map((key) => [key, record.timing[key]]));
}
export async function prepare(input) {
  const { root, candidate, sourceSha, triggeringMerge, trust } = input;
  need(ID.test(candidate), 'invalid candidate id');
  need(SHA.test(sourceSha) && SHA.test(triggeringMerge), 'full source and triggering merge SHAs required');
  const redact = makeRedactor(trust.policy);
  const dir = path.join(root, '.approval', candidate);
  await mkdir(path.dirname(dir), { recursive: true, mode: 0o700 });
  await mkdir(dir, { recursive: false, mode: 0o700 }); // never overwrite a retained attempt
  const timing = { candidateQueuedAt: iso() };
  const record = { schemaVersion: 1, candidateId: candidate, sourceSha, triggeringMerge, timing };
  const save = () => atomic(path.join(dir, 'timing.json'), record);
  await save();
  try {
    timing.candidateStartedAt = iso();
    await save();
    return await prepareCandidate({ ...input, dir, timing, save });
  } catch (error) {
    timing.failedAt = iso();
    record.error = redact(error.message);
    await save();
    for (const entry of await readdir(dir).catch(() => [])) {
      if (/^(\.git-|image-meta-)/.test(entry) || ['source', 'build', 'tools'].includes(entry)) await rm(path.join(dir, entry), { recursive: true, force: true });
    }
    throw error;
  }
}
async function readImageArchive(command, tarPath, dir, tag) {
  const meta = await mkdtemp(path.join(dir, 'image-meta-'));
  try { await command('tar', ['-xf', tarPath, '-C', meta, 'manifest.json'], dir); }
  catch { throw new Error('docker save produced an archive without manifest.json; this builder\'s image store or save format is unsupported'); }
  const manifest = JSON.parse(await readFile(path.join(meta, 'manifest.json'), 'utf8'));
  need(Array.isArray(manifest) && manifest.length === 1, 'image archive must hold exactly one image');
  const entry = manifest[0];
  need(typeof entry.Config === 'string' && /^(blobs\/sha256\/[a-f0-9]{64}|[a-f0-9]{64}\.json)$/.test(entry.Config), 'image archive config path is unsafe');
  need(Array.isArray(entry.RepoTags) && entry.RepoTags.length === 1 && [tag, `docker.io/library/${tag}`].includes(entry.RepoTags[0]), 'image archive must carry only the candidate tag');
  await command('tar', ['-xf', tarPath, '-C', meta, entry.Config], dir);
  const bytes = await readFile(path.join(meta, entry.Config));
  const digest = hash(bytes);
  need(entry.Config.includes(digest), 'image config digest does not match its archive path');
  await rm(meta, { recursive: true, force: true });
  return { bytes, digest, config: JSON.parse(bytes) };
}
function checkImageConfig(config, image, { candidate, sourceSha, triggeringMerge }) {
  need(`${config.os}/${config.architecture}` === image.platform, 'image platform is not the requested platform');
  const labels = config.config?.Labels ?? {};
  need(labels['org.opencontainers.image.revision'] === sourceSha && labels['io.tracefinity.release.candidate'] === candidate
    && labels['io.tracefinity.release.triggering-merge'] === triggeringMerge, 'image labels do not name this candidate and source');
  need((config.config?.Env ?? []).includes(`APP_VERSION=${sourceSha}`), 'image does not bake APP_VERSION as the full source SHA');
  need(Array.isArray(config.rootfs?.diff_ids) && config.rootfs.diff_ids.length > 0 && config.rootfs.diff_ids.every((id) => IMAGE_ID.test(id)), 'image config carries no layer IDs');
  need(same(config.rootfs.diff_ids, image.diffIds), 'image layer IDs differ from the pinned image');
}
const REQUIRED_TOOLS = [['git', ['--version']], ['tar', ['--version']], ['docker', ['--version']], ['ssh', ['-V']]];
/** Fail closed, naming every missing tool, before any slow work starts. */
async function checkTools(command, cwd) {
  const versions = {};
  const missing = [];
  for (const [tool, args] of REQUIRED_TOOLS) {
    try { versions[tool] = (await command(tool, args, cwd, { timeoutMs: 30_000 })).split('\n')[0]; }
    catch (error) { missing.push(`${tool} (${error.code === 'ENOENT' ? 'not installed' : String(error.message).slice(0, 120)})`); }
  }
  // Source, gate and dependency installs run in the sandbox container, so no python, node, corepack or make is needed (or trusted) on the host.
  try { versions.buildx = (await command('docker', ['buildx', 'version'], cwd, { timeoutMs: 30_000 })).split('\n')[0]; }
  catch { missing.push('docker buildx (the image build uses --provenance and --sbom flags)'); }
  need(missing.length === 0, `required tools are missing or unusable: ${missing.join('; ')}`);
  return versions;
}
/**
 * Build the sandbox toolchain image from the fixed in-controller Dockerfile, pin its ID, and return the runner for sandboxed steps.
 */
async function prepareSandbox(command, { dir, gateRoot, toolsDir, gatePath, policy }) {
  const engine = localEngine(command, dir);
  const tag = gateImageTag();
  await engine.docker(['build', '--pull', '--tag', tag, '-'], { input: GATE_DOCKERFILE, timeoutMs: 30 * 60_000 });
  const image = await engine.docker(['image', 'inspect', '--format', '{{.Id}}', tag]);
  need(IMAGE_ID.test(image), 'the sandbox image has no readable ID');
  for (const sub of ['bin', 'corepack', 'models', 'pnpm-home', 'pnpm-store']) await mkdir(path.join(toolsDir, sub), { recursive: true });
  const passwdFile = path.join(dir, 'gate-passwd');
  await writeFile(passwdFile, `root:x:0:0:root:/root:/bin/sh\ngate:x:${process.getuid()}:${process.getgid()}:gate:/tmp:/bin/sh\n`, { mode: 0o644 });
  return { image, dockerfileSha256: hash(GATE_DOCKERFILE), workSource: gateRoot, passwdFile,
    run: async ({ label, network, argv, workdir = '/work', gate = false, timeoutMs = 60 * 60_000 }) => {
      const args = gateRunArgs({ image, network, workSource: gateRoot, toolsDir, passwdFile, gateFile: gate ? gatePath : null, workdir, argv, candidateDir: dir, policy });
      try { return await engine.docker(args, { timeoutMs, maxOutput: 128 * 1024 * 1024, mergeStderr: true }); }
      catch (error) { throw new Error(`${label}: ${String(error.message).slice(0, 600)}`); }
    } };
}
/**
 * Provision isolated build/test dependencies inside the sandbox, in the archived gate export only, so the trusted `.ade/check` can
 * run unchanged: a backend venv with the app's requirements, pytest and ruff, and frontend modules from the frozen lockfile.
 */
async function provisionGate(sandbox) {
  const step = (label, argv, workdir = '/work') => sandbox.run({ label: `gate dependency provisioning failed at "${label}"`, network: 'bridge', argv, workdir });
  await step('python venv', ['python3', '-m', 'venv', 'backend/venv']);
  await step('pip upgrade', ['/work/backend/venv/bin/python', '-m', 'pip', 'install', '--upgrade', 'pip']);
  await step('cpu torch', ['/work/backend/venv/bin/python', '-m', 'pip', 'install', '--no-deps', 'torch', 'torchvision', '--index-url', 'https://download.pytorch.org/whl/cpu']);
  await step('backend requirements, pytest, ruff', ['/work/backend/venv/bin/python', '-m', 'pip', 'install', '-r', 'backend/requirements.txt', 'pytest', 'ruff']);
  // The backend builds its U2-Net Portable paper-detection session when the API module is imported, which downloads the weights on first
  // use. The network-less gate cannot, so fetch them here (rembg verifies the pinned checksum) into the scratch tools dir named by U2NET_HOME.
  const modelDigest = (await step('u2netp model weights', ['/work/backend/venv/bin/python', '-c', MODEL_FETCH])).trim().split('\n').at(-1);
  need(/^[a-f0-9]{64}$/.test(modelDigest), 'the u2netp model weights have no readable digest');
  await step('corepack pnpm shim', ['corepack', 'enable', '--install-directory', '/tools/bin', 'pnpm']);
  await step('frontend frozen lockfile install', ['/tools/bin/pnpm', 'install', '--frozen-lockfile', '--store-dir', '/tools/pnpm-store'], '/work/frontend');
  const evidence = { pipFreezeSha256: hash(await step('pip freeze', ['/work/backend/venv/bin/python', '-m', 'pip', 'freeze'])), u2netpSha256: modelDigest,
    pnpmVersion: await step('pnpm version', ['/tools/bin/pnpm', '--version'], '/work/frontend'), ruffVersion: await step('ruff version', ['/work/backend/venv/bin/ruff', '--version']),
    frontendLockSha256: hash(await readFile(path.join(sandbox.workSource, 'frontend/pnpm-lock.yaml'))) };
  return { evidence };
}
async function prepareCandidate({ root, dir, candidate, sourceSha, triggeringMerge, trust, command = run, sleep = pause, fetchImpl = fetch, timing, save }) {
  const { policy, policySha256 } = trust;
  const t = policy.target;
  const tools = await checkTools(command, root);
  const repoUrl = `https://github.com/${policy.source.repository}.git`;
  const branchRef = `refs/heads/${policy.source.branch}`;
  const repository = await isolatedGit(command, dir);
  const remoteHead = (await repository.git(['ls-remote', '--exit-code', repoUrl, branchRef])).split('\n').filter(Boolean).map((line) => line.split(/\s+/));
  need(remoteHead.length === 1 && remoteHead[0][1] === branchRef && remoteHead[0][0] === sourceSha, `source must be the exact current remote ${policy.source.branch}`);
  await fetchSource(repository, repoUrl, sourceSha); // objects only, into the isolated repository: never the Task checkout
  await ancestry(repository, sourceSha, triggeringMerge);
  const sourceProvenance = { commit: sourceSha, tree: await repository.git(['rev-parse', `${sourceSha}^{tree}`]), repository: policy.source.repository, isolatedRepository: true, replaceObjects: 'disabled', objectChecking: 'transfer.fsckObjects' };
  // Fail fast if the target cannot be observed. Preparation only ever reads the remote.
  const observe = async (fn) => { const remote = readOnlyEngine(await openRemote(trust, command)); try { return await fn(remote); } finally { await remote.close(); } };
  const engineVersion = await observe(async (remote) => {
    const version = await remote.docker(['version', '--format', '{{.Server.Version}}']);
    need(!(await remote.docker(['info', '--format', '{{json .DriverStatus}}'])).includes('io.containerd.snapshotter'),
      'target engine uses the containerd image store; its image IDs cannot be compared with the signed ID');
    return version;
  });
  // Two pristine exports of the exact commit: one is gated, the other is the only build context.
  const sourceTar = path.join(dir, 'source.tar');
  await repository.git(['archive', '--format=tar', `--output=${sourceTar}`, sourceSha]);
  const gateRoot = path.join(dir, 'source');
  const buildRoot = path.join(dir, 'build');
  for (const target of [gateRoot, buildRoot]) { await mkdir(target); await command('tar', ['-xf', sourceTar, '--no-same-owner', '-C', target]); }
  const fingerprint = await sourceFingerprint(buildRoot);
  need(await sourceFingerprint(gateRoot) === fingerprint, 'source exports differ');
  // The gate is read from the exact trusted commit and fails closed: absent or non-zero stops preparation.
  const gate = await repository.git(['show', `${sourceSha}:.ade/check`]);
  need(gate.trim().length > 0, 'trusted .ade/check is empty');
  const gatePath = path.join(dir, 'trusted-check.sh');
  await writeFile(gatePath, `${gate}\n`, { mode: 0o700 });
  const toolsDir = path.join(dir, 'tools');
  const sandbox = await prepareSandbox(command, { dir, gateRoot, toolsDir, gatePath, policy });
  const provisioned = await provisionGate(sandbox);
  const gateLog = await sandbox.run({ label: 'trusted gate', network: 'none', argv: ['bash', '/gate/check'], gate: true, timeoutMs: 120 * 60_000 });
  need(await sourceFingerprint(buildRoot) === fingerprint, 'build context changed during checks');
  // Build the image from the untouched export and pin it.
  const tag = `${policy.build.imageRepository}:${candidate}`;
  const local = localEngine(command, buildRoot);
  await local.docker(['build', '--pull', '--platform', policy.build.platform, '--provenance=false', '--sbom=false', '--build-arg', `APP_VERSION=${sourceSha}`,
    '--label', `org.opencontainers.image.revision=${sourceSha}`, '--label', `org.opencontainers.image.source=https://github.com/${policy.source.repository}`,
    '--label', `io.tracefinity.release.candidate=${candidate}`, '--label', `io.tracefinity.release.triggering-merge=${triggeringMerge}`, '--tag', tag, buildRoot],
  { timeoutMs: 90 * 60_000 });
  need(await sourceFingerprint(buildRoot) === fingerprint, 'build changed the source export');
  const imageTar = path.join(dir, 'image.tar');
  await local.docker(['save', '--output', imageTar, tag], { timeoutMs: 30 * 60_000 });
  const archive = await readImageArchive(command, imageTar, dir, tag);
  const imageId = `sha256:${archive.digest}`;
  const image = { tag, platform: policy.build.platform, imageId, diffIds: archive.config.rootfs?.diff_ids ?? [], tarSha256: await hashFile(imageTar),
    tarBytes: (await lstat(imageTar)).size, appVersion: sourceSha };
  checkImageConfig(archive.config, image, { candidate, sourceSha, triggeringMerge });
  await writeFile(path.join(dir, 'image-config.json'), archive.bytes, { mode: 0o600 });
  const builderImageId = await local.docker(['image', 'inspect', '--format', '{{.Id}}', tag]);
  const canary = await runCanary(local, { ref: tag, name: `tracefinity-canary-${candidate}`, target: t, sourceSha, sleep });
  const spec = buildContainerSpec(t, image, { candidate, sourceSha });
  // Observe the live container and the tunnel as late as possible, so the signed "before" state is fresh. Read-only.
  const previous = await observe((remote) => snapshotContainer(remote, t.container.name));
  let ingress = null;
  if (t.exposure.mode === 'public') {
    const g = t.exposure.ingress;
    const cf = readOnlyCloudflare(openCloudflare(trust, fetchImpl));
    await checkTunnelDns(cf, g);
    const base = await readTunnelConfig(cf, g);
    const plan = planIngress(base, g);
    ingress = ingressSummary(g, plan.action, base, plan.safe, plan.planned);
    await writeFile(path.join(dir, 'ingress-plan.json'), encode({ schemaVersion: 1, tunnelId: g.tunnelId, hostname: g.hostname, service: g.service, action: plan.action, base, safe: plan.safe, planned: plan.planned }), { mode: 0o600 });
  }
  // Evidence, artifacts, manifest, approval and handoff.
  await copyFile(path.join(buildRoot, 'scripts/release-controller.mjs'), path.join(dir, 'release-controller.mjs'));
  await chmod(path.join(dir, 'release-controller.mjs'), 0o600);
  await writeFile(path.join(dir, 'checks.json'), encode({ sourceSha, triggeringMerge, gate: { path: '.ade/check', sha256: hash(await regular(gatePath)), exitCode: 0, logTail: gateLog.slice(-16384) },
    provisioning: { tools, ...provisioned.evidence }, gateSandbox: { image: sandbox.image, dockerfileSha256: sandbox.dockerfileSha256, provisionNetwork: 'bridge', gateNetwork: 'none', limits: GATE_LIMITS, hostMounts: ['source copy', 'scratch tools', 'generated passwd', 'gate script (read-only)'] },
    sourceFingerprint: fingerprint, sourceProvenance, image: { imageId, tarSha256: image.tarSha256, builderImageId }, canary,
    engine: { dockerServer: engineVersion }, controller: { preparedWith: hash(await readFile(SELF)), exported: hash(await regular(path.join(dir, 'release-controller.mjs'))) },
    remoteAccess: 'read-only' }), { mode: 0o600 });
  const artifacts = {};
  for (const file of artifactsFor(t)) artifacts[file] = await hashFile(path.join(dir, file));
  need(artifacts['image.tar'] === image.tarSha256, 'image archive changed while preparing');
  timing.evidenceCompletedAt = iso();
  await save();
  const manifest = { schemaVersion: 1, kind: 'tracefinity.release-manifest', candidateId: candidate, sourceSha, triggeringMerge, policySha256, target: t,
    source: { repository: policy.source.repository, branch: policy.source.branch, fingerprint, archiveSha256: artifacts['source.tar'] }, image,
    container: { name: spec.name, createArgs: spec.createArgs, specSha256: spec.specSha256 }, previous, ingress,
    builder: { node: process.version, platform: process.platform, arch: process.arch }, artifacts };
  const manifestBytes = encode(manifest);
  await writeFile(path.join(dir, 'manifest.json'), manifestBytes, { mode: 0o600 });
  // Slow cleanup first: the approval clock starts only now, after the image is built and everything is ready to sign.
  for (const leftover of [gateRoot, buildRoot, toolsDir, path.join(dir, 'gate-passwd')]) await rm(leftover, { recursive: true, force: true });
  await repository.close();
  const created = Date.now();
  const approval = encode({ schemaVersion: 1, kind: 'tracefinity.production-approval', candidateId: candidate, sourceSha, triggeringMerge, services: [SERVICE],
    manifestSha256: hash(manifestBytes), imageId, imageTarSha256: image.tarSha256, containerSpecSha256: spec.specSha256, previous, ingress, exposure: t.exposure.mode,
    target: t, policySha256, createdAt: new Date(created).toISOString(), expiresAt: new Date(created + APPROVAL_LIFETIME_MS).toISOString() });
  await writeFile(path.join(dir, 'approval.json'), approval, { mode: 0o600 });
  await writeFile(path.join(dir, 'signing-handoff.json'), encode(handoff(approval)), { mode: 0o600 });
  timing.approvalCreatedAt = new Date(created).toISOString();
  await save();
  return { candidateId: candidate, sourceSha, imageId, status: 'awaiting_signature', deployedSha: null, exposure: t.exposure.mode, ingress: ingress ? { action: ingress.action, hostname: ingress.hostname } : null,
    expiresAt: new Date(created + APPROVAL_LIFETIME_MS).toISOString() };
}

// ---------------------------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------------------------
/**
 * Verify one candidate directory against the pinned policy. `artifacts: 'all'` re-hashes the image
 * archive; `'small'` (used between mutations, when the archive is no longer an input) checks its size only.
 * `verifier` replaces the Ed25519 check in tests only; no command-line or environment path reaches it.
 */
export async function verifyCandidate(dir, trust, { signed = true, now = Date.now(), artifacts = 'all', verifier = verifyDetachedSignature } = {}) {
  const directory = await lstat(dir);
  need(directory.isDirectory() && !directory.isSymbolicLink() && directory.uid === process.getuid() && (directory.mode & 0o022) === 0, 'candidate directory is not owner-owned');
  const approvalBytes = await regular(path.join(dir, 'approval.json'));
  const a = JSON.parse(approvalBytes);
  exact(a, ['schemaVersion', 'kind', 'candidateId', 'sourceSha', 'triggeringMerge', 'services', 'manifestSha256', 'imageId', 'imageTarSha256',
    'containerSpecSha256', 'previous', 'ingress', 'exposure', 'target', 'policySha256', 'createdAt', 'expiresAt'], [], 'approval');
  need(a.candidateId === path.basename(dir), 'candidate directory/approval mismatch');
  need(a.schemaVersion === 1 && a.kind === 'tracefinity.production-approval' && ID.test(a.candidateId) && SHA.test(a.sourceSha) && SHA.test(a.triggeringMerge)
    && same(a.services, [SERVICE]) && IMAGE_ID.test(a.imageId) && SHA256.test(a.imageTarSha256) && SHA256.test(a.containerSpecSha256), 'invalid approval');
  need(Date.parse(a.expiresAt) > now && Date.parse(a.createdAt) <= now && Date.parse(a.expiresAt) - Date.parse(a.createdAt) <= APPROVAL_LIFETIME_MS, 'approval absent, invalid or expired');
  const manifestBytes = await regular(path.join(dir, 'manifest.json'));
  need(hash(manifestBytes) === a.manifestSha256, 'tampered manifest');
  const m = JSON.parse(manifestBytes);
  need(m.schemaVersion === 1 && m.kind === 'tracefinity.release-manifest', 'invalid manifest');
  for (const key of ['candidateId', 'sourceSha', 'triggeringMerge', 'policySha256']) need(m[key] === a[key], `manifest ${key} mismatch`);
  need(a.policySha256 === trust.policySha256 && same(a.target, trust.policy.target) && same(m.target, a.target) && a.exposure === a.target.exposure.mode,
    'approval does not match trusted policy/target');
  need(m.image?.imageId === a.imageId && m.image.tarSha256 === a.imageTarSha256 && m.container?.specSha256 === a.containerSpecSha256 && same(m.previous, a.previous),
    'approval does not bind the manifest image, container and previous state');
  need(m.image.appVersion === m.sourceSha && m.image.platform === trust.policy.build.platform && m.source?.repository === trust.policy.source.repository, 'manifest image/source mismatch');
  need(a.previous?.present === false || (a.previous?.present === true && SHA256.test(a.previous.containerId) && IMAGE_ID.test(a.previous.imageId)), 'invalid previous container identity');
  const spec = buildContainerSpec(trust.policy.target, m.image, { candidate: m.candidateId, sourceSha: m.sourceSha });
  need(same(m.container.createArgs, spec.createArgs) && m.container.specSha256 === spec.specSha256 && m.container.name === spec.name, 'manifest container spec is not the one the policy derives');
  need(same(await json(path.join(dir, 'signing-handoff.json')), handoff(approvalBytes)), 'tampered signing handoff');
  const files = artifactsFor(trust.policy.target);
  need(same(Object.keys(m.artifacts).sort(), [...files].sort()), 'unexpected artifact set');
  for (const file of files) {
    if (file === 'image.tar' && artifacts === 'small') {
      const info = await regularInfo(path.join(dir, file));
      need(info.size === m.image.tarBytes, 'tampered artifact: image.tar');
    } else need(await hashFile(path.join(dir, file)) === m.artifacts[file], `tampered artifact: ${file}`);
  }
  if (trust.policy.target.exposure.mode === 'public') {
    // The approval binds the tunnel, hostname, service and the digests of the configuration before and after; recompute all of it.
    const g = trust.policy.target.exposure.ingress;
    const plan = await json(path.join(dir, 'ingress-plan.json'));
    need(plan.schemaVersion === 1 && plan.tunnelId === g.tunnelId && plan.hostname === g.hostname && plan.service === g.service, 'ingress plan does not name the policy tunnel/hostname/service');
    const again = planIngress(plan.base, g);
    need(again.action === plan.action && configDigest(again.safe) === configDigest(plan.safe) && configDigest(again.planned) === configDigest(plan.planned), 'ingress plan is not the minimal change to its base configuration');
    const summary = ingressSummary(g, plan.action, plan.base, plan.safe, plan.planned);
    need(same(a.ingress, summary) && same(m.ingress, summary), 'approval does not bind the ingress plan');
  } else need(a.ingress === null && m.ingress === null, 'a private candidate may not carry ingress changes');
  need(m.artifacts['image.tar'] === m.image.tarSha256 && m.artifacts['source.tar'] === m.source.archiveSha256, 'artifact digests are not the pinned image/source');
  const configBytes = await regular(path.join(dir, 'image-config.json'));
  need(`sha256:${hash(configBytes)}` === m.image.imageId, 'image config is not the pinned image ID');
  const config = JSON.parse(configBytes);
  checkImageConfig(config, m.image, { candidate: m.candidateId, sourceSha: m.sourceSha, triggeringMerge: m.triggeringMerge });
  const evidence = await json(path.join(dir, 'checks.json'));
  need(evidence.gate?.sha256 === m.artifacts['trusted-check.sh'] && evidence.gate.exitCode === 0, 'trusted gate evidence mismatch');
  need(evidence.sourceSha === m.sourceSha && evidence.triggeringMerge === m.triggeringMerge && evidence.image?.imageId === m.image.imageId && evidence.sourceFingerprint === m.source.fingerprint,
    'build/check identity mismatch');
  if (signed) need(verifier(approvalBytes, await regular(path.join(dir, 'release.sig')), trust.policy.publicKeyBase64) !== false, 'signature is not from the explicitly trusted operator');
  return m;
}

// ---------------------------------------------------------------------------------------------
// Submit
// ---------------------------------------------------------------------------------------------
export async function submit({ root, candidate, trust, command = run, now = () => Date.now(), verifier = verifyDetachedSignature }) {
  need(ID.test(candidate), 'invalid candidate id');
  const dir = path.join(root, '.approval', candidate);
  need(await realpath(dir) === dir, 'candidate path may not traverse symlinks');
  const manifest = await verifyCandidate(dir, trust, { now: now(), verifier });
  const signatureAcceptedAt = iso();
  const approval = await json(path.join(dir, 'approval.json'));
  const acceptedTiming = { ...await candidateTiming(dir, manifest), approvalCreatedAt: approval.createdAt, signatureAcceptedAt };
  await atomic(path.join(dir, 'timing.json'), { schemaVersion: 1, candidateId: candidate, sourceSha: manifest.sourceSha, triggeringMerge: manifest.triggeringMerge, timing: acceptedTiming });
  try {
    await mkdir(trust.policy.target.receiptsRoot, { recursive: true, mode: 0o700 });
    const iso = await isolatedGit(command, trust.policy.target.receiptsRoot);
    try { await fetchSource(iso, `https://github.com/${trust.policy.source.repository}.git`, manifest.sourceSha); await ancestry(iso, manifest.sourceSha, manifest.triggeringMerge); }
    finally { await iso.close(); }
  }
  catch (error) {
    await atomic(path.join(dir, 'timing.json'), { schemaVersion: 1, candidateId: candidate, sourceSha: manifest.sourceSha, triggeringMerge: manifest.triggeringMerge,
      failureStage: 'submission', error: makeRedactor(trust.policy)(error.message), timing: { ...acceptedTiming, failedAt: iso() } });
    throw error;
  }
  const t = trust.policy.target;
  const job = path.join(t.receiptsRoot, candidate);
  await mkdir(t.receiptsRoot, { recursive: true, mode: 0o700 });
  await mkdir(job, { mode: 0o700 }); // an existing job refuses replay, including uncertain dispatch
  const receipt = path.join(job, 'receipt.json');
  const approvalSha256 = hash(await regular(path.join(dir, 'approval.json')));
  const base = { candidateId: candidate, sourceSha: manifest.sourceSha, triggeringMerge: manifest.triggeringMerge, approvalSha256, policySha256: trust.policySha256, deployedSha: null };
  const submitting = { status: 'submitting', ...base, timing: acceptedTiming };
  await atomic(receipt, submitting);
  const redact = makeRedactor(trust.policy);
  try {
    for (const file of ['approval.json', 'manifest.json', 'signing-handoff.json', 'release.sig', ...Object.keys(manifest.artifacts)]) {
      await copyFile(path.join(dir, file), path.join(job, file), fsConstants.COPYFILE_EXCL | fsConstants.COPYFILE_FICLONE);
      await chmod(path.join(job, file), 0o400);
    }
    await verifyCandidate(job, trust, { now: now(), verifier });
  } catch (error) {
    await atomic(receipt, { ...submitting, status: 'failed', error: redact(error.message), timing: { ...acceptedTiming, failedAt: iso() } });
    throw error;
  }
  const queued = { status: 'queued', ...base, timing: { ...acceptedTiming, deployQueuedAt: iso() } };
  await atomic(receipt, queued);
  try {
    await command('systemd-run', ['--user', '--unit', `tracefinity-release-${candidate}`, '--collect', '--property=Type=exec', '--property=UMask=0077',
      '--property=NoNewPrivileges=yes', '--property=PrivateTmp=yes', '--property=RuntimeMaxSec=3h', `--working-directory=${job}`,
      t.nodePath, path.join(job, 'release-controller.mjs'), 'deploy-job', '--candidate', candidate]);
  } catch (error) {
    // A transport error does not prove the worker failed to start: keep separate dispatch evidence and never claim failure.
    await atomic(path.join(job, 'dispatch-error.json'), { candidateId: candidate, sourceSha: manifest.sourceSha, triggeringMerge: manifest.triggeringMerge, failedAt: iso(), error: redact(error.message) });
    throw error;
  }
  return { ...queued, receipt };
}

// ---------------------------------------------------------------------------------------------
// Deployment worker
// ---------------------------------------------------------------------------------------------
/**
 * Fail-closed retraction to the signed route-absent configuration, only while the live configuration is still exactly the
 * signed plan, and only with a valid signature and unexpired approval checked immediately before the write.
 */
async function retractIngress(cf, g, plan, plannedConfigSha256, authorize) {
  const current = await readTunnelConfig(cf, g);
  if (configDigest(current) !== plannedConfigSha256) return { retracted: false, reason: 'the tunnel configuration is no longer the signed planned one; left untouched' };
  await writeIngress(cf, g, { expectSha256: plannedConfigSha256, config: plan.safe, authorize });
  return { retracted: true };
}
const PUBLIC_ATTEMPTS = 60;
export async function deployJob({ candidate, trust, command = run, probe = defaultProbe, fetchImpl = fetch, sleep = pause, now = () => Date.now(), verifier = verifyDetachedSignature }) {
  need(ID.test(candidate), 'invalid candidate id');
  const t = trust.policy.target;
  const redact = makeRedactor(trust.policy);
  const job = path.join(t.receiptsRoot, candidate);
  const receipt = path.join(job, 'receipt.json');
  const productionPath = path.join(t.receiptsRoot, 'production-state.json');
  const queued = await json(receipt);
  need(queued.status === 'queued', 'job already attempted; inspect receipt, never replay automatically');
  const timing = { ...queued.timing, deployStartedAt: iso() };
  const progress = { ...queued, status: 'deploying', deployedSha: null, timing };
  await atomic(receipt, progress); // persist the start before validation, the lock or any target contact
  const lock = path.join(t.receiptsRoot, 'deployment.lock');
  const verify = (mode) => verifyCandidate(job, trust, { now: now(), artifacts: mode, verifier });
  /** Signature, strict expiry, policy and artifacts, checked again at this moment: required immediately before every mutation. */
  const authorize = () => verify('small');
  let m;
  try {
    m = await verify('all'); // verification before the lock and before any target contact
    await mkdir(lock).catch((error) => { throw error.code === 'EEXIST' ? new Error('another deployment holds the deployment lock; inspect the target before removing it') : error; });
  } catch (error) {
    await atomic(receipt, { ...progress, status: 'failed', deployedSha: null, error: redact(error.message), timing: { ...timing, failedAt: iso() } }).catch(() => {});
    throw error;
  }
  const spec = buildContainerSpec(t, m.image, { candidate, sourceSha: m.sourceSha });
  const g = t.exposure.mode === 'public' ? t.exposure.ingress : null;
  let phase = 'connect';
  let mutated = false;
  let remote = null;
  let staged = null;
  let live0 = null;
  let ingressRecord = null;
  let priorState = null;
  let uncertainWritten = false;
  let result;
  /** One irreversible step on the live target: authorized immediately before it, and from then on the target counts as changed. */
  const liveStep = async (fn) => { await authorize(); mutated = true; return fn(); };
  try {
    remote = await openRemote(trust, command);
    const cf = g ? openCloudflare(trust, fetchImpl) : null;
    phase = 'preflight';
    await atomic(receipt, { ...progress, phase });
    await remote.docker(['version', '--format', '{{.Server.Version}}']);
    live0 = await snapshotContainer(remote, spec.name);
    need(samePrevious(live0, m.previous), 'target changed since preparation: the live container is not the signed previous container');
    for (const name of [spec.nextName, spec.prevName]) need(!(await containerInspect(remote, name)), `container name ${name} is already in use on the target; this candidate was already attempted`);
    if (cf) {
      await checkTunnelDns(cf, g);
      need(configDigest(await readTunnelConfig(cf, g)) === m.ingress.baseConfigSha256, 'the tunnel ingress changed since preparation; refusing');
    }
    phase = 'image';
    await atomic(receipt, { ...progress, phase });
    await verify('all'); // before the first target mutation
    const present = await imageInspect(remote, m.image.imageId);
    let transferred = false;
    if (!present) {
      await authorize(); // immediately before the transfer
      await remote.docker(['load'], { stdinFile: path.join(job, 'image.tar'), stdinSha256: m.image.tarSha256, timeoutMs: 60 * 60_000 });
      transferred = true;
    }
    verifyImage(await imageInspect(remote, m.image.imageId), m.image);
    phase = 'administrator';
    await authorize();
    // setup is disabled, so auth/status cannot show an administrator: count the real account store, read-only, with the signed image.
    const administrator = await adminOneShot(remote, m.image.imageId, t.container.storagePath);
    if (g && !administrator.verified) throw new Error('public exposure refused: no enabled administrator exists in the native account store; deploy privately, provision one out of band, then sign a fresh public candidate');
    phase = 'canary';
    await runCanary(remote, { ref: m.image.imageId, name: `tracefinity-canary-${candidate}`, target: t, sourceSha: m.sourceSha, sleep, authorize, staged: { spec } });
    phase = 'stage';
    await authorize();
    await remote.docker(spec.createArgs);
    const next = await containerInspect(remote, spec.nextName);
    need(next, 'staged container was not created');
    staged = next.Id;
    verifyContainer(next, spec, spec.nextName, m.image, { running: false });
    phase = 'cutover';
    const check = await snapshotContainer(remote, spec.name);
    need(samePrevious(check, m.previous), 'target changed during staging; refusing to cut over');
    // From here the live service may change at any step. Persist an uncertain state BEFORE the first mutation, so a killed worker
    // can never leave the previous release looking like the current one.
    priorState = await readFile(productionPath).catch(() => null);
    const uncertain = { ...progress, phase, uncertain: true, previousContainer: live0, stagedContainerId: staged, imageTransferred: transferred, policySha256: trust.policySha256 };
    await atomic(receipt, uncertain);
    await atomic(productionPath, uncertain);
    uncertainWritten = true;
    const plan = g ? await json(path.join(job, 'ingress-plan.json')) : null;
    if (g) ingressRecord = { action: m.ingress.action, singleWriterAttested: true, withdrawn: false, putAttempted: false, applied: false,
      baseConfigSha256: m.ingress.baseConfigSha256, safeConfigSha256: m.ingress.safeConfigSha256, plannedConfigSha256: m.ingress.plannedConfigSha256 };
    if (g && m.ingress.action === 'replace') {
      // The existing route would reach the replacement the moment it starts: withdraw it (signed) before the cutover, restore it only once the replacement is proven.
      await writeIngress(cf, g, { expectSha256: m.ingress.baseConfigSha256, config: plan.safe, authorize, onBeforePut: () => { mutated = true; } });
      ingressRecord.withdrawn = true;
    }
    if (live0.present) {
      await liveStep(() => remote.docker(['stop', '--time', '30', live0.containerId], { timeoutMs: 300_000 }));
      await liveStep(() => remote.docker(['update', '--restart', 'no', live0.containerId]));
      await liveStep(() => remote.docker(['rename', live0.containerId, spec.prevName]));
    }
    await liveStep(() => remote.docker(['rename', staged, spec.name]));
    await liveStep(() => remote.docker(['start', staged]));
    phase = 'verify-live';
    let observed;
    for (let attempt = 1; ; attempt++) {
      try { observed = await observeRuntime({ remote, spec, image: m.image, sourceSha: m.sourceSha, target: t, containerId: staged, probe }); break; }
      catch (error) {
        if (error.fatal || attempt >= BOOT_ATTEMPTS) throw new Error(error.fatal ? error.message : `new container did not pass live verification after ${BOOT_ATTEMPTS} attempts: ${error.message}`);
        if (attempt % 5 === 0) await atomic(receipt, { ...progress, phase, uncertain: true, previousContainer: live0, stagedContainerId: staged, verifying: { attempt, windowSeconds: BOOT_ATTEMPTS, lastReason: redact(error.message) } });
        await sleep(1000);
      }
    }
    let publicSide = null;
    if (cf) {
      // Route activation is its own signed step: only with the container proven and an administrator verified inside it.
      phase = 'ingress';
      need(observed.administrator.verified, 'no verified administrator inside the running container; refusing to activate public routing');
      try {
        const written = await writeIngress(cf, g, { expectSha256: m.ingress.action === 'replace' ? m.ingress.safeConfigSha256 : m.ingress.baseConfigSha256, config: plan.planned, authorize,
          onBeforePut: () => { ingressRecord.putAttempted = true; } });
        ingressRecord.applied = true;
        ingressRecord.versions = written;
        for (let attempt = 1; ; attempt++) {
          try { publicSide = await observePublic({ probe, target: t, cf, plannedConfigSha256: m.ingress.plannedConfigSha256, remote, containerId: staged }); break; }
          catch (error) { if (attempt >= PUBLIC_ATTEMPTS) throw error; await sleep(1000); }
        }
      } catch (error) {
        if (ingressRecord.putAttempted) {
          ingressRecord.retraction = await retractIngress(cf, g, plan, m.ingress.plannedConfigSha256, authorize).catch((e) => (e.unauthorized
            ? { retracted: false, authorized: false, reason: `compensating ingress change not authorized (${redact(e.message)}); the public route may still be active and needs operator action` }
            : { retracted: false, reason: redact(e.message) }));
        }
        throw new Error(`${error.message}${ingressRecord.retraction ? (ingressRecord.retraction.retracted ? '; ingress retracted to the signed route-absent configuration' : `; ingress could not be retracted (${ingressRecord.retraction.reason})`) : ''}`);
      }
      ingressRecord.activeConfigSha256 = publicSide.ingress.activeConfigSha256;
    }
    timing.verifiedAt = iso();
    result = { status: 'deployed', candidateId: candidate, sourceSha: m.sourceSha, triggeringMerge: m.triggeringMerge, deployedSha: m.sourceSha,
      approvalSha256: queued.approvalSha256, manifestSha256: hash(await regular(path.join(job, 'manifest.json'))), policySha256: trust.policySha256,
      image: { imageId: m.image.imageId, tarSha256: m.image.tarSha256, transferred }, runtime: observed.runtime, administrator: { ...administrator, ...observed.administrator },
      exposure: { mode: t.exposure.mode, publicExposure: cf ? 'verified' : 'not_applied' }, ingress: ingressRecord, health: { ...observed.health, ...(publicSide ? { public: publicSide.public } : {}) },
      previousContainer: live0, preservedPreviousName: live0.present ? spec.prevName : null, verifiedAt: timing.verifiedAt, timing };
    await atomic(receipt, result);
    await atomic(productionPath, result);
  } catch (error) {
    // Nothing on the live target changed: the previous production state is still true, so put it back.
    if (!mutated && uncertainWritten) await (priorState ? atomic(productionPath, JSON.parse(priorState)) : rm(productionPath, { force: true })).catch(() => {});
    const failed = { ...progress, status: mutated ? 'production_incomplete' : 'failed', phase, deployedSha: null, error: redact(error.message),
      ...(mutated ? { previousContainer: live0, stagedContainerId: staged, preservedPreviousName: live0?.present ? spec.prevName : null, ingress: ingressRecord, policySha256: trust.policySha256 } : {}),
      timing: { ...timing, failedAt: iso() } };
    if (!mutated && staged && remote) await remote.docker(['rm', '-f', staged]).catch(() => {});
    await atomic(receipt, failed);
    if (mutated) await atomic(productionPath, failed);
    throw error;
  } finally {
    await remote?.close().catch(() => {});
    await rm(lock, { recursive: true, force: true });
  }
  return result;
}

/**
 * Re-run every live proof against the pinned policy and the durable candidate. Read-only on the
 * target. `execute` additionally upgrades a `production_incomplete` record, and nothing else, to
 * `deployed` when every proof passes; the original failure stays on the record as `recovery`.
 */
export async function verifyLive({ candidate, trust, command = run, probe = defaultProbe, fetchImpl = fetch, execute = false, verifier = verifyDetachedSignature }) {
  need(ID.test(candidate), 'invalid candidate id');
  const t = trust.policy.target;
  const redact = makeRedactor(trust.policy);
  const job = path.join(t.receiptsRoot, candidate);
  const record = await json(path.join(job, 'receipt.json'));
  need(['deployed', 'production_incomplete'].includes(record.status), `only a deployed or production_incomplete job can be verified live (this one is ${record.status})`);
  const production = await json(path.join(t.receiptsRoot, 'production-state.json'));
  need(production.candidateId === candidate && production.status === record.status, 'production-state.json names a different job; inspect the target first');
  const signedAt = Date.parse(record.timing?.signatureAcceptedAt ?? record.timing?.deployStartedAt ?? '');
  need(Number.isFinite(signedAt), 'the job never recorded when the signature was accepted');
  const m = await verifyCandidate(job, trust, { now: signedAt, artifacts: 'small', verifier });
  const spec = buildContainerSpec(t, m.image, { candidate, sourceSha: m.sourceSha });
  const remote = await openRemote(trust, command);
  let observed;
  let publicSide = null;
  try {
    const live = await snapshotContainer(remote, spec.name);
    need(live.present, 'no container owns the production name');
    const expected = record.runtime?.containerId ?? record.stagedContainerId;
    if (expected && live.containerId !== expected) throw new Error('the live container is not the one this job deployed');
    observed = await observeRuntime({ remote, spec, image: m.image, sourceSha: m.sourceSha, target: t, containerId: live.containerId, probe });
    if (t.exposure.mode === 'public') publicSide = await observePublic({ probe, target: t, cf: openCloudflare(trust, fetchImpl), plannedConfigSha256: m.ingress.plannedConfigSha256, remote, containerId: live.containerId });
  } catch (error) {
    return { status: record.status, candidateId: candidate, sourceSha: m.sourceSha, deployedSha: null, verifiedLive: false, reason: redact(error.message) };
  } finally { await remote.close(); }
  const exposure = { mode: t.exposure.mode, publicExposure: publicSide ? 'verified' : 'not_applied' };
  const health = { ...observed.health, ...(publicSide ? { public: publicSide.public } : {}) };
  const ingress = publicSide ? { ...(record.ingress ?? {}), activeConfigSha256: publicSide.ingress.activeConfigSha256 } : null;
  if (record.status === 'deployed' || !execute) return { status: record.status, candidateId: candidate, sourceSha: m.sourceSha, deployedSha: m.sourceSha, verifiedLive: true,
    runtime: observed.runtime, administrator: observed.administrator, exposure, ingress, health, upgradePending: record.status !== 'deployed' };
  const { failedAt, ...timing } = record.timing ?? {};
  timing.verifiedAt = iso();
  const result = { status: 'deployed', candidateId: candidate, sourceSha: m.sourceSha, triggeringMerge: m.triggeringMerge, deployedSha: m.sourceSha,
    approvalSha256: record.approvalSha256, manifestSha256: hash(await regular(path.join(job, 'manifest.json'))), policySha256: trust.policySha256,
    image: { imageId: m.image.imageId, tarSha256: m.image.tarSha256 }, runtime: observed.runtime, administrator: observed.administrator, exposure, ingress,
    health, previousContainer: record.previousContainer ?? null, preservedPreviousName: record.preservedPreviousName ?? null, verifiedAt: timing.verifiedAt, timing,
    recovery: { from: 'production_incomplete', failedAt: failedAt ?? null, error: typeof record.error === 'string' ? record.error : null } };
  await atomic(path.join(job, 'receipt.json'), result);
  await atomic(path.join(t.receiptsRoot, 'production-state.json'), result);
  return result;
}

// ---------------------------------------------------------------------------------------------
// Status and acceptance support
// ---------------------------------------------------------------------------------------------
const none = 'No Tracefinity release has been deployed by the controller';
const minute = (stamp) => (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(stamp) ? `${stamp.slice(0, 16)}Z` : stamp);
async function latestJob(receiptsRoot) {
  const entries = await readdir(receiptsRoot, { withFileTypes: true }).catch(() => []);
  let newest = null;
  for (const entry of entries) {
    if (!entry.isDirectory() || !ID.test(entry.name)) continue;
    const info = await lstat(path.join(receiptsRoot, entry.name, 'receipt.json')).catch(() => null);
    if (info?.isFile() && (!newest || info.mtimeMs > newest.mtimeMs)) newest = { candidateId: entry.name, mtimeMs: info.mtimeMs };
  }
  if (!newest) return null;
  const receipt = await json(path.join(receiptsRoot, newest.candidateId, 'receipt.json')).catch(() => null);
  return receipt && typeof receipt === 'object' && !Array.isArray(receipt) ? { ...receipt, candidateId: newest.candidateId } : null;
}
function describe(record, deployedSha) {
  const candidate = record.candidateId ?? 'unknown';
  if (!deployedSha) return `not deployed: ${record.status} for candidate ${candidate}${record.uncertain ? ' (a cutover is in progress or its worker died; the live state is uncertain and no SHA is claimed)' : ''}${record.error ? `: ${record.error}` : ''}`;
  const private_ = record.exposure?.mode !== 'public';
  const admin = record.administrator?.verified ? 'administrator verified' : 'no administrator verified yet';
  return `deployed ${short(deployedSha)} (candidate ${candidate}, image ${String(record.runtime?.imageId ?? 'unrecorded').slice(0, 19)}, verified ${record.verifiedAt ? minute(record.verifiedAt) : 'unrecorded'}) `
    + `${private_ ? `privately on the target loopback only; public exposure NOT applied; ${admin}` : 'with public exposure checks passed (browser login works only on the public HTTPS hostname: the LAN http URL carries Secure cookies and serves probes only)'}; receipt only, run verify-live to re-check the live container`;
}
async function liveStatus(trust) {
  let state;
  try { state = await json(path.join(trust.policy.target.receiptsRoot, 'production-state.json')); }
  catch (error) {
    if (error.code === 'ENOENT') return { status: 'not_deployed', deployedSha: null, summary: none };
    return { status: 'unknown', deployedSha: null, summary: `production-state.json is unreadable or not valid (${typeof error.code === 'string' ? error.code : 'parse error'}); inspect the receipts directory` };
  }
  const record = state && typeof state === 'object' && !Array.isArray(state) ? state : {};
  const status = typeof record.status === 'string' ? record.status : 'unknown';
  // Only a verified receipt names a deployed SHA; any other status reports null even if the file carries one.
  const deployedSha = status === 'deployed' && SHA.test(record.deployedSha ?? '') ? record.deployedSha : null;
  const result = { status, evidence: 'receipt' };
  for (const key of ['candidateId', 'sourceSha', 'triggeringMerge', 'approvalSha256', 'verifiedAt', 'error']) if (typeof record[key] === 'string') result[key] = record[key];
  result.deployedSha = deployedSha;
  for (const key of ['runtime', 'image', 'exposure', 'ingress', 'administrator', 'health', 'timing']) if (record[key] && typeof record[key] === 'object') result[key] = record[key];
  result.summary = describe({ ...record, status }, deployedSha);
  return result;
}
async function withDispatchError(receipt, receiptsRoot) {
  const error = await json(path.join(receiptsRoot, receipt.candidateId, 'dispatch-error.json')).catch(() => null);
  if (!error || error.candidateId !== receipt.candidateId || error.sourceSha !== receipt.sourceSha || error.triggeringMerge !== receipt.triggeringMerge) return receipt;
  return { ...receipt, dispatchError: error };
}
/** What is deployed, from the durable receipts alone: read-only, needs no candidate, and never throws. */
export async function productionStatus(trust, unavailable = null) {
  if (!trust) return { status: 'not_deployed', deployedSha: null, summary: `${none} (${unavailable})` };
  const liveReceipt = await liveStatus(trust);
  const live = liveReceipt.candidateId ? await withDispatchError(liveReceipt, trust.policy.target.receiptsRoot) : liveReceipt;
  const job = await latestJob(trust.policy.target.receiptsRoot);
  if (job?.status !== 'failed' || job.candidateId === live.candidateId) return live;
  const latest = { status: 'failed', candidateId: job.candidateId, deployedSha: null };
  for (const key of ['sourceSha', 'triggeringMerge', 'error']) if (typeof job[key] === 'string') latest[key] = job[key];
  if (job.timing) latest.timing = job.timing;
  latest.summary = `not deployed: failed for candidate ${job.candidateId}${latest.error ? `: ${latest.error}` : ''}`;
  return { ...live, latestJob: latest, summary: `${live.summary}; the latest job failed for candidate ${job.candidateId}${latest.error ? `: ${latest.error}` : ''}` };
}
export async function status({ root, candidate, trust, now = Date.now(), verifier = verifyDetachedSignature }) {
  if (candidate === undefined) return productionStatus(trust);
  need(ID.test(candidate), 'invalid candidate id');
  const redact = makeRedactor(trust.policy);
  const receipt = await json(path.join(trust.policy.target.receiptsRoot, candidate, 'receipt.json')).catch(() => null);
  if (receipt) return withDispatchError({ ...receipt, ...(receipt.status === 'deployed' ? { summary: describe(receipt, receipt.deployedSha) } : {}) }, trust.policy.target.receiptsRoot);
  const dir = path.join(root, '.approval', candidate);
  const observed = await regular(path.join(dir, 'timing.json')).then((bytes) => JSON.parse(bytes)).catch(() => null);
  if (observed?.candidateId === candidate && observed?.timing?.failedAt) return { status: observed.failureStage === 'submission' ? 'submission_failed' : 'preparation_failed',
    candidateId: candidate, sourceSha: observed.sourceSha, triggeringMerge: observed.triggeringMerge, deployedSha: null, timing: observed.timing, reason: observed.error };
  if (observed?.candidateId === candidate && !observed.timing?.approvalCreatedAt) return { status: 'preparation_incomplete', candidateId: candidate,
    sourceSha: observed.sourceSha, triggeringMerge: observed.triggeringMerge, deployedSha: null, timing: observed.timing };
  const approval = await regular(path.join(dir, 'approval.json')).then((bytes) => JSON.parse(bytes)).catch(() => null);
  if (!approval) return { status: 'candidate_missing', candidateId: candidate, deployedSha: null };
  if (!(Date.parse(approval.expiresAt) > now)) return { status: 'expired', candidateId: candidate, sourceSha: approval.sourceSha, triggeringMerge: approval.triggeringMerge, deployedSha: null,
    expiresAt: approval.expiresAt, reason: 'approval expired unsigned or unsubmitted; prepare a fresh candidate' };
  let manifest;
  try { manifest = await verifyCandidate(dir, trust, { signed: false, now, artifacts: 'small' }); }
  catch (error) { return { status: 'candidate_invalid', candidateId: candidate, deployedSha: null, reason: redact(error.message) }; }
  const timing = await candidateTiming(dir, manifest);
  const metadata = { expiresAt: approval.expiresAt, imageId: manifest.image.imageId, exposure: manifest.target.exposure.mode, ...(Object.keys(timing).length ? { timing } : {}) };
  const base = { candidateId: candidate, sourceSha: manifest.sourceSha, triggeringMerge: manifest.triggeringMerge, deployedSha: null, receiptAbsent: true, ...metadata };
  if (!await lstat(path.join(dir, 'release.sig')).catch(() => null)) return { status: 'awaiting_signature', ...base };
  try { await verifyCandidate(dir, trust, { now, artifacts: 'small', verifier }); return { status: 'signed', ...base }; }
  catch (error) { return { status: 'awaiting_valid_signature', ...base, reason: redact(error.message) }; }
}
async function deployedRecord(trust, candidateId) {
  need(ID.test(candidateId ?? ''), 'invalid candidate id');
  const t = trust.policy.target;
  const state = await json(path.join(t.receiptsRoot, 'production-state.json')).catch(() => null);
  const receipt = await json(path.join(t.receiptsRoot, candidateId, 'receipt.json')).catch(() => null);
  for (const record of [state, receipt]) {
    need(record?.status === 'deployed' && record.candidateId === candidateId && SHA.test(record.deployedSha ?? '') && record.deployedSha === record.sourceSha,
      `candidate ${candidateId} is not the verified deployed release`);
  }
  need(receipt.policySha256 === trust.policySha256, 'the pinned policy changed since this candidate was deployed');
  need(IMAGE_ID.test(receipt.runtime?.imageId ?? '') && receipt.runtime.appVersion === receipt.sourceSha && SHA256.test(receipt.approvalSha256 ?? ''), 'receipt carries no verified runtime identity');
  return receipt;
}
/**
 * Everything the authenticated acceptance verifier may use, from the fixed policy and the durable
 * receipt only, in exactly the shape it validates. Refuses unless that candidate is the verified
 * deployed release AND its public exposure was applied and verified; a private deployment has no public
 * origin to accept, and says so with `code: 'private_deployment'`.
 */
export async function loadAcceptanceTarget({ candidateId }, deps = {}) {
  const trust = deps.trust ?? await loadPolicy();
  const receipt = await deployedRecord(trust, candidateId);
  const x = trust.policy.target.exposure;
  if (x.mode !== 'public' || receipt.exposure?.mode !== 'public' || receipt.exposure.publicExposure !== 'verified') {
    throw Object.assign(new Error(`candidate ${candidateId} was deployed privately: public exposure was not applied or verified, so there is no public origin to accept`), { code: 'private_deployment' });
  }
  const a = trust.policy.acceptance ?? {};
  return { candidateId, environment: 'production', state: 'deployed', sourceSha: receipt.sourceSha, imageDigest: receipt.runtime.imageId, appVersion: receipt.runtime.appVersion,
    approvalSha256: receipt.approvalSha256, deployedAt: receipt.verifiedAt, publicOrigin: new URL(x.publicUrl).origin,
    ...(a.cookieFile === undefined ? {} : { cookieFile: a.cookieFile }), publish: a.publish ?? null, timeoutMs: a.timeoutMs ?? 120_000 };
}
/**
 * Bind the public route to the inspected container before any credential is sent to it. Re-reads the pinned
 * tunnel ingress and DNS from Cloudflare (the ingress must still be exactly the signed planned configuration),
 * re-inspects the container (it must still be the deployed container and image ID), and proves the public hostname
 * reaches it with a fresh nonce. Throws on any failure: callers must not send credentials unless this returns.
 */
export async function proveRouteBinding({ candidateId }, deps = {}) {
  const trust = deps.trust ?? await loadPolicy();
  const receipt = await deployedRecord(trust, candidateId);
  const t = trust.policy.target;
  const x = t.exposure;
  if (x.mode !== 'public' || receipt.exposure?.publicExposure !== 'verified') throw Object.assign(new Error(`candidate ${candidateId} was deployed privately; there is no public route to bind`), { code: 'private_deployment' });
  need(SHA256.test(receipt.ingress?.plannedConfigSha256 ?? '') && SHA256.test(receipt.runtime.containerId ?? ''), 'receipt carries no signed ingress or container identity');
  const cf = openCloudflare(trust, deps.fetchImpl ?? fetch);
  await checkTunnelDns(cf, x.ingress);
  need(configDigest(await readTunnelConfig(cf, x.ingress)) === receipt.ingress.plannedConfigSha256, 'the live tunnel ingress is not the signed planned configuration');
  const remote = await openRemote(trust, deps.command ?? run);
  try {
    const live = await snapshotContainer(remote, t.container.name);
    need(live.present && live.containerId === receipt.runtime.containerId && live.imageId === receipt.runtime.imageId, 'the container that owns the production name is not the deployed container');
    await proveRouteToContainer({ remote, containerId: live.containerId, probe: deps.probe ?? defaultProbe, publicUrl: x.publicUrl });
    return { bound: true, candidateId, containerId: live.containerId, imageId: live.imageId, ingressConfigSha256: receipt.ingress.plannedConfigSha256 };
  } finally { await remote.close(); }
}
/**
 * Did the deployed container's backend receive a request carrying this marker? Reads the container's log
 * (stdout and stderr) since `sinceIso` over the pinned SSH target, searches for the fixed marker and returns
 * only `{ seen }`: log content is never returned or recorded. Used to bind a public route to the inspected
 * container before credentials are sent. Throws if the target is unreachable or is not the deployed container.
 */
export async function confirmBackendRequest({ marker, sinceIso }, deps = {}) {
  need(typeof marker === 'string' && /^acceptance_nonce=[0-9a-f]{32}$/.test(marker), 'marker must be acceptance_nonce=<32 hex>');
  need(typeof sinceIso === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/.test(sinceIso) && Number.isFinite(Date.parse(sinceIso)), 'sinceIso must be a UTC ISO timestamp');
  const trust = deps.trust ?? await loadPolicy();
  const t = trust.policy.target;
  const state = await json(path.join(t.receiptsRoot, 'production-state.json')).catch(() => null);
  need(state?.status === 'deployed' && SHA256.test(state.runtime?.containerId ?? ''), 'no verified deployed container is recorded');
  const remote = await openRemote(trust, deps.command ?? run);
  try {
    const live = await snapshotContainer(remote, t.container.name);
    need(live.present && live.containerId === state.runtime.containerId && live.imageId === state.runtime.imageId, 'the container that owns the production name is not the deployed container');
    const logs = await remote.docker(['logs', '--since', sinceIso, '--tail', '20000', live.containerId], { mergeStderr: true, maxOutput: 64 * 1024 * 1024, timeoutMs: 120_000 });
    return { seen: logs.includes(marker) };
  } finally { await remote.close(); }
}
/** The container that owns the production name on the pinned target right now. Throws when the host cannot be reached. */
export async function inspectRunningImage(deps = {}) {
  const trust = deps.trust ?? await loadPolicy();
  const name = trust.policy.target.container.name;
  const remote = await openRemote(trust, deps.command ?? run);
  try {
    const info = await containerInspect(remote, name);
    if (!info) return { running: false, imageId: null, repoDigests: [], containerId: null, containerName: name };
    const image = await imageInspect(remote, info.Image);
    return { running: info.State?.Running === true, imageId: info.Image, repoDigests: image?.RepoDigests ?? [], containerId: info.Id, containerName: name };
  } finally { await remote.close(); }
}

// ---------------------------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------------------------
async function main() {
  const [action, ...argv] = process.argv.slice(2);
  const allowed = new Set(['--candidate', '--source', '--triggering-merge', '--execute']);
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    need(allowed.has(argv[i]) && !(argv[i] in args), 'unknown or repeated option');
    args[argv[i]] = argv[i] === '--execute' ? true : argv[++i];
  }
  if (action === 'status' && args['--candidate'] === undefined) {
    let unavailable = null;
    return productionStatus(await loadPolicy().catch((error) => { unavailable = error.message; return null; }), unavailable);
  }
  const trust = await loadPolicy();
  const options = { root: process.cwd(), candidate: args['--candidate'], trust };
  if (action === 'prepare') {
    await mkdir(path.join(options.root, '.approval'), { recursive: true });
    return prepare({ ...options, sourceSha: args['--source'], triggeringMerge: args['--triggering-merge'] });
  }
  if (action === 'status') return status(options);
  if (action === 'submit') { need(args['--execute'] === true, 'submit requires --execute and a genuine operator signature'); return submit(options); }
  if (action === 'deploy-job') {
    const durable = path.join(trust.policy.target.receiptsRoot, options.candidate, 'release-controller.mjs');
    need(SELF === durable && await realpath(SELF) === SELF, 'deploy-job must run the durable managed copy');
    need(hash(await regular(SELF)) === (await json(path.join(path.dirname(SELF), 'manifest.json'))).artifacts['release-controller.mjs'], 'durable controller does not match the signed manifest');
    return deployJob(options);
  }
  if (action === 'verify-live') return verifyLive({ ...options, execute: args['--execute'] === true });
  throw new Error('usage: release-controller.mjs prepare|status|submit|verify-live [--candidate ID] [--source SHA --triggering-merge SHA] [--execute]');
}
if (process.argv[1] && path.resolve(process.argv[1]) === SELF) {
  main().then((result) => console.log(JSON.stringify(result, null, 2))).catch((error) => { console.error(error.message); process.exitCode = 1; });
}
