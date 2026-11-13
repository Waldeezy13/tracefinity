/**
 * Deterministic tests for scripts/release-controller.mjs. Run: node --test tests/release-controller.test.mjs
 *
 * No signing key exists anywhere in this file: Ed25519 verification is checked against the public
 * RFC 8032 section 7.1 vectors (public key, message, signature), and the dynamic candidate paths use an
 * injected verifier. Docker, SSH, Cloudflare and HTTP are in-memory fakes that obey the real command and
 * API shapes; git, tar and bash are real. Nothing touches the network, a service or a real key.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, writeFile, readFile, readdir, rm, lstat, realpath, symlink, chmod, utimes } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as rc from '../scripts/release-controller.mjs';

const CONTROLLER = fileURLToPath(new URL('../scripts/release-controller.mjs', import.meta.url));
const DOCKERFILE = fileURLToPath(new URL('../Dockerfile', import.meta.url));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const readJson = async (file) => JSON.parse(await readFile(file, 'utf8'));
const exists = (file) => lstat(file).then(() => true, () => false);

// ---------------------------------------------------------------------------------------------
// RFC 8032 section 7.1 public vectors. Public keys, messages and signatures only.
// ---------------------------------------------------------------------------------------------
const RFC = {
  one: { pub: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', msg: '',
    sig: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b' },
  two: { pub: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', msg: '72',
    sig: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00' },
};
const hex = (value) => Buffer.from(value, 'hex');
const ORDER = (1n << 252n) + 27742317777372353535851937790883648493n;
const verifyVector = (v, { message = hex(v.msg), signature = hex(v.sig), pub = v.pub } = {}) =>
  rc.verifyDetachedSignature(message, Buffer.from(signature).toString('base64'), hex(pub).toString('base64'));

test('RFC 8032 vectors verify, including the panel newline form', () => {
  for (const v of [RFC.one, RFC.two]) assert.equal(verifyVector(v), true);
  assert.equal(rc.verifyDetachedSignature(hex(RFC.two.msg), `${hex(RFC.two.sig).toString('base64')}\n`, hex(RFC.two.pub).toString('base64')), true);
});
test('signature negatives: altered signature or message, wrong key, malleated scalar, bad lengths and encodings', () => {
  const flip = (buffer, at) => { const copy = Buffer.from(buffer); copy[at] ^= 1; return copy; };
  const bad = /signature is not from the explicitly trusted operator|signature is not canonical|invalid detached signature|invalid trusted public key/;
  for (const at of [0, 31, 32, 63]) assert.throws(() => verifyVector(RFC.two, { signature: flip(hex(RFC.two.sig), at) }), bad);
  assert.throws(() => verifyVector(RFC.two, { message: hex('73') }), bad);
  assert.throws(() => verifyVector(RFC.two, { message: Buffer.alloc(0) }), bad);
  assert.throws(() => verifyVector(RFC.one, { pub: RFC.two.pub }), bad); // a genuine signature by another key
  assert.throws(() => verifyVector(RFC.two, { signature: hex(RFC.one.sig) }), bad);
  // S + L is the textbook malleated copy of a valid signature: a strict verifier rejects it.
  const signature = Buffer.from(hex(RFC.two.sig));
  let scalar = 0n;
  for (let i = 63; i >= 32; i--) scalar = (scalar << 8n) | BigInt(signature[i]);
  assert(scalar < ORDER);
  let widened = scalar + ORDER;
  for (let i = 32; i < 64; i++) { signature[i] = Number(widened & 0xffn); widened >>= 8n; }
  assert.throws(() => verifyVector(RFC.two, { signature }), /signature is not canonical/);
  assert.throws(() => verifyVector(RFC.two, { signature: hex(RFC.two.sig).subarray(0, 63) }), /invalid detached signature/);
  assert.throws(() => verifyVector(RFC.two, { signature: Buffer.concat([hex(RFC.two.sig), Buffer.alloc(1)]) }), /invalid detached signature/);
  const good = hex(RFC.two.sig).toString('base64');
  const key = hex(RFC.two.pub).toString('base64');
  for (const text of [good.replace(/=+$/, ''), `${good.slice(0, 10)} ${good.slice(10)}`, '', 'not base64!!', good.toLowerCase()]) {
    assert.throws(() => rc.verifyDetachedSignature(hex(RFC.two.msg), text, key), /invalid detached signature|signature is not/);
  }
  assert.throws(() => rc.verifyDetachedSignature(hex(RFC.two.msg), good, hex(RFC.two.pub).subarray(0, 31).toString('base64')), /invalid trusted public key/);
});

// ---------------------------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------------------------
const TOKEN = 'cf-fixture-token-0123456789abcdefghij';
const IDS = { account: 'a'.repeat(32), zone: 'b'.repeat(32), tunnel: '11111111-2222-3333-4444-555555555555' };
const OLD_IMAGE = `sha256:${'9'.repeat(64)}`;
const OLD_CONTAINER = 'c'.repeat(64);
function makePolicy(root, exposure = 'private') {
  const publicExposure = { mode: 'public', publishAddress: '192.0.2.10', lanUrl: 'http://192.0.2.10:3000/', publicUrl: 'https://app.example.test/', publicStatus: 200,
    ingress: { provider: 'cloudflare-tunnel', accountId: IDS.account, zoneId: IDS.zone, tunnelId: IDS.tunnel, hostname: 'app.example.test',
      service: 'http://192.0.2.10:3000', apiTokenFile: path.join(root, 'cf-token'), singleWriter: true } };
  return { schemaVersion: 1, kind: 'tracefinity.release-policy', publicKeyBase64: hex(RFC.one.pub).toString('base64'),
    source: { repository: 'example/tracefinity', branch: 'main' }, build: { platform: 'linux/amd64', imageRepository: 'tracefinity-release' },
    target: { kind: 'unraid-docker', nodePath: '/usr/bin/node', receiptsRoot: path.join(root, 'receipts'), dockerPath: '/usr/bin/docker',
      ssh: { host: 'unraid.test.invalid', port: 2222, user: 'root', identityFile: path.join(root, 'id_fixture'),
        hostKey: 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFixtureHostKeyFixtureHostKeyFixtureHostKey1234' },
      container: { name: 'tracefinity', hostPort: 3000, storagePath: '/mnt/user/appdata/tracefinity', puid: 99, pgid: 100, envFile: '/mnt/user/appdata/tracefinity-release/app.env',
        env: { RCLONE_EXPORT_REMOTE: 'drive:Tracefinity', RCLONE_CONFIG: '/config/rclone.conf' },
        mounts: [{ hostPath: '/mnt/user/appdata/tracefinity-rclone/rclone.conf', containerPath: '/config/rclone.conf' }] },
      exposure: exposure === 'public' ? publicExposure : { mode: 'private' } },
    acceptance: { cookieFile: path.join(root, 'cookie'), timeoutMs: 60_000,
      publish: { repository: 'example/tracefinity', stateBranch: 'production-state', tokenFile: path.join(root, 'publish-token'), verifier: 'fixture-verifier' } } };
}
const BASE = '/tmp/tf-policy-fixture';
test('policy shape: strict, every command-line string pattern-checked, secrets refused', () => {
  rc.validatePolicy(makePolicy(BASE));
  rc.validatePolicy(makePolicy(BASE, 'public'));
  const bad = (mutate, pattern, exposure = 'private') => {
    const policy = structuredClone(makePolicy(BASE, exposure));
    mutate(policy);
    assert.throws(() => rc.validatePolicy(policy), pattern);
  };
  bad((p) => { p.extra = 1; }, /unknown field extra/);
  bad((p) => { p.publicKeyBase64 = 'AAAA'; }, /public key/);
  bad((p) => { p.target.ssh.host = '-oProxyCommand=evil'; }, /invalid ssh target/);
  bad((p) => { p.target.ssh.user = 'root;id'; }, /invalid ssh target/);
  bad((p) => { p.target.ssh.hostKey = 'ssh-ed25519 AAAA comment'; }, /pinned public host key/);
  bad((p) => { p.target.container.name = 'a b'; }, /invalid container/);
  bad((p) => { p.target.container.storagePath = '/mnt/user/../etc'; }, /invalid container/);
  bad((p) => { p.target.container.puid = 0; }, /non-root/);
  bad((p) => { p.target.container.env.AUTH_SETUP_ENABLED = 'true'; }, /controller-managed/);
  bad((p) => { p.target.container.env.AUTH_MODE = 'open'; }, /controller-managed/);
  bad((p) => { p.target.container.env.GOOGLE_API_KEY = 'abc'; }, /looks secret/);
  bad((p) => { p.target.container.mounts[0].hostPath = '/var/run/docker.sock'; }, /not allowed/);
  bad((p) => { p.target.container.mounts[0].containerPath = '/etc/passwd'; }, /under \/config or \/secrets/);
  bad((p) => { delete p.target.exposure; }, /exposure is required/);
  bad((p) => { p.target.exposure.extra = 1; }, /unknown field extra/);
  bad((p) => { delete p.target.exposure.ingress; }, /ingress/, 'public');
  bad((p) => { p.target.exposure.publishAddress = '127.0.0.1'; }, /non-loopback/, 'public');
  bad((p) => { p.target.exposure.ingress.hostname = 'other.example.test'; }, /hostname of exposure.publicUrl/, 'public');
  bad((p) => { p.target.exposure.ingress.service = 'http://192.0.2.10:3999'; }, /container host port/, 'public');
  bad((p) => { p.target.exposure.sensitiveStatuses = [200]; }, /non-success/, 'public');
  bad((p) => { p.acceptance.publish.stateBranch = 'main'; }, /production-state/);
  bad((p) => { p.acceptance.timeoutMs = 600_000; }, /timeoutMs/);
});
test('policy digest covers the deployment, not the acceptance block', () => {
  const a = makePolicy(BASE);
  const b = structuredClone(a);
  b.acceptance.timeoutMs = 90_000;
  assert.equal(rc.policyDigest(a), rc.policyDigest(b));
  b.target.container.hostPort = 3001;
  assert.notEqual(rc.policyDigest(a), rc.policyDigest(b));
});
test('policy file: owner-only, no symlink, outside any environment override', async (t) => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'tfpol-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'policy.json');
  await writeFile(file, JSON.stringify(makePolicy(root)), { mode: 0o600 });
  const loaded = await rc.loadPolicy(file);
  assert.equal(loaded.policySha256, rc.policyDigest(makePolicy(root)));
  await chmod(file, 0o644);
  await assert.rejects(rc.loadPolicy(file), /mode 0600|unsafe/);
  await chmod(file, 0o600);
  await symlink(file, path.join(root, 'link.json'));
  await assert.rejects(rc.loadPolicy(path.join(root, 'link.json')), /unsafe|symlink|not a regular file/);
  await assert.rejects(rc.loadPolicy(path.join(root, 'missing.json')), /missing or unsafe/);
  const previousHome = process.env.HOME;
  process.env.HOME = root;
  t.after(() => { if (previousHome === undefined) delete process.env.HOME; else process.env.HOME = previousHome; });
  assert.equal(rc.policyPath(), path.join(os.userInfo().homedir, '.config/station-zero/tracefinity-release-policy.json'));
  assert.notEqual(rc.policyPath(), path.join(root, '.config/station-zero/tracefinity-release-policy.json'));
});
test('CLI: no option or environment can substitute the policy or target', async (t) => {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'tfcli-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const policy = makePolicy(root);
  await mkdir(path.join(root, '.config/station-zero'), { recursive: true });
  await writeFile(path.join(root, '.config/station-zero/tracefinity-release-policy.json'), JSON.stringify(policy), { mode: 0o600 });
  await mkdir(policy.target.receiptsRoot, { recursive: true });
  await writeFile(path.join(policy.target.receiptsRoot, 'production-state.json'),
    JSON.stringify({ status: 'deployed', candidateId: 'leak-canary', sourceSha: 'a'.repeat(40), deployedSha: 'a'.repeat(40) }));
  const env = { PATH: process.env.PATH, HOME: root, TRACEFINITY_POLICY: path.join(root, '.config/station-zero/tracefinity-release-policy.json') };
  const out = await rc.run(process.execPath, [CONTROLLER, 'status'], root, { env });
  assert(!out.includes('leak-canary'));
  assert.equal(typeof JSON.parse(out).status, 'string');
  await assert.rejects(rc.run(process.execPath, [CONTROLLER, 'status', '--policy', 'x'], root, { env }), /unknown or repeated option/);
  await assert.rejects(rc.run(process.execPath, [CONTROLLER, 'submit', '--candidate', 'x'], root, { env }), /--execute|public trust|unsafe/);
});
test('redaction hides the private target from anything printed', () => {
  const redact = rc.makeRedactor(makePolicy(BASE, 'public'));
  const text = redact('ssh root@unraid.test.invalid:2222 failed; /mnt/user/appdata/tracefinity; https://app.example.test/; tunnel 11111111-2222-3333-4444-555555555555');
  for (const secret of ['unraid.test.invalid', '/mnt/user/appdata/tracefinity', 'app.example.test', IDS.tunnel]) assert(!text.includes(secret), secret);
});
test('canonical JSON ignores key order; ingress normalisation ignores provider defaults', () => {
  assert.equal(rc.canonical({ b: 1, a: [{ d: 1, c: 2 }] }), rc.canonical({ a: [{ c: 2, d: 1 }], b: 1 }));
  assert.equal(rc.configDigest({ ingress: [{ hostname: 'a', service: 's', originRequest: {} }] }), rc.configDigest({ ingress: [{ hostname: 'a', service: 's' }] }));
  assert.notEqual(rc.configDigest({ ingress: [{ hostname: 'a', service: 's' }] }), rc.configDigest({ ingress: [{ hostname: 'a', service: 't' }] }));
});
test('streamed input must hash to the signed artifact', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'tfstream-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const file = path.join(root, 'blob');
  await writeFile(file, 'artifact bytes');
  assert.equal(await rc.run('cat', [], undefined, { stdinFile: file, stdinSha256: sha256('artifact bytes') }), 'artifact bytes');
  await assert.rejects(rc.run('cat', [], undefined, { stdinFile: file, stdinSha256: sha256('different') }), /does not match the signed artifact digest/);
});
test('remote command quoting cannot be broken out of', () => {
  const hostile = "a'; rm -rf /; echo '";
  const quoted = [rc.shellQuote('/usr/bin/docker'), rc.shellQuote(hostile), rc.shellQuote('x y')].join(' ');
  assert.deepEqual(shellSplit(quoted), ['/usr/bin/docker', hostile, 'x y']);
});

// ---------------------------------------------------------------------------------------------
// Nginx routing: health must use paths nginx really sends to the backend
// ---------------------------------------------------------------------------------------------
test('every path the controller requests through nginx is routed by the real Dockerfile config; /health is not a backend path', async () => {
  const dockerfile = await readFile(DOCKERFILE, 'utf8');
  const config = /server \{([\s\S]*?)\nNGINX_EOF/.exec(dockerfile)[1];
  const locations = [...config.matchAll(/location\s+(\S+)\s*\{([^}]*)\}/g)].map(([, prefix, body]) => ({ prefix, upstream: /proxy_pass\s+([^;]+);/.exec(body)[1] }));
  const route = (requestPath) => locations.filter((l) => requestPath.startsWith(l.prefix)).sort((a, b) => b.prefix.length - a.prefix.length)[0].upstream;
  const BACKEND = 'http://127.0.0.1:8000';
  const FRONTEND = 'http://127.0.0.1:3001';
  for (const p of [rc.NGINX_PROBE_PATHS.authStatus, rc.NGINX_PROBE_PATHS.sensitive, rc.NGINX_PROBE_PATHS.version]) assert.equal(route(p), BACKEND, p);
  assert.equal(route(rc.NGINX_PROBE_PATHS.frontend), FRONTEND);
  assert.equal(route('/health'), FRONTEND, '/health through nginx reaches Next.js, never the backend');
  assert.match(dockerfile, new RegExp(`uvicorn app.main:app --host 127.0.0.1 --port ${rc.BACKEND_DIRECT_PROBE.port}`));
  assert.equal(rc.BACKEND_DIRECT_PROBE.path, '/health');
});

// ---------------------------------------------------------------------------------------------
// In-memory world: real git/tar/bash, fake docker/ssh/Cloudflare/HTTP
// ---------------------------------------------------------------------------------------------
function shellSplit(text) {
  const out = [];
  let current = '';
  let inQuote = false;
  let started = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuote) { if (ch === "'") inQuote = false; else current += ch; }
    else if (ch === "'") { inQuote = true; started = true; }
    else if (ch === '\\') { current += text[++i]; started = true; }
    else if (/\s/.test(ch)) { if (started) { out.push(current); current = ''; started = false; } }
    else { current += ch; started = true; }
  }
  if (started) out.push(current);
  return out;
}
const failure = (code, stderr) => Object.assign(new Error(`docker exited ${code}: ${stderr}`), { code, stderr });
const envOf = (c) => Object.fromEntries(c.Config.Env.map((entry) => [entry.slice(0, entry.indexOf('=')), entry.slice(entry.indexOf('=') + 1)]));
const VALUE_FLAGS = new Set(['--name', '--pull', '--restart', '--publish', '--security-opt', '--mount', '--env-file', '--env', '--label', '--memory', '--memory-swap', '--cpus', '--network', '--tmpfs', '--entrypoint',
  '--user', '--cap-drop', '--pids-limit', '--ipc', '--workdir']);
function parseRun(args) {
  const p = { env: [], labels: {}, mounts: [], security: [], flags: {}, image: null };
  for (let i = 1; i < args.length; i++) {
    const a = args[i];
    if (VALUE_FLAGS.has(a)) {
      const value = args[++i];
      if (a === '--env') p.env.push(value);
      else if (a === '--label') p.labels[value.slice(0, value.indexOf('='))] = value.slice(value.indexOf('=') + 1);
      else if (a === '--mount') p.mounts.push(value);
      else if (a === '--security-opt') p.security.push(value);
      else p.flags[a] = value;
    } else if (a.startsWith('-')) p.flags[a] = true;
    else { p.image = a; p.rest = args.slice(i + 1); break; }
  }
  return p;
}
class FakeDocker {
  constructor(ctx, side) {
    Object.assign(this, { ctx, side, containers: new Map(), images: new Map(), tags: new Map(), flags: {}, seq: 0, probes: 0, nginxLog: [], logText: '',
      admins: { accounts: 0, enabledAdmins: 0 }, envFile: ['GOOGLE_API_KEY=fixture-value'], loadable: null });
  }
  id() { return sha256(`${this.side}:${++this.seq}`); }
  find(ref) { return [...this.containers.values()].find((c) => c.Id === ref || c.Name === `/${ref}`) ?? null; }
  image(ref) { return this.images.get(ref) ?? this.images.get(this.tags.get(ref)) ?? null; }
  event(op, extra = {}) { this.ctx.events.push({ side: this.side, op, ...extra }); }
  seedPrevious() {
    this.containers.set(OLD_CONTAINER, { Id: OLD_CONTAINER, Name: '/tracefinity', Image: OLD_IMAGE, RestartCount: 0,
      State: { Running: true, Status: 'running', Restarting: false, Dead: false, OOMKilled: false, StartedAt: '2026-01-01T00:00:00Z' },
      Config: { Env: ['PATH=/usr/bin'], Labels: {} }, HostConfig: { RestartPolicy: { Name: 'always' } }, Mounts: [] });
  }
  makeContainer(p, name) {
    const img = this.image(p.image);
    if (!img) throw failure(1, `Unable to find image '${p.image}' locally`);
    if (this.find(name)) throw failure(1, `Conflict. The container name "/${name}" is already in use`);
    const env = [...img.Config.Env];
    const withFile = p.flags['--env-file'] !== undefined;
    if (withFile && !this.flags.envFileWins) env.push(...this.envFile);
    env.push(...p.env);
    if (withFile && this.flags.envFileWins) env.push('AUTH_SETUP_ENABLED=true');
    const bindings = {};
    if (p.flags['--publish']) { const [address, host, container] = p.flags['--publish'].split(':'); bindings[container] = [{ HostIp: address, HostPort: host }]; }
    return { Id: this.id(), Name: `/${name}`, Image: img.Id, RestartCount: 0, canary: name.startsWith('tracefinity-canary'),
      State: { Running: false, Status: 'created', Restarting: false, Dead: false, OOMKilled: false, StartedAt: '0001-01-01T00:00:00Z' },
      Config: { Env: env, Labels: { ...img.Config.Labels, ...p.labels } },
      HostConfig: { PortBindings: bindings, Privileged: false, PublishAllPorts: false, CapAdd: null, Devices: null, PidMode: '', NetworkMode: 'bridge',
        RestartPolicy: { Name: p.flags['--restart'] ?? 'no' }, SecurityOpt: p.security },
      Mounts: p.mounts.map((m) => { const kv = Object.fromEntries(m.split(',').map((x) => x.split('='))); return { Type: kv.type, Source: kv.source, Destination: kv.target, RW: !('readonly' in kv) }; }) };
  }
  probeFor(c) {
    const env = envOf(c);
    return { backendDirect: 200, frontend: 200, authStatus: 200, auth: { mode: env.AUTH_MODE ?? 'native', setup_required: env.AUTH_SETUP_ENABLED !== 'false', authenticated: false },
      sensitive: 401, versionStatus: 200, version: { version: env.APP_VERSION }, ...(this.flags.probe ?? {}) };
  }
  async docker(args, options = {}) {
    this.ctx.docker.push({ side: this.side, args, options });
    if (this.flags.unreachable) throw Object.assign(new Error('ssh exited 255: ssh: connect to host unraid.test.invalid port 2222: Connection refused'), { code: 255, stderr: 'ssh: connect to host unraid.test.invalid port 2222: Connection refused' });
    const [cmd, sub] = args;
    if (cmd === 'version') return '27.5.1';
    if (cmd === 'info') return JSON.stringify(this.flags.containerdStore ? [['driver-type', 'io.containerd.snapshotter.v1']] : [['Backing Filesystem', 'extfs']]);
    if (cmd === 'container' && sub === 'inspect') {
      const c = this.find(args.at(-1));
      if (!c) throw failure(1, `Error: No such container: ${args.at(-1)}`);
      return JSON.stringify(c);
    }
    if (cmd === 'image' && sub === 'inspect') {
      const img = this.image(args.at(-1));
      if (!img) throw failure(1, `Error: No such image: ${args.at(-1)}`);
      return args.includes('{{.Id}}') ? img.Id : JSON.stringify(img);
    }
    if (cmd === 'build') return this.build(args, options);
    if (cmd === 'save') return this.save(args);
    if (cmd === 'load') {
      this.event('load');
      const actual = sha256(await readFile(options.stdinFile));
      if (options.stdinSha256 !== undefined && actual !== options.stdinSha256) throw new Error('streamed input does not match the signed artifact digest');
      const source = this.flags.loadAs ?? this.loadable;
      this.images.set(source.imageId, { Id: source.imageId, RootFS: { Type: 'layers', Layers: source.diffIds }, Os: 'linux', Architecture: 'amd64', RepoDigests: [],
        Config: { Env: [`APP_VERSION=${source.appVersion}`], Labels: {} } });
      return `Loaded image ID: ${source.imageId}`;
    }
    if (cmd === 'create') {
      const p = parseRun(args);
      const c = this.makeContainer({ ...p, image: args.at(-1) }, p.flags['--name']);
      this.event('create', { args });
      this.containers.set(c.Id, c);
      return c.Id;
    }
    if (cmd === 'run') {
      const p = parseRun(args);
      if (p.labels['io.tracefinity.release.gate']) { this.event('run', { kind: 'gate', args }); return this.gate(p, args); }
      if (p.flags['--rm']) {
        const seed = p.flags['--entrypoint'] === 'sh';
        this.event('run', { kind: seed ? 'seed' : 'admin', args });
        if (seed) return '';
        if (this.flags.storageCorrupt) throw failure(1, 'json.decoder.JSONDecodeError');
        return JSON.stringify(this.admins);
      }
      this.event('run', { kind: 'canary', args });
      const c = this.makeContainer(p, p.flags['--name']);
      Object.assign(c.State, { Running: true, Status: 'running' });
      this.containers.set(c.Id, c);
      return c.Id;
    }
    if (cmd === 'start') {
      await this.ctx.hooks.start?.();
      this.event('start');
      const c = this.find(args.at(-1));
      Object.assign(c.State, { Running: true, Status: 'running', StartedAt: new Date().toISOString() });
      if (this.flags.wrongImageOnStart) c.Image = `sha256:${'e'.repeat(64)}`;
      return c.Id;
    }
    if (cmd === 'stop') { await this.ctx.hooks.stop?.(); this.event('stop'); Object.assign(this.find(args.at(-1)).State, { Running: false, Status: 'exited' }); return ''; }
    if (cmd === 'update') { this.event('update'); this.find(args.at(-1)).HostConfig.RestartPolicy = { Name: args[args.indexOf('--restart') + 1] }; return ''; }
    if (cmd === 'rename') {
      this.event('rename', { to: args[2] });
      if (this.find(args[2])) throw failure(1, `Error response from daemon: Conflict. The name "/${args[2]}" is already in use`);
      this.find(args[1]).Name = `/${args[2]}`;
      return '';
    }
    if (cmd === 'rm') { this.event('rm'); const c = this.find(args.at(-1)); if (c) this.containers.delete(c.Id); return ''; }
    if (cmd === 'logs') return this.logText;
    if (cmd === 'exec') {
      const ref = args.includes('-i') ? args[2] : args[1];
      const c = this.find(ref);
      if (!c || !c.State.Running) throw failure(1, `Error: No such container: ${ref}`);
      if (args.includes('printenv')) return envOf(c)[args.at(-1)] ?? '';
      if (args.includes('grep')) {
        const hits = this.nginxLog.filter((line) => line.includes(args[args.indexOf('-c') + 1])).length;
        if (!hits) throw failure(1, '');
        return String(hits);
      }
      if (options.input?.includes('tf_route_probe')) {
        this.nginxLog.push(`GET /api/auth/status?tf_route_probe=${/tf_route_probe=([0-9a-f]{32})/.exec(options.input)[1]}`);
        return '';
      }
      if (options.input.includes('users.json')) {
        if (this.flags.storageCorrupt) throw failure(1, 'json.decoder.JSONDecodeError');
        return JSON.stringify(this.admins);
      }
      if (!c.canary && this.probes++ < (this.flags.notReadyFor ?? 0)) return JSON.stringify({ backendDirect: 0, frontend: 0, authStatus: 0, auth: null, sensitive: 0, versionStatus: 0, version: null });
      return JSON.stringify(this.probeFor(c));
    }
    if (cmd === 'volume') { if (sub === 'create') { this.event('volume'); return args[2]; } this.event('rm'); return ''; }
    if (cmd === 'buildx') { if (this.flags.buildxMissing) throw failure(1, 'docker: unknown command: docker buildx'); return 'github.com/docker/buildx v0.20.0'; }
    throw new Error(`fake docker does not implement: ${args.join(' ')}`);
  }
  gate(p, args) {
    const argv = p.rest;
    const mount = (target) => p.mounts.map((m) => Object.fromEntries(m.split(',').map((x) => x.split('=')))).find((m) => m.target === target);
    this.ctx.provisioning.push({ argv, args, network: p.flags['--network'] });
    if (argv[0] === 'bash' && argv[1] === '/gate/check') return rc.run('bash', [mount('/gate/check').source], mount('/work').source, { env: { PATH: '/usr/local/bin:/usr/bin:/bin' }, mergeStderr: true });
    if (this.ctx.flags.failProvision?.(argv)) throw failure(1, 'simulated');
    if (argv.includes('freeze')) return 'pytest==9.0.0\nruff==0.9.0';
    if (argv.includes('-c') && argv.some((a) => a.includes('U2netpSession'))) return `Downloading data from 'https://example.invalid/u2netp.onnx'\n${sha256('u2netp')}`;
    return argv.includes('--version') ? 'fixture 1.0' : '';
  }
  build(args, options = {}) {
    if (args.at(-1) === '-') { // the sandbox toolchain image, built from a Dockerfile on stdin
      const id = `sha256:${sha256(options.input)}`;
      this.images.set(id, { Id: id, Config: { Env: [], Labels: {} }, RootFS: { Layers: [] }, Os: 'linux', Architecture: 'amd64', RepoDigests: [] });
      this.tags.set(args[args.indexOf('--tag') + 1], id);
      return '';
    }
    const labels = {};
    let version;
    let tag;
    for (let i = 1; i < args.length; i++) {
      if (args[i] === '--label') { const value = args[++i]; labels[value.slice(0, value.indexOf('='))] = value.slice(value.indexOf('=') + 1); }
      else if (args[i] === '--build-arg') version = args[++i].replace('APP_VERSION=', '');
      else if (args[i] === '--tag') tag = args[++i];
      else if (args[i] === '--platform') i += 1;
    }
    const config = { architecture: 'amd64', os: 'linux', config: { Env: [`APP_VERSION=${version}`, 'PATH=/usr/bin'], Labels: labels },
      rootfs: { type: 'layers', diff_ids: [`sha256:${sha256(`layer-1:${version}`)}`, `sha256:${sha256('layer-2')}`] } };
    const bytes = Buffer.from(JSON.stringify(config));
    const id = `sha256:${sha256(bytes)}`;
    this.images.set(id, { Id: id, Config: config.config, RootFS: { Type: 'layers', Layers: config.rootfs.diff_ids }, Os: 'linux', Architecture: 'amd64', RepoDigests: [], bytes });
    this.tags.set(tag, id);
    this.buildContext = args.at(-1);
    return '';
  }
  async save(args) {
    const out = args[args.indexOf('--output') + 1];
    const tag = args.at(-1);
    const img = this.image(tag);
    const work = await mkdtemp(path.join(os.tmpdir(), 'tfsave-'));
    const digest = img.Id.slice(7);
    await mkdir(path.join(work, 'blobs/sha256'), { recursive: true });
    await writeFile(path.join(work, 'blobs/sha256', digest), img.bytes);
    await writeFile(path.join(work, 'manifest.json'), JSON.stringify([{ Config: `blobs/sha256/${digest}`, RepoTags: [tag], Layers: [] }]));
    await rc.run('tar', ['-cf', out, '-C', work, 'manifest.json', 'blobs']);
    await rm(work, { recursive: true, force: true });
    this.savedAt = Date.now();
    return '';
  }
}
const GIT_ENV = { PATH: '/usr/local/bin:/usr/bin:/bin', HOME: os.tmpdir(), GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1',
  GIT_AUTHOR_NAME: 'Fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid', GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z',
  GIT_COMMITTER_NAME: 'Fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid', GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z' };
/**
 * Fixture history built only with plumbing (hash-object, update-index, write-tree, commit-tree, update-ref): a base commit, a side
 * commit and a genuine two-parent merge, with HEAD detached at the merge. No branch is created, switched or merged and no worktree exists.
 * Dates and identities are fixed, so every repo built from the same files has the same commit ids.
 */
async function makeRepo(repo, gate) {
  await mkdir(repo, { recursive: true });
  const git = (args, options = {}) => rc.run('git', args, repo, { env: GIT_ENV, ...options });
  await git(['init', '--quiet']);
  const files = { 'README.md': 'base\n', 'backend/requirements.txt': 'fastapi\n', 'frontend/pnpm-lock.yaml': 'lockfileVersion: 9\n',
    'scripts/release-controller.mjs': await readFile(CONTROLLER, 'utf8') };
  if (gate !== null) files['.ade/check'] = gate;
  const tree = async (overrides = {}) => {
    const index = path.join(repo, '.git', 'tf-index');
    await rm(index, { force: true });
    const env = { ...GIT_ENV, GIT_INDEX_FILE: index };
    for (const [name, content] of Object.entries({ ...files, ...overrides })) {
      const blob = await git(['hash-object', '-w', '--stdin'], { input: content });
      await git(['update-index', '--add', '--cacheinfo', `${name === '.ade/check' ? '100755' : '100644'},${blob},${name}`], { env });
    }
    return git(['write-tree'], { env });
  };
  const baseTree = await tree();
  const sideTree = await tree({ 'README.md': 'side\n' });
  const baseSha = await git(['commit-tree', baseTree, '-m', 'base']);
  const sideSha = await git(['commit-tree', sideTree, '-p', baseSha, '-m', 'side']);
  const mergeSha = await git(['commit-tree', sideTree, '-p', baseSha, '-p', sideSha, '-m', 'merge']);
  await git(['update-ref', '--no-deref', 'HEAD', mergeSha]);
  return { baseSha, sideSha, mergeSha, tree, git };
}
const stubSignature = (bytes) => createHash('sha512').update('tracefinity-test-signature\0').update(bytes).digest('base64');
const GATE = '#!/bin/sh\nset -eu\ntest -f backend/requirements.txt\necho gate-ok\n';
async function world(t, { exposure = 'private', gate = GATE, previous = false, admins = false, poison = false } = {}) {
  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), 'tfrc-')));
  t.after(() => rm(root, { recursive: true, force: true }));
  const repo = path.join(root, 'repo');
  const remoteRepo = path.join(root, 'remote');
  const { baseSha, mergeSha } = await makeRepo(remoteRepo, gate); // the stand-in for GitHub
  const checkout = await makeRepo(repo, gate); // the Task checkout; same objects, same ids
  assert.equal(checkout.mergeSha, mergeSha);
  if (poison) {
    // A hostile checkout: a replacement ref swaps the merge commit for one carrying different source, and its config rewrites the remote.
    const evilTree = await checkout.tree({ 'backend/requirements.txt': 'evil-package\n' });
    const evil = await checkout.git(['commit-tree', evilTree, '-p', baseSha, '-m', 'evil']);
    await checkout.git(['replace', '--force', mergeSha, evil]);
    await checkout.git(['config', 'url.file:///nonexistent/.insteadOf', 'https://github.com/']);
  }
  const policy = makePolicy(root, exposure);
  rc.validatePolicy(policy);
  await mkdir(policy.target.receiptsRoot, { recursive: true, mode: 0o700 });
  await writeFile(path.join(root, 'cf-token'), TOKEN, { mode: 0o600 });
  const ctx = { root, repo, remoteRepo, baseSha, mergeSha, sourceSha: mergeSha, policy, trust: { policy, policySha256: rc.policyDigest(policy) }, calls: [], docker: [], events: [], ssh: [],
    systemd: [], provisioning: [], probed: [], missing: new Set(), sleeps: 0, flags: {}, hooks: {}, clock: () => Date.now() };
  ctx.host = new FakeDocker(ctx, 'remote');
  ctx.local = new FakeDocker(ctx, 'local');
  if (previous) ctx.host.seedPrevious();
  if (admins) ctx.host.admins = { accounts: 1, enabledAdmins: 1 };
  const g = policy.target.exposure.ingress;
  ctx.cf = { calls: [], source: 'cloudflare', version: 1, addDefaults: true, putFails: false, bump: [],
    config: { ingress: [{ hostname: 'other.example.test', service: 'http://192.0.2.20:8080' }, { service: 'http_status:404' }], 'warp-routing': { enabled: false } },
    dns: g ? [{ type: 'CNAME', name: g.hostname, content: `${g.tunnelId}.cfargotunnel.com`, proxied: true }] : [],
    async fetch(url, init = {}) {
      const u = new URL(url);
      const method = init.method ?? 'GET';
      ctx.cf.calls.push({ method, path: u.pathname });
      const reply = (status, payload) => ({ ok: status < 400, status, json: async () => payload });
      if (init.headers?.authorization !== `Bearer ${TOKEN}`) return reply(403, { success: false, errors: [{ code: 10000, message: 'Authentication error' }] });
      const configPath = `/client/v4/accounts/${g.accountId}/cfd_tunnel/${g.tunnelId}/configurations`;
      if (u.pathname === configPath && method === 'GET') return reply(200, { success: true, result: { tunnel_id: g.tunnelId, version: ctx.cf.version, source: ctx.cf.source, config: structuredClone(ctx.cf.config) } });
      if (u.pathname === configPath && method === 'PUT') {
        if (ctx.cf.putFails) return reply(500, { success: false, errors: [{ code: 1000 }] });
        ctx.events.push({ side: 'cf', op: 'cf:PUT' });
        ctx.cf.config = structuredClone(JSON.parse(init.body).config);
        if (ctx.cf.addDefaults) ctx.cf.config.ingress = ctx.cf.config.ingress.map((rule) => ({ originRequest: {}, ...rule }));
        ctx.cf.version += ctx.cf.bump.shift() ?? 1;
        return reply(200, { success: true, result: {} });
      }
      if (u.pathname === `/client/v4/zones/${g.zoneId}/dns_records`) return reply(200, { success: true, result: ctx.cf.dns.filter((r) => r.name === u.searchParams.get('name')) });
      return reply(404, { success: false, errors: [{ code: 7003 }] });
    } };
  ctx.probe = async (url) => {
    ctx.probed.push(url);
    const u = new URL(url);
    if (u.host === '192.0.2.10:3000') {
      if (u.pathname === '/api/auth/status') return { status: 200, body: JSON.stringify({ mode: 'native', setup_required: false, authenticated: false }) };
      if (u.pathname === '/api/api-keys') return { status: ctx.flags.lanSensitive ?? 401, body: '' };
    }
    if (u.host === 'app.example.test') {
      if (!ctx.cf.config.ingress.some((rule) => rule.hostname === 'app.example.test')) return { status: 404, body: '' };
      if (u.pathname === '/') return { status: 200, body: '' };
      if (u.pathname === '/api/api-keys') return { status: ctx.flags.publicSensitive ?? 401, body: '' };
      if (u.pathname === '/api/auth/status') {
        if (!ctx.flags.misroute) ctx.host.nginxLog.push(`GET ${u.pathname}${u.search}`);
        return { status: 200, body: JSON.stringify({ mode: 'native', setup_required: false, authenticated: false }) };
      }
    }
    throw new Error(`unreachable ${url}`);
  };
  ctx.sleep = async () => { ctx.sleeps += 1; };
  ctx.verifier = (bytes, signature, publicKey) => {
    ctx.events.push({ side: 'verify', op: 'verify' });
    assert.equal(publicKey, policy.publicKeyBase64, 'the verifier must receive the pinned public key');
    if (String(signature).trim() !== stubSignature(bytes)) throw new Error('signature is not from the explicitly trusted operator');
    return true;
  };
  ctx.command = async (file, args, cwd, options = {}) => {
    const name = path.basename(file);
    ctx.calls.push({ file, args, cwd, options });
    if (ctx.missing.has(name)) throw Object.assign(new Error(`spawn ${name} ENOENT`), { code: 'ENOENT' });
    if (args.includes('--version') || (file === 'ssh' && args[0] === '-V')) return `${name} fixture 1.0`;
    if (file === 'ssh') {
      ctx.ssh.push(args);
      const remote = shellSplit(args.at(-1));
      assert.equal(remote[0], policy.target.dockerPath);
      return ctx.host.docker(remote.slice(1), options);
    }
    if (file === 'docker') return ctx.local.docker(args, options);
    if (file === 'systemd-run') { ctx.systemd.push(args); if (ctx.flags.systemdFails) throw new Error('systemd-run failed'); return ''; }
    if (file === 'git' && args.includes('ls-remote')) return `${ctx.flags.remoteMain ?? mergeSha}\trefs/heads/main`;
    if (file === 'git' && args.includes('fetch')) {
      const rewritten = [...args];
      rewritten[rewritten.indexOf('fetch') + 2] = remoteRepo; // the pinned GitHub URL is served by the fixture remote
      return rc.run('git', ['-c', 'protocol.file.allow=always', ...rewritten], cwd, options);
    }
    return rc.run(file, args, cwd, options);
  };
  ctx.dir = (candidate) => path.join(repo, '.approval', candidate);
  ctx.job = (candidate) => path.join(policy.target.receiptsRoot, candidate);
  ctx.prepare = (candidate, overrides = {}) => rc.prepare({ root: repo, candidate, sourceSha: mergeSha, triggeringMerge: mergeSha, trust: ctx.trust, command: ctx.command,
    sleep: ctx.sleep, fetchImpl: (url, init) => ctx.cf.fetch(url, init), ...overrides });
  ctx.sign = async (candidate) => writeFile(path.join(ctx.dir(candidate), 'release.sig'), `${stubSignature(await readFile(path.join(ctx.dir(candidate), 'approval.json')))}\n`, { mode: 0o644 });
  ctx.manifest = (candidate) => readJson(path.join(ctx.dir(candidate), 'manifest.json'));
  ctx.submit = (candidate, overrides = {}) => rc.submit({ root: repo, candidate, trust: ctx.trust, command: ctx.command, now: () => ctx.clock(), verifier: ctx.verifier, ...overrides });
  ctx.deploy = (candidate, overrides = {}) => rc.deployJob({ candidate, trust: ctx.trust, command: ctx.command, probe: ctx.probe, fetchImpl: (url, init) => ctx.cf.fetch(url, init),
    sleep: ctx.sleep, now: () => ctx.clock(), verifier: ctx.verifier, ...overrides });
  ctx.ship = async (candidate) => {
    await ctx.prepare(candidate);
    await ctx.sign(candidate);
    await ctx.submit(candidate);
    ctx.host.loadable = (await ctx.manifest(candidate)).image;
  };
  ctx.receipt = (candidate) => readJson(path.join(ctx.job(candidate), 'receipt.json'));
  ctx.remoteOps = () => ctx.events.filter((e) => e.side === 'remote').map((e) => e.op);
  return ctx;
}
const hasSequence = (args, ...tokens) => args.some((_, i) => tokens.every((token, j) => args[i + j] === token));
function assertVerifiedBeforeMutations(all) {
  const events = all.filter((e) => e.side !== 'local');
  const mutating = new Set(['load', 'run', 'create', 'volume', 'stop', 'update', 'rename', 'start', 'cf:PUT']);
  events.forEach((e, i) => {
    if (mutating.has(e.op)) assert.equal(events[i - 1]?.op, 'verify', `${e.op} at event ${i} was not immediately preceded by a signature and expiry verification`);
  });
}

// ---------------------------------------------------------------------------------------------
// Prepare
// ---------------------------------------------------------------------------------------------
test('prepare: exact source, isolated dependencies before the trusted gate, pinned image, one-hour approval after the build, read-only remote', async (t) => {
  const ctx = await world(t, { previous: true });
  const result = await ctx.prepare('c1');
  assert.equal(result.status, 'awaiting_signature');
  assert.equal(result.deployedSha, null);
  const dir = ctx.dir('c1');
  const names = await readdir(dir);
  for (const gone of ['source', 'build', 'tools']) assert(!names.includes(gone), `${gone} was cleaned up`);
  for (const kept of ['image.tar', 'image-config.json', 'source.tar', 'checks.json', 'trusted-check.sh', 'release-controller.mjs', 'manifest.json', 'approval.json', 'signing-handoff.json']) assert(names.includes(kept), kept);
  assert(!names.includes('ingress-plan.json'));
  const manifest = await ctx.manifest('c1');
  const approvalBytes = await readFile(path.join(dir, 'approval.json'));
  const approval = JSON.parse(approvalBytes);
  assert.equal(manifest.image.imageId, `sha256:${sha256(await readFile(path.join(dir, 'image-config.json')))}`);
  assert.equal(manifest.image.appVersion, ctx.sourceSha);
  assert.equal(approval.imageId, manifest.image.imageId);
  assert.equal(approval.manifestSha256, sha256(await readFile(path.join(dir, 'manifest.json'))));
  assert.deepEqual(approval.previous, { present: true, containerId: OLD_CONTAINER, imageId: OLD_IMAGE, running: true });
  assert.equal(approval.sourceSha, ctx.sourceSha);
  assert.equal(approval.triggeringMerge, ctx.mergeSha);
  assert.equal(rc.APPROVAL_LIFETIME_MS, 3_600_000);
  assert.equal(Date.parse(approval.expiresAt) - Date.parse(approval.createdAt), 3_600_000);
  assert(Date.parse(approval.createdAt) >= ctx.local.savedAt, 'the approval clock starts after the image is built');
  const handoff = await readJson(path.join(dir, 'signing-handoff.json'));
  assert.equal(handoff.kind, 'wds.production-approval-signing-handoff');
  assert.equal(handoff.approval.bytesBase64, approvalBytes.toString('base64'));
  assert.equal(handoff.approval.sha256, sha256(approvalBytes));
  assert.deepEqual(handoff.responseContract.allowedFields, ['approvalSha256', 'signatureBase64']);
  assert.equal(handoff.responseContract.privateKeyFieldsAllowed, false);
  // Dependencies are provisioned inside the archived gate export, before the unchanged gate, which runs before the build.
  const index = (predicate) => ctx.calls.findIndex(predicate);
  const dockerRun = (needle) => index((c) => c.file === 'docker' && c.args[0] === 'run' && c.args.includes(needle));
  const venv = dockerRun('venv');
  const gate = dockerRun('/gate/check');
  const build = index((c) => c.file === 'docker' && c.args[0] === 'build' && c.args.includes('--build-arg'));
  assert(venv >= 0 && venv < gate && gate < build);
  assert(!ctx.calls.some((c) => ['python3', 'python', 'corepack', 'pnpm', 'ruff', 'make', 'bash'].includes(path.basename(c.file)) && !c.args.includes('--version')), 'no source or dependency code runs on the host');
  assert(ctx.provisioning.some((p) => hasSequence(p.argv, 'install', '--frozen-lockfile')));
  assert(ctx.provisioning.some((p) => hasSequence(p.argv, '-r', 'backend/requirements.txt', 'pytest', 'ruff')));
  // The backend fetches its paper-detection model when the API module is imported, so the network-less gate needs the weights fetched
  // beforehand, over the install network, into the scratch tools dir that U2NET_HOME names for every sandbox step.
  const fetchModel = ctx.provisioning.findIndex((p) => p.argv.some((a) => a.includes('U2netpSession')));
  const gateStep = ctx.provisioning.findIndex((p) => p.argv.includes('/gate/check'));
  assert(fetchModel >= 0 && fetchModel < gateStep && ctx.provisioning[fetchModel].network === 'bridge', 'the model weights are fetched on the install network before the gate');
  assert(hasSequence(ctx.provisioning[fetchModel].args, '--env', 'U2NET_HOME=/tools/models') && hasSequence(ctx.provisioning[gateStep].args, '--env', 'U2NET_HOME=/tools/models'));
  assert.equal((await readJson(path.join(dir, 'checks.json'))).provisioning.u2netpSha256, sha256('u2netp'));
  const buildArgs = ctx.docker.find((d) => d.side === 'local' && d.args[0] === 'build' && d.args.includes('--build-arg')).args;
  assert(hasSequence(buildArgs, '--build-arg', `APP_VERSION=${ctx.sourceSha}`));
  assert(hasSequence(buildArgs, '--platform', 'linux/amd64'));
  assert(ctx.local.buildContext.endsWith('/build') && !ctx.local.buildContext.includes('/source'), 'the image is built from the pristine export, never the gated one');
  // Forced auth environment and exact container spec are signed.
  const create = manifest.container.createArgs;
  for (const env of ['AUTH_MODE=native', 'AUTH_SETUP_ENABLED=false', 'AUTH_COOKIE_SECURE=true', 'AUTH_ALLOW_ACCOUNT_DATA_WITHOUT_LOGIN=false', 'SHOW_APP_VERSION=true']) assert(hasSequence(create, '--env', env), env);
  assert(hasSequence(create, '--publish', '127.0.0.1:3000:3000/tcp'), 'private deployments publish on loopback only');
  assert(!create.includes('--privileged'));
  assert.equal(create.at(-1), manifest.image.imageId, 'the container is created from the pinned image ID, never a tag');
  // Preparation only observed the remote and never touched a tunnel.
  const remoteCommands = ctx.docker.filter((d) => d.side === 'remote').map((d) => d.args[0] === 'container' ? 'container inspect' : d.args[0]);
  assert(remoteCommands.length > 0 && remoteCommands.every((c) => ['version', 'info', 'container inspect'].includes(c)), remoteCommands.join());
  assert.deepEqual(ctx.remoteOps(), []);
  assert.deepEqual(ctx.cf.calls, []);
  assert(!(await readdir(ctx.policy.target.receiptsRoot)).some((n) => n.startsWith('.ssh-')), 'no ssh scratch left behind');
  assert.equal((await rc.status({ root: ctx.repo, candidate: 'c1', trust: ctx.trust, verifier: ctx.verifier })).status, 'awaiting_signature');
});
test('prepare: ssh is hardened, host key pinned, remote command safely quoted', async (t) => {
  const ctx = await world(t);
  await ctx.prepare('c1');
  const args = ctx.ssh[0];
  const joined = args.join(' ');
  for (const flag of ['-F /dev/null', 'BatchMode=yes', 'IdentitiesOnly=yes', 'IdentityAgent=none', 'StrictHostKeyChecking=yes', 'GlobalKnownHostsFile=/dev/null', 'ProxyCommand=none',
    'ClearAllForwardings=yes', 'ForwardAgent=no', 'PasswordAuthentication=no', 'HostKeyAlgorithms=ssh-ed25519', '-p 2222', `-i ${ctx.policy.target.ssh.identityFile}`]) assert(joined.includes(flag), flag);
  assert(args.includes('root@unraid.test.invalid'));
  assert.match(joined, /UserKnownHostsFile=\S+\.ssh-\S+\/known_hosts/);
  assert.equal(shellSplit(args.at(-1))[0], '/usr/bin/docker');
});
test('prepare fails closed and leaves nothing signable', async (t) => {
  const cases = [
    ['source is not the exact remote main head', {}, { flags: { remoteMain: 'f'.repeat(40) } }, /exact current remote main/, 0],
    ['trusted gate absent at the source', { gate: null }, {}, /\.ade\/check|exit code 128|exited 128/, 0],
    ['trusted gate fails', { gate: '#!/bin/sh\nexit 3\n' }, {}, /exited 3/, 0],
    ['a required tool is missing', {}, { missing: ['tar'] }, /required tools are missing or unusable: tar \(not installed\)/, 0],
    ['dependency provisioning fails', {}, { flags: { failProvision: (argv) => argv.includes('/tools/bin/pnpm') && argv.includes('install') } }, /provisioning failed at "frontend frozen lockfile install"/, 0],
    ['the model weights cannot be fetched', {}, { flags: { failProvision: (argv) => argv.some((a) => a.includes('U2netpSession')) } }, /provisioning failed at "u2netp model weights"/, 0],
    ['the target is unreachable', {}, { hostFlags: { unreachable: true } }, /Connection refused|exited 255/, 0],
    ['the target uses the containerd image store', {}, { hostFlags: { containerdStore: true } }, /containerd image store/, 0],
    ['docker buildx is missing', {}, { localFlags: { buildxMissing: true } }, /docker buildx/, 0],
  ];
  for (const [label, worldOptions, setup, pattern] of cases) {
    const ctx = await world(t, worldOptions);
    for (const name of setup.missing ?? []) ctx.missing.add(name);
    Object.assign(ctx.flags, setup.flags ?? {});
    Object.assign(ctx.host.flags, setup.hostFlags ?? {});
    Object.assign(ctx.local.flags, setup.localFlags ?? {});
    await assert.rejects(ctx.prepare('c1'), pattern, label);
    assert(!ctx.docker.some((d) => d.args[0] === 'build' && !d.args.includes(rc.gateImageTag())), `${label}: no release image was built`);
    assert(!(await exists(path.join(ctx.dir('c1'), 'approval.json'))), `${label}: no approval exists`);
    assert.equal((await rc.status({ root: ctx.repo, candidate: 'c1', trust: ctx.trust })).status, 'preparation_failed', label);
  }
  const ctx = await world(t);
  await assert.rejects(rc.prepare({ root: ctx.repo, candidate: 'c1', sourceSha: ctx.mergeSha, triggeringMerge: ctx.baseSha, trust: ctx.trust, command: ctx.command, sleep: ctx.sleep }), /must be a merge/);
  await assert.rejects(rc.prepare({ root: ctx.repo, candidate: 'c2', sourceSha: ctx.mergeSha, triggeringMerge: '0'.repeat(40), trust: ctx.trust, command: ctx.command, sleep: ctx.sleep }));
  await ctx.prepare('c3');
  await assert.rejects(ctx.prepare('c3'), /EEXIST/, 'a retained candidate id is never overwritten');
  await assert.rejects(ctx.prepare('Bad_ID'), /invalid candidate id/);
});

// ---------------------------------------------------------------------------------------------
// Submit: signature, expiry, tampering, replay
// ---------------------------------------------------------------------------------------------
test('submit: verified signature queues a durable systemd job; replay is refused', async (t) => {
  const ctx = await world(t);
  await ctx.prepare('c1');
  assert.equal((await rc.status({ root: ctx.repo, candidate: 'c1', trust: ctx.trust, verifier: ctx.verifier })).status, 'awaiting_signature');
  await ctx.sign('c1');
  assert.equal((await rc.status({ root: ctx.repo, candidate: 'c1', trust: ctx.trust, verifier: ctx.verifier })).status, 'signed');
  const queued = await ctx.submit('c1');
  assert.equal(queued.status, 'queued');
  assert.equal(queued.deployedSha, null);
  const unit = ctx.systemd[0];
  assert(unit.includes('--user') && unit.includes('tracefinity-release-c1'));
  assert.deepEqual(unit.slice(-4), [path.join(ctx.job('c1'), 'release-controller.mjs'), 'deploy-job', '--candidate', 'c1']);
  assert.equal(unit.at(-5), '/usr/bin/node');
  assert.equal((await lstat(ctx.job('c1'))).mode & 0o777, 0o700);
  for (const file of ['image.tar', 'approval.json', 'release.sig', 'manifest.json']) assert.equal((await lstat(path.join(ctx.job('c1'), file))).mode & 0o777, 0o400, file);
  assert.equal(ctx.remoteOps().length, 0, 'submit never touches the target');
  await assert.rejects(ctx.submit('c1'), /EEXIST/);
  assert.equal(ctx.systemd.length, 1);
  assert.equal((await ctx.receipt('c1')).status, 'queued');
});
test('submit: a transport error keeps dispatch evidence and never claims failure or success', async (t) => {
  const ctx = await world(t);
  await ctx.prepare('c1');
  await ctx.sign('c1');
  ctx.flags.systemdFails = true;
  await assert.rejects(ctx.submit('c1'), /systemd-run failed/);
  assert.equal((await ctx.receipt('c1')).status, 'queued');
  assert.equal((await readJson(path.join(ctx.job('c1'), 'dispatch-error.json'))).candidateId, 'c1');
  assert.equal((await rc.productionStatus(ctx.trust)).status, 'not_deployed');
});
test('submit: signature negatives with the injected verifier and with the real Ed25519 verifier', async (t) => {
  const ctx = await world(t);
  await ctx.prepare('c1');
  const sig = path.join(ctx.dir('c1'), 'release.sig');
  await assert.rejects(ctx.submit('c1'), /ENOENT/, 'missing signature');
  const bytes = await readFile(path.join(ctx.dir('c1'), 'approval.json'));
  for (const bad of ['', 'garbage', stubSignature(Buffer.from('other approval')), stubSignature(bytes).slice(0, -4)]) {
    await writeFile(sig, `${bad}\n`);
    await assert.rejects(ctx.submit('c1'), /not from the explicitly trusted operator/, `signature ${bad.slice(0, 12)}`);
  }
  await ctx.sign('c1');
  await assert.rejects(rc.submit({ root: ctx.repo, candidate: 'c1', trust: ctx.trust, command: ctx.command }), /signature is not (from the explicitly trusted operator|canonical)|invalid detached signature/,
    'a stub signature is not a genuine Ed25519 signature');
  await writeFile(sig, `${Buffer.alloc(63).toString('base64')}\n`);
  await assert.rejects(rc.submit({ root: ctx.repo, candidate: 'c1', trust: ctx.trust, command: ctx.command }), /invalid detached signature/);
  assert.equal(ctx.systemd.length, 0);
  assert(!(await exists(ctx.job('c1'))), 'nothing durable was created');
});
test('submit: tampering any signed byte, or the policy, prevents dispatch', async (t) => {
  for (const exposure of ['private', 'public']) {
    const ctx = await world(t, { exposure, admins: true });
    await ctx.prepare('c1');
    await ctx.sign('c1');
    const files = ['approval.json', 'manifest.json', 'signing-handoff.json', 'image.tar', 'image-config.json', 'source.tar', 'checks.json', 'trusted-check.sh', 'release-controller.mjs',
      ...(exposure === 'public' ? ['ingress-plan.json'] : [])];
    for (const file of files) {
      const target = path.join(ctx.dir('c1'), file);
      const original = await readFile(target);
      const flipped = Buffer.from(original);
      flipped[0] ^= 1;
      await writeFile(target, flipped);
      await assert.rejects(ctx.submit('c1'), (error) => error instanceof Error, `${exposure} ${file}`);
      await writeFile(target, original);
    }
    assert.equal(ctx.systemd.length, 0);
    assert(!(await exists(ctx.job('c1'))));
    const changed = structuredClone(ctx.policy);
    changed.target.container.hostPort = 3001;
    if (changed.target.exposure.mode === 'public') changed.target.exposure.ingress.service = 'http://192.0.2.10:3001';
    await assert.rejects(ctx.submit('c1', { trust: { policy: changed, policySha256: rc.policyDigest(changed) } }), /does not match trusted policy\/target/);
    const otherKey = structuredClone(ctx.policy);
    otherKey.publicKeyBase64 = hex(RFC.two.pub).toString('base64');
    await assert.rejects(ctx.submit('c1', { trust: { policy: otherKey, policySha256: rc.policyDigest(otherKey) } }), /does not match trusted policy\/target/);
    const acceptanceOnly = structuredClone(ctx.policy);
    acceptanceOnly.acceptance.timeoutMs = 30_000;
    assert.equal((await ctx.submit('c1', { trust: { policy: acceptanceOnly, policySha256: rc.policyDigest(acceptanceOnly) } })).status, 'queued', 'acceptance settings are not part of the signed deployment');
  }
});
test('approval window is strict: one hour, created no later than now, expired exactly at expiresAt', async (t) => {
  const ctx = await world(t);
  await ctx.prepare('c1');
  await ctx.sign('c1');
  const approval = await readJson(path.join(ctx.dir('c1'), 'approval.json'));
  const created = Date.parse(approval.createdAt);
  const expires = Date.parse(approval.expiresAt);
  const verify = (now) => rc.verifyCandidate(ctx.dir('c1'), ctx.trust, { now, verifier: ctx.verifier });
  assert.equal((await verify(created)).sourceSha, ctx.sourceSha);
  assert.equal((await verify(expires - 1)).sourceSha, ctx.sourceSha);
  await assert.rejects(verify(expires), /expired/);
  await assert.rejects(verify(expires + 60_000), /expired/);
  await assert.rejects(verify(created - 1), /expired/);
  await assert.rejects(ctx.submit('c1', { now: () => expires }), /expired/);
  assert.equal((await rc.status({ root: ctx.repo, candidate: 'c1', trust: ctx.trust, now: expires, verifier: ctx.verifier })).status, 'expired');
  const widen = async (mutate) => {
    const dir = ctx.dir('c1');
    const next = JSON.parse(await readFile(path.join(dir, 'approval.json')));
    mutate(next);
    const bytes = Buffer.from(`${JSON.stringify(next, null, 2)}\n`);
    await writeFile(path.join(dir, 'approval.json'), bytes);
    await writeFile(path.join(dir, 'signing-handoff.json'), Buffer.from(`${JSON.stringify(rc.handoff(bytes), null, 2)}\n`));
    await ctx.sign('c1');
  };
  await widen((a) => { a.expiresAt = new Date(created + 2 * 3_600_000).toISOString(); });
  await assert.rejects(verify(created + 1000), /expired|manifest|invalid/, 'a window longer than one hour is refused even when re-signed');
});

// ---------------------------------------------------------------------------------------------
// Deployment worker
// ---------------------------------------------------------------------------------------------
test('first deploy is private: loopback only, verified image ID, closed first-run door, no tunnel contact, honest status', async (t) => {
  const ctx = await world(t);
  await ctx.ship('c1');
  const result = await ctx.deploy('c1');
  const manifest = await ctx.manifest('c1');
  assert.equal(result.status, 'deployed');
  assert.equal(result.deployedSha, ctx.sourceSha);
  assert.equal(result.runtime.imageId, manifest.image.imageId);
  assert.equal(result.runtime.appVersion, ctx.sourceSha);
  assert.equal(result.runtime.publishAddress, '127.0.0.1');
  assert.deepEqual(result.exposure, { mode: 'private', publicExposure: 'not_applied' });
  assert.equal(result.administrator.verified, false, 'a fresh install has no administrator and is still deployable privately');
  assert.equal(result.health.internal.setupRequired, false);
  assert.equal(result.health.internal.sensitiveStatus, 401);
  assert.deepEqual(ctx.cf.calls, [], 'no tunnel contact in a private deployment');
  assert.equal(ctx.probed.length, 0, 'no LAN or public request in a private deployment');
  assert.deepEqual(await readJson(path.join(ctx.policy.target.receiptsRoot, 'production-state.json')), await ctx.receipt('c1'));
  assert(!(await exists(path.join(ctx.policy.target.receiptsRoot, 'deployment.lock'))));
  assert(!(await readdir(ctx.policy.target.receiptsRoot)).some((n) => n.startsWith('.ssh-')));
  // Exact remote behaviour.
  const live = ctx.host.find('tracefinity');
  assert.equal(live.Image, manifest.image.imageId);
  assert.deepEqual(live.HostConfig.PortBindings, { '3000/tcp': [{ HostIp: '127.0.0.1', HostPort: '3000' }] });
  assert.equal(envOf(live).AUTH_SETUP_ENABLED, 'false');
  assert.equal(envOf(live).AUTH_COOKIE_SECURE, 'true');
  const adminRun = ctx.events.find((e) => e.op === 'run' && e.kind === 'admin');
  assert(adminRun.args.some((a) => /^type=bind,source=\/mnt\/user\/appdata\/tracefinity,target=\/app\/storage,readonly$/.test(a)), 'the account store is read-only for the check');
  assert(hasSequence(adminRun.args, '--network', 'none'));
  const seed = ctx.events.find((e) => e.op === 'run' && e.kind === 'seed');
  assert(seed.args.some((a) => /^type=bind,source=\/mnt\/user\/appdata\/tracefinity,target=\/seed,readonly$/.test(a)), 'credential files are copied from the live storage mounted read-only');
  const canary = ctx.events.find((e) => e.side === 'remote' && e.op === 'run' && e.kind === 'canary');
  assert(hasSequence(canary.args, '--network', 'none') && !canary.args.includes('--tmpfs') && !canary.args.includes('--publish'));
  assert(hasSequence(canary.args, '--env-file', '/mnt/user/appdata/tracefinity-release/app.env'), 'the staged canary runs the production env file');
  assert(canary.args.some((a) => /^type=volume,source=tracefinity-canary-c1-storage,target=\/app\/storage$/.test(a)), 'on a private seeded volume');
  assert(!canary.args.some((a) => a.includes('source=/mnt/user/appdata/tracefinity,')), 'never the live storage');
  assert(canary.args.some((a) => /target=\/config\/rclone\.conf,readonly$/.test(a)), 'extra mounts are read-only in the canary');
  assert(hasSequence(canary.args, '--env', 'AUTH_SETUP_ENABLED=false') && hasSequence(canary.args, '--env', 'RCLONE_EXPORT_REMOTE=drive:Tracefinity'));
  assertVerifiedBeforeMutations(ctx.events);
  const status = await rc.productionStatus(ctx.trust);
  assert.equal(status.status, 'deployed');
  assert.equal(status.deployedSha, ctx.sourceSha);
  assert.equal(status.evidence, 'receipt');
  assert.match(status.summary, /privately on the target loopback only; public exposure NOT applied; no administrator verified yet/);
  const printed = JSON.stringify(status);
  for (const secret of ['unraid.test.invalid', '/mnt/user/appdata', 'id_fixture']) assert(!printed.includes(secret), secret);
  await assert.rejects(rc.loadAcceptanceTarget({ candidateId: 'c1' }, { trust: ctx.trust }), (error) => error.code === 'private_deployment');
  await assert.rejects(ctx.deploy('c1'), /job already attempted/, 'replay is refused');
});
test('replacement preserves the previous container stopped under its own name; ids, not names, are stopped', async (t) => {
  const ctx = await world(t, { previous: true });
  await ctx.ship('c1');
  const result = await ctx.deploy('c1');
  assert.equal(result.previousContainer.containerId, OLD_CONTAINER);
  assert.equal(result.preservedPreviousName, 'tracefinity-prev-c1');
  const previous = ctx.host.find('tracefinity-prev-c1');
  assert.equal(previous.Id, OLD_CONTAINER);
  assert.equal(previous.State.Running, false);
  assert.equal(previous.HostConfig.RestartPolicy.Name, 'no');
  assert(ctx.host.find('tracefinity').State.Running);
  const stop = ctx.docker.find((d) => d.args[0] === 'stop');
  assert.equal(stop.args.at(-1), OLD_CONTAINER);
  assert.deepEqual(ctx.remoteOps().filter((op) => op !== 'run' && op !== 'rm'), ['load', 'volume', 'create', 'stop', 'update', 'rename', 'rename', 'start']);
  assertVerifiedBeforeMutations(ctx.events);
});
test('worker refuses before any mutation when the target drifted, the candidate was attempted, a lock exists or an artifact changed', async (t) => {
  let ctx = await world(t, { previous: true });
  await ctx.ship('c1');
  ctx.host.containers.get(OLD_CONTAINER).Image = `sha256:${'8'.repeat(64)}`;
  await assert.rejects(ctx.deploy('c1'), /target changed since preparation/);
  assert.deepEqual(ctx.remoteOps(), []);
  assert.equal((await ctx.receipt('c1')).status, 'failed');
  assert.equal((await ctx.receipt('c1')).deployedSha, null);

  ctx = await world(t, { previous: true });
  await ctx.ship('c1');
  ctx.host.containers.delete(OLD_CONTAINER);
  await assert.rejects(ctx.deploy('c1'), /target changed since preparation/, 'an approval signed against a different prior state cannot be replayed');
  assert.deepEqual(ctx.remoteOps(), []);

  ctx = await world(t);
  await ctx.ship('c1');
  ctx.host.seedPrevious();
  await assert.rejects(ctx.deploy('c1'), /target changed since preparation/);

  ctx = await world(t);
  await ctx.ship('c1');
  const afterLockShip = ctx.docker.length; // preparation legitimately observed the remote; only the worker's contact is under test
  await mkdir(path.join(ctx.policy.target.receiptsRoot, 'deployment.lock'));
  await assert.rejects(ctx.deploy('c1'), /another deployment holds the deployment lock/);
  assert(await exists(path.join(ctx.policy.target.receiptsRoot, 'deployment.lock')), 'the loser does not remove the holder\'s lock');
  assert.equal((await ctx.receipt('c1')).status, 'failed');
  assert.deepEqual(ctx.docker.slice(afterLockShip).filter((d) => d.side === 'remote'), []);

  ctx = await world(t);
  await ctx.ship('c1');
  const afterTamperShip = ctx.docker.length;
  await chmod(path.join(ctx.job('c1'), 'image.tar'), 0o600);
  await writeFile(path.join(ctx.job('c1'), 'image.tar'), 'swapped');
  await assert.rejects(ctx.deploy('c1'), /tampered artifact: image.tar/);
  assert.deepEqual(ctx.docker.slice(afterTamperShip).filter((d) => d.side === 'remote'), [], 'no target contact at all');

  ctx = await world(t);
  await ctx.ship('c1');
  ctx.host.images.set(ctx.host.loadable.imageId, { Id: ctx.host.loadable.imageId, Config: { Env: [], Labels: {} }, RootFS: { Layers: ctx.host.loadable.diffIds }, Os: 'linux', Architecture: 'amd64' });
  await ctx.host.docker(['create', '--name', 'tracefinity-next-c1', ctx.host.loadable.imageId]);
  ctx.events.length = 0;
  await assert.rejects(ctx.deploy('c1'), /already in use on the target; this candidate was already attempted/);
  assert.deepEqual(ctx.remoteOps(), []);
});
test('the loaded image must be exactly the signed image ID; the approval cannot lapse before cutover; live target stays untouched', async (t) => {
  let ctx = await world(t, { previous: true });
  await ctx.ship('c1');
  ctx.host.flags.loadAs = { ...ctx.host.loadable, imageId: `sha256:${'d'.repeat(64)}` };
  await assert.rejects(ctx.deploy('c1'), /target image ID absent is not the signed sha256:/);
  assert(!ctx.remoteOps().includes('create'));
  assert(ctx.host.find('tracefinity').State.Running);

  ctx = await world(t, { previous: true });
  await ctx.ship('c1');
  ctx.host.flags.loadAs = { ...ctx.host.loadable, diffIds: [`sha256:${'1'.repeat(64)}`] };
  await assert.rejects(ctx.deploy('c1'), /target image layers are not the signed layers/);

  ctx = await world(t, { previous: true });
  await ctx.ship('c1');
  const expires = Date.parse((await readJson(path.join(ctx.job('c1'), 'approval.json'))).expiresAt);
  const result = ctx.deploy('c1', { now: () => (ctx.events.some((e) => e.op === 'create') ? expires + 1 : Date.now()) });
  await assert.rejects(result, /expired/);
  assert.equal((await ctx.receipt('c1')).status, 'failed');
  assert.deepEqual(ctx.remoteOps().filter((op) => ['stop', 'update', 'rename', 'start'].includes(op)), [], 'the cutover never began');
  assert(ctx.host.find('tracefinity').State.Running, 'the previous container still serves');
  assert.equal(ctx.host.find('tracefinity').Id, OLD_CONTAINER);
  assert(!ctx.host.find('tracefinity-next-c1'), 'the staged container was removed');

  ctx = await world(t);
  await ctx.ship('c1');
  ctx.host.flags.envFileWins = true;
  await assert.rejects(ctx.deploy('c1'), /effective environment AUTH_SETUP_ENABLED is not the signed value|first-run setup is reachable/);
  assert((await ctx.receipt('c1')).status === 'failed' && !ctx.host.find('tracefinity-next-c1'));

  ctx = await world(t);
  await ctx.ship('c1');
  ctx.host.flags.probe = { sensitive: 200 };
  await assert.rejects(ctx.deploy('c1'), /canary never became healthy|sensitive endpoint answered 200/);
  assert(!ctx.remoteOps().includes('create'));
});
test('after cutover only proofs make a deployment: wrong image, open first-run door, never healthy', async (t) => {
  let ctx = await world(t, { previous: true });
  await ctx.ship('c1');
  ctx.host.flags.wrongImageOnStart = true;
  await assert.rejects(ctx.deploy('c1'), /container uses image sha256:e+, not the signed/);
  let receipt = await ctx.receipt('c1');
  assert.equal(receipt.status, 'production_incomplete');
  assert.equal(receipt.deployedSha, null);
  assert.equal(receipt.preservedPreviousName, 'tracefinity-prev-c1');
  assert.equal((await rc.productionStatus(ctx.trust)).deployedSha, null);
  assert.match((await rc.productionStatus(ctx.trust)).summary, /not deployed: production_incomplete/);

  ctx = await world(t);
  await ctx.ship('c1');
  const original = ctx.host.probeFor.bind(ctx.host);
  ctx.host.probeFor = (c) => ({ ...original(c), auth: { mode: 'native', setup_required: true, authenticated: false } });
  await assert.rejects(ctx.deploy('c1'), /first-run setup is reachable|canary never became healthy/);

  ctx = await world(t);
  await ctx.ship('c1');
  ctx.host.flags.notReadyFor = 100_000;
  await assert.rejects(ctx.deploy('c1'), /did not pass live verification after 180 attempts/);
  receipt = await ctx.receipt('c1');
  assert.equal(receipt.status, 'production_incomplete');
  assert.equal(ctx.sleeps, 179);
  assert.equal((await readJson(path.join(ctx.policy.target.receiptsRoot, 'production-state.json'))).status, 'production_incomplete');
  assert(!(await exists(path.join(ctx.policy.target.receiptsRoot, 'deployment.lock'))));
  // Recovery: verify-live reports honestly, and only --execute upgrades the record, only when every proof passes.
  const before = ctx.remoteOps().length;
  ctx.host.flags.notReadyFor = 0;
  const report = await rc.verifyLive({ candidate: 'c1', trust: ctx.trust, command: ctx.command, probe: ctx.probe, verifier: ctx.verifier });
  assert.equal(report.verifiedLive, true);
  assert.equal(report.upgradePending, true);
  assert.equal((await ctx.receipt('c1')).status, 'production_incomplete');
  const upgraded = await rc.verifyLive({ candidate: 'c1', trust: ctx.trust, command: ctx.command, probe: ctx.probe, verifier: ctx.verifier, execute: true });
  assert.equal(upgraded.status, 'deployed');
  assert.equal(upgraded.recovery.from, 'production_incomplete');
  assert.equal(ctx.remoteOps().length, before, 'verify-live never mutates the target');
});
test('verify-live reports drift honestly and inspectRunningImage never mistakes an unreachable host for a stopped app', async (t) => {
  const ctx = await world(t, { previous: true });
  await ctx.ship('c1');
  await ctx.deploy('c1');
  const deps = { trust: ctx.trust, command: ctx.command };
  const running = await rc.inspectRunningImage(deps);
  assert.equal(running.running, true);
  assert.equal(running.imageId, (await ctx.manifest('c1')).image.imageId);
  assert.deepEqual(running.repoDigests, []);
  const live = await rc.verifyLive({ candidate: 'c1', trust: ctx.trust, command: ctx.command, probe: ctx.probe, verifier: ctx.verifier });
  assert.equal(live.verifiedLive, true);
  assert.equal(live.deployedSha, ctx.sourceSha);
  const replaced = ctx.host.find('tracefinity');
  replaced.Name = '/gone';
  ctx.host.containers.set('f'.repeat(64), { ...replaced, Id: 'f'.repeat(64), Name: '/tracefinity' });
  const drift = await rc.verifyLive({ candidate: 'c1', trust: ctx.trust, command: ctx.command, probe: ctx.probe, verifier: ctx.verifier });
  assert.equal(drift.verifiedLive, false);
  assert.equal(drift.deployedSha, null);
  ctx.host.flags.unreachable = true;
  await assert.rejects(rc.inspectRunningImage(deps), /Connection refused|exited 255/);
  const unreachable = await rc.verifyLive({ candidate: 'c1', trust: ctx.trust, command: ctx.command, probe: ctx.probe, verifier: ctx.verifier });
  assert.equal(unreachable.verifiedLive, false);
  assert.doesNotMatch(unreachable.reason, /unraid\.test\.invalid/, 'the reason is redacted');
});

// ---------------------------------------------------------------------------------------------
// Public exposure and the signed Cloudflare ingress
// ---------------------------------------------------------------------------------------------
const OTHER_RULE = { hostname: 'other.example.test', service: 'http://192.0.2.20:8080' };
test('public candidate signs the tunnel, hostname, service and before/after configuration digests; preparation never changes the tunnel', async (t) => {
  const ctx = await world(t, { exposure: 'public', admins: true });
  await ctx.prepare('c1');
  const dir = ctx.dir('c1');
  const plan = await readJson(path.join(dir, 'ingress-plan.json'));
  const approval = await readJson(path.join(dir, 'approval.json'));
  assert.equal(plan.action, 'add');
  assert.deepEqual(plan.planned.ingress, [OTHER_RULE, { hostname: 'app.example.test', service: 'http://192.0.2.10:3000' }, { service: 'http_status:404' }], 'only our rule is added, before the catch-all');
  assert.deepEqual(plan.planned['warp-routing'], plan.base['warp-routing'], 'unrelated settings are preserved');
  assert.deepEqual(approval.ingress, { provider: 'cloudflare-tunnel', accountId: IDS.account, zoneId: IDS.zone, tunnelId: IDS.tunnel, hostname: 'app.example.test',
    service: 'http://192.0.2.10:3000', action: 'add', singleWriterAttested: true, baseConfigSha256: rc.configDigest(plan.base), safeConfigSha256: rc.configDigest(plan.safe),
    plannedConfigSha256: rc.configDigest(plan.planned) });
  assert.equal(approval.exposure, 'public');
  assert(hasSequence((await ctx.manifest('c1')).container.createArgs, '--publish', '192.0.2.10:3000:3000/tcp'));
  assert(ctx.cf.calls.length >= 2 && ctx.cf.calls.every((c) => c.method === 'GET'), 'preparation only reads Cloudflare');
  assert.equal(ctx.cf.version, 1);
  const refusals = [
    ['DNS record missing', (c) => { c.cf.dns = []; }, /proxied DNS CNAME/],
    ['DNS points elsewhere', (c) => { c.cf.dns[0].content = 'other.cfargotunnel.com'; }, /proxied DNS CNAME/],
    ['tunnel is locally managed', (c) => { c.cf.source = 'local'; }, /not remotely managed/],
    ['hostname routed elsewhere', (c) => { c.cf.config.ingress.unshift({ hostname: 'app.example.test', service: 'http://192.0.2.99:1' }); }, /never repoints/],
    ['wildcard would shadow', (c) => { c.cf.config.ingress.unshift({ hostname: '*.example.test', service: 'http://192.0.2.98:1' }); }, /wildcard rule would shadow/],
    ['no catch-all', (c) => { c.cf.config.ingress.pop(); }, /catch-all/],
  ];
  for (const [label, mutate, pattern] of refusals) {
    const other = await world(t, { exposure: 'public', admins: true });
    mutate(other);
    await assert.rejects(other.prepare('c1'), pattern, label);
    assert(other.cf.calls.every((c) => c.method === 'GET'), label);
  }
  const noToken = await world(t, { exposure: 'public' });
  await chmod(path.join(noToken.root, 'cf-token'), 0o644);
  await assert.rejects(noToken.prepare('c1'), /mode 0600/);
});
test('public deploy: administrator verified before cutover, container proven, then exactly one signed ingress change, then the public route is bound to the container', async (t) => {
  const ctx = await world(t, { exposure: 'public', previous: true, admins: true });
  await ctx.ship('c1');
  const base = structuredClone(ctx.cf.config);
  const result = await ctx.deploy('c1');
  assert.equal(result.status, 'deployed');
  assert.deepEqual(result.exposure, { mode: 'public', publicExposure: 'verified' });
  assert.equal(result.administrator.verified, true);
  assert.equal(result.ingress.applied, true);
  assert.equal(result.health.public.routeProof, 'nonce-in-container-access-log');
  const puts = ctx.events.filter((e) => e.op === 'cf:PUT');
  assert.equal(puts.length, 1);
  const putIndex = ctx.events.indexOf(puts[0]);
  assert.equal(ctx.events[putIndex - 1].op, 'verify', 'signature and expiry are verified immediately before the route changes');
  assert(ctx.events.findIndex((e) => e.op === 'start') < putIndex, 'the route changes only after the container is started and proven');
  assert.deepEqual(rc.normalizeConfig(ctx.cf.config).ingress, [OTHER_RULE, { hostname: 'app.example.test', service: 'http://192.0.2.10:3000' }, { service: 'http_status:404' }]);
  assert.equal(rc.normalizeConfig(ctx.cf.config).ingress[0].hostname, rc.normalizeConfig(base).ingress[0].hostname);
  assertVerifiedBeforeMutations(ctx.events);
  const paths = ctx.probed.map((url) => new URL(url).pathname);
  assert(paths.length > 0 && paths.every((p) => Object.values(rc.NGINX_PROBE_PATHS).includes(p)), `probed ${paths.join()}`);
  assert(!paths.includes('/health'));
  // Acceptance support.
  const target = await rc.loadAcceptanceTarget({ candidateId: 'c1' }, { trust: ctx.trust });
  assert.deepEqual(Object.keys(target).sort(), ['appVersion', 'approvalSha256', 'candidateId', 'cookieFile', 'deployedAt', 'environment', 'imageDigest', 'publicOrigin', 'publish', 'sourceSha', 'state', 'timeoutMs']);
  assert.equal(target.publicOrigin, 'https://app.example.test');
  assert.equal(target.imageDigest, (await ctx.manifest('c1')).image.imageId);
  assert.equal(target.appVersion, ctx.sourceSha);
  assert.equal(target.publish.verifier, 'fixture-verifier');
  await assert.rejects(rc.loadAcceptanceTarget({ candidateId: 'c2' }, { trust: ctx.trust }), /not the verified deployed release/);
  const changed = structuredClone(ctx.policy);
  changed.target.exposure.publicStatus = 302;
  await assert.rejects(rc.loadAcceptanceTarget({ candidateId: 'c1' }, { trust: { policy: changed, policySha256: rc.policyDigest(changed) } }), /pinned policy changed/);
  const deps = { trust: ctx.trust, command: ctx.command, probe: ctx.probe, fetchImpl: (url, init) => ctx.cf.fetch(url, init) };
  const bound = await rc.proveRouteBinding({ candidateId: 'c1' }, deps);
  assert.equal(bound.bound, true);
  assert.equal(bound.containerId, result.runtime.containerId);
  const marker = `acceptance_nonce=${'ab'.repeat(16)}`;
  const since = new Date().toISOString();
  assert.deepEqual(await rc.confirmBackendRequest({ marker, sinceIso: since }, deps), { seen: false });
  ctx.host.logText = `INFO: 127.0.0.1 - "GET /api/version?${marker} HTTP/1.1" 200`;
  assert.deepEqual(await rc.confirmBackendRequest({ marker, sinceIso: since }, deps), { seen: true });
  await assert.rejects(rc.confirmBackendRequest({ marker: 'acceptance_nonce=xyz', sinceIso: since }, deps), /marker must be/);
  await assert.rejects(rc.confirmBackendRequest({ marker, sinceIso: 'yesterday' }, deps), /sinceIso must be/);
  assert(ctx.docker.some((d) => d.args[0] === 'logs' && d.args.includes('--since')));
  // A misrouted or spoofed public origin cannot be bound to the inspected container.
  ctx.flags.misroute = true;
  await assert.rejects(rc.proveRouteBinding({ candidateId: 'c1' }, deps), /nonce is absent from its nginx access log/);
  ctx.flags.misroute = false;
  ctx.cf.config.ingress[1].service = 'http://203.0.113.9:3000';
  await assert.rejects(rc.proveRouteBinding({ candidateId: 'c1' }, deps), /not the signed planned configuration/);
});
test('public deploy refuses when no administrator exists: nothing is mutated and the tunnel is untouched', async (t) => {
  const ctx = await world(t, { exposure: 'public', admins: false });
  await ctx.ship('c1');
  await assert.rejects(ctx.deploy('c1'), /public exposure refused: no enabled administrator exists/);
  assert.equal((await ctx.receipt('c1')).status, 'failed');
  assert.deepEqual(ctx.remoteOps().filter((op) => ['create', 'stop', 'rename', 'start'].includes(op)), []);
  assert(!ctx.events.some((e) => e.op === 'cf:PUT'));
  ctx.host.admins = { accounts: 1, enabledAdmins: 0 };
  const other = await world(t, { exposure: 'public' });
  await other.ship('c1');
  other.host.admins = { accounts: 3, enabledAdmins: 0 };
  await assert.rejects(other.deploy('c1'), /no enabled administrator/, 'disabled accounts do not count');
  const corrupt = await world(t, { exposure: 'public', admins: true });
  await corrupt.ship('c1');
  corrupt.host.flags.storageCorrupt = true;
  await assert.rejects(corrupt.deploy('c1'), /JSONDecodeError|exited 1/, 'an unreadable account store fails closed');
});
test('tunnel drift or an expired approval blocks activation; a failed public proof retracts to the signed base', async (t) => {
  let ctx = await world(t, { exposure: 'public', admins: true });
  await ctx.ship('c1');
  ctx.cf.config.ingress.splice(1, 0, { hostname: 'late.example.test', service: 'http://192.0.2.30:1' });
  await assert.rejects(ctx.deploy('c1'), /tunnel ingress changed since preparation/);
  assert.deepEqual(ctx.remoteOps(), []);
  assert.equal((await ctx.receipt('c1')).status, 'failed');

  ctx = await world(t, { exposure: 'public', admins: true });
  await ctx.ship('c1');
  const expires = Date.parse((await readJson(path.join(ctx.job('c1'), 'approval.json'))).expiresAt);
  await assert.rejects(ctx.deploy('c1', { now: () => (ctx.events.some((e) => e.op === 'start') ? expires + 1 : Date.now()) }), /expired/);
  assert.equal((await ctx.receipt('c1')).status, 'production_incomplete');
  assert(!ctx.events.some((e) => e.op === 'cf:PUT'), 'the route was never activated');

  ctx = await world(t, { exposure: 'public', admins: true });
  await ctx.ship('c1');
  const base = structuredClone(ctx.cf.config);
  ctx.flags.publicSensitive = 200;
  await assert.rejects(ctx.deploy('c1'), /public unauthenticated sensitive endpoint answered 200; ingress retracted to the signed route-absent configuration/);
  const receipt = await ctx.receipt('c1');
  assert.equal(receipt.status, 'production_incomplete');
  assert.equal(receipt.deployedSha, null);
  assert.equal(receipt.ingress.retraction.retracted, true);
  assert.deepEqual(rc.normalizeConfig(ctx.cf.config), rc.normalizeConfig(base));
  assert.equal(ctx.events.filter((e) => e.op === 'cf:PUT').length, 2);

  ctx = await world(t, { exposure: 'public', admins: true });
  await ctx.ship('c1');
  ctx.flags.misroute = true;
  await assert.rejects(ctx.deploy('c1'), /nonce is absent from its nginx access log; ingress retracted/);

  ctx = await world(t, { exposure: 'public', admins: true });
  await ctx.ship('c1');
  ctx.flags.publicSensitive = 200;
  const probe = async (url) => {
    if (url.includes('/api/api-keys') && new URL(url).host === 'app.example.test') ctx.cf.config.ingress.splice(ctx.cf.config.ingress.length - 1, 0, { hostname: 'x.example.test', service: 'http://192.0.2.77:1' });
    return ctx.probe(url);
  };
  await assert.rejects(ctx.deploy('c1', { probe }), /ingress could not be retracted/);
  const untouched = await ctx.receipt('c1');
  assert(untouched.ingress.retraction.reason.includes('left untouched'), 'a configuration changed by someone else is never overwritten');
  assert.equal(ctx.events.filter((e) => e.op === 'cf:PUT').length, 1, 'only the signed activation was written');
  assert(ctx.cf.config.ingress.some((rule) => rule.hostname === 'x.example.test'), 'the other party\'s change is still there');
});
test('a compensating ingress change needs a valid signature and an unexpired approval, or it is not made', async (t) => {
  const ctx = await world(t, { exposure: 'public', admins: true });
  await ctx.ship('c1');
  const expires = Date.parse((await readJson(path.join(ctx.job('c1'), 'approval.json'))).expiresAt);
  ctx.flags.publicSensitive = 200;
  await assert.rejects(ctx.deploy('c1', { now: () => (ctx.events.some((e) => e.op === 'cf:PUT') ? expires + 1 : Date.now()) }),
    /public unauthenticated sensitive endpoint answered 200; ingress could not be retracted \(compensating ingress change not authorized/);
  const receipt = await ctx.receipt('c1');
  assert.equal(receipt.status, 'production_incomplete');
  assert.equal(receipt.deployedSha, null);
  assert.equal(receipt.ingress.retraction.retracted, false);
  assert.equal(receipt.ingress.retraction.authorized, false);
  assert.match(receipt.ingress.retraction.reason, /operator action/);
  assert.equal(ctx.events.filter((e) => e.op === 'cf:PUT').length, 1, 'no unauthorized compensating PUT');
  // And while the approval is valid, the compensating PUT is itself preceded by a verification.
  const valid = await world(t, { exposure: 'public', admins: true });
  await valid.ship('c1');
  valid.flags.publicSensitive = 200;
  await assert.rejects(valid.deploy('c1'), /ingress retracted to the signed route-absent configuration/);
  const puts = valid.events.map((e, i) => [e, i]).filter(([e]) => e.op === 'cf:PUT');
  assert.equal(puts.length, 2);
  for (const [, i] of puts) assert.equal(valid.events[i - 1].op, 'verify', 'every Cloudflare change is immediately preceded by signature and expiry verification');
});
test('Cloudflare failures name only API codes, never the token or private target', async (t) => {
  const ctx = await world(t, { exposure: 'public', admins: true });
  await ctx.ship('c1');
  await writeFile(path.join(ctx.root, 'cf-token'), 'cf-wrong-token-0123456789abcdefghijk');
  await assert.rejects(ctx.deploy('c1'), (error) => /Cloudflare API GET failed \(HTTP 403, codes 10000\)/.test(error.message) && !error.message.includes('cf-wrong-token') && !error.message.includes(TOKEN));
  const receipt = JSON.stringify(await ctx.receipt('c1'));
  for (const secret of ['cf-wrong-token', TOKEN, IDS.tunnel, 'app.example.test']) assert(!receipt.includes(secret), secret);
  assert.deepEqual(ctx.remoteOps(), []);
});
test('policy: ingress needs the single-writer attestation, no wildcard publish address, exactly one acceptance verifier mode', () => {
  const bad = (mutate, pattern, exposure = 'private') => {
    const policy = structuredClone(makePolicy(BASE, exposure));
    mutate(policy);
    assert.throws(() => rc.validatePolicy(policy), pattern);
  };
  bad((p) => { delete p.target.exposure.ingress.singleWriter; }, /singleWriter/, 'public');
  bad((p) => { p.target.exposure.ingress.singleWriter = false; }, /singleWriter must be true/, 'public');
  bad((p) => { p.target.exposure.publishAddress = '0.0.0.0'; }, /never 0\.0\.0\.0/, 'public');
  bad((p) => { p.acceptance.publish.verifierApp = 123; }, /exactly one of verifier/);
  bad((p) => { delete p.acceptance.publish.verifier; }, /exactly one of verifier/);
  bad((p) => { delete p.acceptance.publish.verifier; p.acceptance.publish.verifierApp = 0; }, /invalid acceptance publish/);
  const app = makePolicy(BASE);
  delete app.acceptance.publish.verifier;
  app.acceptance.publish.verifierApp = 123456;
  assert.equal(rc.validatePolicy(app), app);
});
test('source is archived from an isolated repository: a hostile checkout (replace refs, rewritten remote) cannot substitute it', async (t) => {
  const ctx = await world(t, { poison: true });
  assert.equal(await rc.run('git', ['show', `${ctx.sourceSha}:backend/requirements.txt`], ctx.repo, { env: GIT_ENV }), 'evil-package', 'the poisoned checkout really would substitute source');
  await ctx.ship('c1');
  assert.equal(await rc.run('tar', ['-xOf', path.join(ctx.dir('c1'), 'source.tar'), 'backend/requirements.txt'], ctx.root), 'fastapi');
  const gitCalls = ctx.calls.filter((c) => c.file === 'git' && !c.args.includes('--version') && c.args[0] !== 'init');
  assert(gitCalls.length >= 6);
  for (const call of gitCalls) {
    assert.equal(call.options.env.GIT_NO_REPLACE_OBJECTS, '1', call.args.join(' '));
    assert.equal(call.options.env.GIT_CONFIG_GLOBAL, '/dev/null');
    assert.equal(call.options.env.GIT_CONFIG_SYSTEM, '/dev/null');
    assert.match(call.options.env.GIT_DIR, /\/\.git-[^/]+\/repo$/);
    assert.notEqual(call.cwd, ctx.repo, 'no source operation runs in the Task checkout');
  }
  assert(gitCalls.some((c) => c.args.includes('fetch') && c.args.includes('transfer.fsckObjects=true')));
  const evidence = await readJson(path.join(ctx.dir('c1'), 'checks.json'));
  assert.equal(evidence.sourceProvenance.tree, await rc.run('git', ['rev-parse', `${ctx.sourceSha}^{tree}`], ctx.remoteRepo, { env: GIT_ENV }));
  assert.equal(evidence.sourceProvenance.replaceObjects, 'disabled');
  assert.equal(evidence.sourceProvenance.isolatedRepository, true);
  assert(!(await readdir(ctx.dir('c1'))).some((n) => n.startsWith('.git-')), 'the scratch repository is removed');
  assert.equal((await rc.run('git', ['rev-list', '--parents', '-n', '1', ctx.mergeSha], ctx.remoteRepo, { env: GIT_ENV })).split(' ').length, 3, 'a genuine two-parent merge');
});
test('production-state is uncertain before the first live mutation and the previous release is never reported as current meanwhile', async (t) => {
  const ctx = await world(t);
  await ctx.ship('c1');
  await ctx.deploy('c1');
  assert.equal((await rc.productionStatus(ctx.trust)).deployedSha, ctx.sourceSha);
  await ctx.ship('c2');
  let during = null;
  let state = null;
  ctx.hooks.stop = async () => {
    during = await rc.productionStatus(ctx.trust);
    state = await readJson(path.join(ctx.policy.target.receiptsRoot, 'production-state.json'));
  };
  await ctx.deploy('c2');
  assert.equal(during.status, 'deploying');
  assert.equal(during.deployedSha, null);
  assert.match(during.summary, /uncertain/);
  assert.equal(state.uncertain, true);
  assert.equal(state.candidateId, 'c2');
  assert.equal((await rc.productionStatus(ctx.trust)).candidateId, 'c2');
  // Failing before any live mutation restores the previous record, because nothing changed.
  const after = await world(t);
  await after.ship('c1');
  await after.deploy('c1');
  await after.ship('c2');
  const expires = Date.parse((await readJson(path.join(after.job('c2'), 'approval.json'))).expiresAt);
  await assert.rejects(after.deploy('c2', { now: () => (after.events.filter((e) => e.op === 'create').length >= 2 ? expires + 1 : Date.now()) }), /expired/);
  const restored = await rc.productionStatus(after.trust);
  assert.equal(restored.candidateId, 'c1');
  assert.equal(restored.status, 'deployed');
  assert.equal(restored.latestJob.status, 'failed');
});
test('expiry is rechecked immediately before each irreversible step: an expired step is not taken and success is never recorded', async (t) => {
  const afterStop = await world(t, { previous: true });
  await afterStop.ship('c1');
  const expires = Date.parse((await readJson(path.join(afterStop.job('c1'), 'approval.json'))).expiresAt);
  await assert.rejects(afterStop.deploy('c1', { now: () => (afterStop.events.some((e) => e.op === 'stop') ? expires + 1 : Date.now()) }), /expired/);
  assert.deepEqual(afterStop.remoteOps().filter((op) => ['stop', 'update', 'rename', 'start'].includes(op)), ['stop']);
  assert.equal((await afterStop.receipt('c1')).status, 'production_incomplete');
  assert.equal((await rc.productionStatus(afterStop.trust)).deployedSha, null);
  const beforeStart = await world(t, { previous: true });
  await beforeStart.ship('c1');
  const lapse = Date.parse((await readJson(path.join(beforeStart.job('c1'), 'approval.json'))).expiresAt);
  await assert.rejects(beforeStart.deploy('c1', { now: () => (beforeStart.events.filter((e) => e.op === 'rename').length >= 2 ? lapse + 1 : Date.now()) }), /expired/);
  assert(!beforeStart.remoteOps().includes('start'), 'the replacement was never started after the approval lapsed');
  const receipt = await beforeStart.receipt('c1');
  assert.equal(receipt.status, 'production_incomplete');
  assert.equal(receipt.deployedSha, null);
});
test('an existing public route is withdrawn before the replacement can start and restored only after it is proven', async (t) => {
  const ctx = await world(t, { exposure: 'public', previous: true, admins: true });
  ctx.cf.config.ingress.splice(1, 0, { hostname: 'app.example.test', service: 'http://192.0.2.10:3000' });
  const base = structuredClone(ctx.cf.config);
  await ctx.ship('c1');
  const plan = await readJson(path.join(ctx.dir('c1'), 'ingress-plan.json'));
  assert.equal(plan.action, 'replace');
  assert(!plan.safe.ingress.some((rule) => rule.hostname === 'app.example.test'));
  assert.deepEqual(plan.planned, plan.base);
  let routedAtStart = null;
  ctx.hooks.start = async () => { routedAtStart = ctx.cf.config.ingress.some((rule) => rule.hostname === 'app.example.test'); };
  const result = await ctx.deploy('c1');
  assert.equal(routedAtStart, false, 'the replacement never starts while the public route points at it');
  const puts = ctx.events.map((e, i) => [e, i]).filter(([e]) => e.op === 'cf:PUT').map(([, i]) => i);
  assert.equal(puts.length, 2);
  assert(puts[0] < ctx.events.findIndex((e) => e.op === 'stop'), 'withdrawn before the old container is stopped');
  assert(puts[1] > ctx.events.findIndex((e) => e.op === 'start'), 'restored only after the replacement started and was proven');
  assert.deepEqual(rc.normalizeConfig(ctx.cf.config), rc.normalizeConfig(base));
  assert.equal(result.ingress.withdrawn, true);
  assert.equal(result.ingress.applied, true);
  assertVerifiedBeforeMutations(ctx.events);
  const failing = await world(t, { exposure: 'public', previous: true, admins: true });
  failing.cf.config.ingress.splice(1, 0, { hostname: 'app.example.test', service: 'http://192.0.2.10:3000' });
  await failing.ship('c1');
  failing.host.flags.wrongImageOnStart = true;
  await assert.rejects(failing.deploy('c1'), /container uses image/);
  assert(!failing.cf.config.ingress.some((rule) => rule.hostname === 'app.example.test'), 'a failed replacement leaves the route withdrawn, never exposed');
  assert.equal(failing.events.filter((e) => e.op === 'cf:PUT').length, 1);
  assert.equal((await failing.receipt('c1')).ingress.withdrawn, true);
});
test('without a provider precondition a concurrent Cloudflare write is detected and the route is withdrawn again', async (t) => {
  const ctx = await world(t, { exposure: 'public', admins: true });
  await ctx.ship('c1');
  ctx.cf.bump = [2]; // another writer slipped in between our read and our write
  await assert.rejects(ctx.deploy('c1'), /concurrent writer is suspected.*ingress retracted to the signed route-absent configuration/);
  const receipt = await ctx.receipt('c1');
  assert.equal(receipt.status, 'production_incomplete');
  assert.equal(receipt.deployedSha, null);
  assert.equal(receipt.ingress.singleWriterAttested, true);
  assert.equal(receipt.ingress.retraction.retracted, true);
  assert(!ctx.cf.config.ingress.some((rule) => rule.hostname === 'app.example.test'));
  const approval = await readJson(path.join(ctx.dir('c1'), 'approval.json'));
  assert.equal(approval.ingress.singleWriterAttested, true, 'the operator attestation is part of what was signed');
});
test('sandbox: source, installs and the gate run in a credential-free, capped container; the gate has no network', async (t) => {
  process.env.TF_HOST_SECRET_SENTINEL = 'sentinel-host-secret-4242';
  t.after(() => { delete process.env.TF_HOST_SECRET_SENTINEL; });
  const ctx = await world(t, { exposure: 'public', admins: true });
  await ctx.prepare('c1');
  const dir = ctx.dir('c1');
  const runs = ctx.docker.filter((d) => d.side === 'local' && d.args[0] === 'run' && d.args.includes('io.tracefinity.release.gate=1')).map((d) => d.args);
  assert(runs.length >= 8);
  const home = os.userInfo().homedir;
  const forbidden = [ctx.policy.target.ssh.identityFile, path.join(ctx.root, 'cf-token'), ctx.policy.target.receiptsRoot, '/var/run', 'docker.sock', `${home}/.ssh`, `${home}/.config`, `${home}/.docker`, 'SSH_AUTH_SOCK', 'sentinel-host-secret-4242'];
  const allowedKeys = ['PATH', 'HOME', 'LANG', 'LC_ALL', 'CI', 'COREPACK_HOME', 'COREPACK_ENABLE_DOWNLOAD_PROMPT', 'PNPM_HOME', 'PIP_DISABLE_PIP_VERSION_CHECK', 'PIP_NO_CACHE_DIR', 'npm_config_cache', 'U2NET_HOME'];
  for (const args of runs) {
    assert(hasSequence(args, '--cap-drop', 'ALL') && args.includes('--read-only') && hasSequence(args, '--security-opt', 'no-new-privileges:true'));
    assert(!args.includes('--privileged') && !args.includes('--pid') && !args.includes('--volumes-from') && !args.includes('--device') && !args.includes('host'));
    assert(hasSequence(args, '--memory', '8g') && hasSequence(args, '--memory-swap', '8g') && hasSequence(args, '--cpus', '4') && hasSequence(args, '--pids-limit', '2048'));
    assert(hasSequence(args, '--network', args.includes('/gate/check') ? 'none' : 'bridge'), args.includes('/gate/check') ? 'the gate has no network' : 'installs use the bridge network, never the host network');
    const mounts = args.filter((a, i) => args[i - 1] === '--mount').map((m) => Object.fromEntries(m.split(',').map((x) => x.split('='))));
    assert(mounts.length >= 3);
    for (const m of mounts) {
      assert(['/work', '/tools', '/etc/passwd', '/gate/check'].includes(m.target), m.target);
      assert(m.type === 'bind' && m.source.startsWith(`${dir}${path.sep}`), `mount source ${m.source} is inside the candidate`);
    }
    const env = args.filter((a, i) => args[i - 1] === '--env').map((e) => e.split('='));
    assert(env.every(([key]) => allowedKeys.includes(key)));
    assert(args.includes('HOME=/tmp'));
    for (const bad of forbidden) assert(!args.some((a) => a.includes(bad)), `sandbox argument leaks ${bad}`);
  }
  assert(!ctx.calls.some((c) => JSON.stringify(c.options?.env ?? {}).includes('sentinel-host-secret-4242')), 'no host environment value is handed to any child');
  const evidence = await readJson(path.join(dir, 'checks.json'));
  assert.equal(evidence.gateSandbox.gateNetwork, 'none');
  assert.match(evidence.gateSandbox.image, /^sha256:[a-f0-9]{64}$/);
  assert(!(await exists(path.join(dir, 'gate-passwd'))), 'scratch is removed');
});
test('sandbox mount guard refuses anything outside the candidate or covering a host secret or control socket', () => {
  const root = '/tmp/tf-guard-fixture';
  const dir = `${root}/repo/.approval/c1`;
  const base = (policy = makePolicy(root, 'public')) => ({ image: `sha256:${'a'.repeat(64)}`, network: 'none', workSource: `${dir}/source`, toolsDir: `${dir}/tools`, passwdFile: `${dir}/gate-passwd`, argv: ['true'], candidateDir: dir, policy });
  assert(rc.gateRunArgs(base()).includes('--cap-drop'));
  const refuses = (overrides, pattern) => assert.throws(() => rc.gateRunArgs({ ...base(), ...overrides }), pattern);
  refuses({ workSource: os.userInfo().homedir }, /outside the candidate/);
  refuses({ workSource: root }, /outside the candidate/);
  refuses({ workSource: path.dirname(dir) }, /outside the candidate/);
  refuses({ toolsDir: '/var/run' }, /outside the candidate/);
  refuses({ network: 'host' }, /bridge or none/);
  refuses({ image: 'node:20' }, /invalid sandbox step/);
  refuses({ workdir: '/etc' }, /invalid sandbox step/);
  for (const [field, set] of [['identityFile', (p, v) => { p.target.ssh.identityFile = v; }], ['receiptsRoot', (p, v) => { p.target.receiptsRoot = v; }],
    ['apiTokenFile', (p, v) => { p.target.exposure.ingress.apiTokenFile = v; }], ['cookieFile', (p, v) => { p.acceptance.cookieFile = v; }]]) {
    const policy = makePolicy(root, 'public');
    set(policy, `${dir}/source/${field}`);
    refuses({ policy }, /would expose a host secret/);
  }
});
test('policy: storagePath and envFile obey the same dangerous-host-path deny list as extra mounts', () => {
  const bad = (mutate) => { const policy = structuredClone(makePolicy(BASE)); mutate(policy); assert.throws(() => rc.validatePolicy(policy), /may not be a system or socket path|not allowed/); };
  for (const p of ['/var/run/x', '/run/docker.sock', '/etc/tracefinity', '/proc/1', '/boot/config', '/usr/local/data', '/var/lib/docker/volumes']) {
    bad((policy) => { policy.target.container.storagePath = p; });
    bad((policy) => { policy.target.container.envFile = p; });
    bad((policy) => { policy.target.container.mounts[0].hostPath = p; });
  }
});
test('an unreadable production-state reports a generic error without paths or file contents', async (t) => {
  const ctx = await world(t);
  await writeFile(path.join(ctx.policy.target.receiptsRoot, 'production-state.json'), '{"secret":"TOPSECRET-123" not json');
  const status = await rc.productionStatus(ctx.trust);
  assert.equal(status.status, 'unknown');
  const text = JSON.stringify(status);
  for (const leak of ['TOPSECRET', ctx.root, 'position', 'Unexpected']) assert(!text.includes(leak), leak);
});

// ---------------------------------------------------------------------------------------------
// `.ade/config.json` releaseStatus: an older preserved Release checkout has no scripts/release-controller.mjs.
// The command runs only a controller whose SHA-256 equals the pin in the base policy.
// ---------------------------------------------------------------------------------------------
const ADE_CONFIG = JSON.parse(await readFile(fileURLToPath(new URL('../.ade/config.json', import.meta.url)), 'utf8'));
const STATUS_ARGV = ADE_CONFIG.releaseStatus;
/** A fixture controller; its hash is injected as the pin so no deployed policy or key is involved. */
const fake = (label, body = '') => `console.log(JSON.stringify({ label: ${JSON.stringify(label)}, args: process.argv.slice(2) }));\n${body}`;
const PINNED = fake('pinned');
/** Run the repository's releaseStatus argv exactly as Station Zero does (spawned directly, working directory the Task checkout), with the pin replaced. */
const runStatus = (cwd, pin = sha256(PINNED)) => spawnSync(process.execPath, [...STATUS_ARGV.slice(1, -1), pin], { cwd, encoding: 'utf8', env: { PATH: process.env.PATH } });
const checkout = async (t) => {
  const dir = await realpath(await mkdtemp(path.join(os.tmpdir(), 'tfstatus-')));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
};
const plantScript = async (dir, source) => {
  await mkdir(path.join(dir, 'scripts'), { recursive: true });
  await writeFile(path.join(dir, 'scripts/release-controller.mjs'), source);
};
const plantCandidate = async (dir, id, source = PINNED) => {
  const candidate = path.join(dir, '.approval', id);
  await mkdir(candidate, { recursive: true });
  await writeFile(path.join(candidate, 'release-controller.mjs'), source);
  return path.join(candidate, 'release-controller.mjs');
};
const refused = (result, pattern) => {
  assert.equal(result.status, 1);
  assert.equal(result.stdout, ''); // nothing ran and nothing was reported as a status
  assert.match(result.stderr, pattern);
};

test('releaseStatus is an argv run by node, pinned to a controller hash that is the committed controller', async () => {
  assert.equal(STATUS_ARGV[0], 'node');
  assert.equal(STATUS_ARGV.length, 4);
  assert.equal(STATUS_ARGV[1], '-e');
  assert.match(STATUS_ARGV[3], /^[a-f0-9]{64}$/);
  // Refresh the pin in .ade/config.json whenever scripts/release-controller.mjs changes.
  assert.equal(STATUS_ARGV[3], sha256(await readFile(CONTROLLER)), 'releaseStatus pin is stale: update it to the SHA-256 of scripts/release-controller.mjs');
  assert.deepEqual(ADE_CONFIG.releaseSigning.submit, ['node', '.approval/{candidate}/release-controller.mjs', 'submit', '--candidate', '{candidate}', '--execute']);
});
test('releaseStatus runs the checkout controller when it matches the pin, ahead of candidate copies', async (t) => {
  const dir = await checkout(t);
  await plantScript(dir, PINNED);
  await plantCandidate(dir, 'c1', fake('candidate-with-other-bytes'));
  const result = runStatus(dir);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { label: 'pinned', args: ['status'] }); // no candidate argument: it reports what is live
});
test('releaseStatus in an older checkout runs a candidate copy that matches the pin and skips newer ones that do not', async (t) => {
  const dir = await checkout(t);
  const older = await plantCandidate(dir, 'c-old', PINNED);
  await utimes(older, new Date(Date.now() - 120_000), new Date(Date.now() - 120_000));
  await plantCandidate(dir, 'c-newest-but-different', fake('different'));
  const result = runStatus(dir);
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { label: 'pinned', args: ['status'] });
});
test('releaseStatus never runs a checkout controller that differs from the pin, and uses a matching candidate copy instead when one exists', async (t) => {
  const dir = await checkout(t);
  await plantScript(dir, fake('edited-checkout-copy'));
  refused(runStatus(dir), /matches the SHA-256 pinned in \.ade\/config\.json; none was run/);
  await plantCandidate(dir, 'c-ok', PINNED);
  const result = runStatus(dir);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).label, 'pinned');
});
test('releaseStatus never runs candidate copies that differ from the pin, are symlinks, or sit outside a candidate directory', async (t) => {
  const dir = await checkout(t);
  const real = await plantCandidate(dir, 'c-real', PINNED);
  await plantCandidate(dir, 'c-edited', `${PINNED}// edited\n`);
  await rm(real); // the only matching bytes now live outside the approval tree, reachable only through a symlink
  const target = path.join(dir, 'elsewhere.mjs');
  await writeFile(target, PINNED);
  await mkdir(path.join(dir, '.approval', 'c-link'), { recursive: true });
  await symlink(target, path.join(dir, '.approval', 'c-link', 'release-controller.mjs'));
  await writeFile(path.join(dir, '.approval', 'release-controller.mjs'), PINNED); // a file directly under .approval is not a candidate
  refused(runStatus(dir), /matches the SHA-256 pinned in \.ade\/config\.json; none was run/);
});
test('releaseStatus without any controller fails with an actionable single message and no JSON on stdout', async (t) => {
  const dir = await checkout(t);
  refused(runStatus(dir), /bootstrap it as described in docs\/signed-deployment\.md/);
  await mkdir(path.join(dir, '.approval', 'failed-attempt'), { recursive: true }); // a preparation that never produced a controller copy
  refused(runStatus(dir), /bootstrap it as described in docs\/signed-deployment\.md/);
});
test('releaseStatus refuses a missing or malformed pin without running anything', async (t) => {
  const dir = await checkout(t);
  await plantScript(dir, PINNED);
  for (const pin of ['', 'nothex', sha256(PINNED).toUpperCase(), sha256(PINNED).slice(1)]) refused(runStatus(dir, pin), /missing its pinned controller SHA-256/);
  const noPin = spawnSync(process.execPath, STATUS_ARGV.slice(1, -1), { cwd: dir, encoding: 'utf8', env: { PATH: process.env.PATH } });
  refused(noPin, /missing its pinned controller SHA-256/);
});
test('releaseStatus passes the controller exit status and stderr through and leaves no scratch copy', async (t) => {
  const dir = await checkout(t);
  const source = 'console.error("policy unreadable"); console.error(process.argv[1]); process.exitCode = 3;\n';
  await plantScript(dir, source);
  const result = runStatus(dir, sha256(source));
  assert.equal(result.status, 3);
  assert.match(result.stderr, /policy unreadable/);
  const scratch = result.stderr.trim().split('\n').at(-1);
  assert(!(await exists(scratch)), 'the verified copy is removed after the run');
});
