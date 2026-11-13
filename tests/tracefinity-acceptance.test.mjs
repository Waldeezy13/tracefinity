// Deterministic tests for scripts/tracefinity-acceptance.mjs. A local fake of
// the Tracefinity API (and of the GitHub API) stands in for the deployed app:
// no real service, credential, key or network is touched.
// Run: node --test tests/tracefinity-acceptance.test.mjs

import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  CONTRACT,
  Refusal,
  assertNoLeak,
  assessRecord,
  contractSha256,
  inspectBinaryStl,
  loadCookie,
  loadToken,
  main,
  parseArgs,
  readProtectedFile,
  rulesetWriterProblems,
  runningImageMatches,
  validateTarget,
  updateRuleProblems,
  writerRestrictionProblems,
} from '../scripts/tracefinity-acceptance.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const COOKIE = 'cookie-value-0123456789abcdef-AAAA';
const TOKEN = 'ghp_0123456789abcdefghijklmnop';
const SHA = 'a'.repeat(40);
const DIGEST = `sha256:${'b'.repeat(64)}`;
const OTHER_DIGEST = `sha256:${'d'.repeat(64)}`;
const NOW = new Date('2026-11-13T13:00:00.000Z');
const VERIFIER = 'verifier-bot';
const APP_ID = 424242;

const tmp = mkdtempSync(path.join(os.tmpdir(), 'tracefinity-acceptance-test-'));
test.after(() => rmSync(tmp, { recursive: true, force: true }));

function secretFile(name, content, mode = 0o600) {
  const file = path.join(tmp, name);
  writeFileSync(file, content);
  chmodSync(file, mode);
  return file;
}

const COOKIE_FILE = secretFile('cookie', `${COOKIE}\n`);
const TOKEN_FILE = secretFile('token', `${TOKEN}\n`);

// ---------------------------------------------------------------------------
// STL fixtures: a real closed box, subdivided so shared edges are exact
// ---------------------------------------------------------------------------

function boxTriangles(X, Y, Z, n = 5) {
  const faces = [
    { o: [0, 0, Z], u: [X, 0, 0], v: [0, Y, 0] },
    { o: [0, 0, 0], u: [0, Y, 0], v: [X, 0, 0] },
    { o: [X, 0, 0], u: [0, Y, 0], v: [0, 0, Z] },
    { o: [0, 0, 0], u: [0, 0, Z], v: [0, Y, 0] },
    { o: [0, Y, 0], u: [0, 0, Z], v: [X, 0, 0] },
    { o: [0, 0, 0], u: [X, 0, 0], v: [0, 0, Z] },
  ];
  const triangles = [];
  for (const { o, u, v } of faces) {
    const at = (i, j) => o.map((c, k) => c + (u[k] * i) / n + (v[k] * j) / n);
    for (let i = 0; i < n; i += 1) {
      for (let j = 0; j < n; j += 1) {
        const a = at(i, j);
        const b = at(i + 1, j);
        const c = at(i + 1, j + 1);
        const d = at(i, j + 1);
        triangles.push([a, b, c], [a, c, d]);
      }
    }
  }
  return triangles;
}

function stlFrom(triangles) {
  const buf = Buffer.alloc(84 + 50 * triangles.length);
  buf.writeUInt32LE(triangles.length, 80);
  triangles.forEach((tri, i) => {
    tri.forEach((vertex, v) => vertex.forEach((value, axis) => buf.writeFloatLE(value, 84 + i * 50 + 12 + v * 12 + axis * 4)));
  });
  return buf;
}

const boxStl = (height) => stlFrom(boxTriangles(83.5, 83.5, height));

/** Plausible-looking but not a solid: the same few triangles repeated. */
function repeatedTrianglesStl() {
  const base = [[[0, 0, 0], [83.5, 83.5, 28], [3, 2, 1]], [[0, 0, 0], [83.5, 0, 0], [0, 83.5, 28]]];
  return stlFrom(Array.from({ length: 120 }, (_, i) => base[i % 2]));
}

const area = (points) => Math.abs(points.reduce((sum, p, i) => {
  const q = points[(i + 1) % points.length];
  return sum + (p.x * q.y - q.x * p.y);
}, 0) / 2);

// ---------------------------------------------------------------------------
// A fake Tracefinity
// ---------------------------------------------------------------------------

async function startApp(overrides = {}) {
  const state = {
    version: SHA,
    setupRequired: false,
    mode: 'native',
    cookieValid: true,
    isAdmin: false,
    anonymousOpen: new Set(),
    failGenerate: false,
    generateStatus: null,
    generateDetail: null,
    generateDelayMs: 0,
    unpocketed: false,
    malformedStl: false,
    leakDelete: false,
    meFailFrom: 0,
    meDestroyFrom: 0,
    meCalls: 0,
    bins: new Map(),
    log: [],
    ...overrides,
  };
  let counter = 0;
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      const cookieHeader = req.headers.cookie ?? '';
      const hasCookie = cookieHeader.length > 0;
      const authed = cookieHeader === `tracefinity_auth=${COOKIE}` && state.cookieValid;
      state.log.push({ method: req.method, path: url.pathname, search: url.search, hasCookie });
      const json = (status, body) => {
        res.writeHead(status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(body));
      };
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : null;
      const p = url.pathname;
      // the real combined container only routes /api/ and /storage/ to the backend
      if (!p.startsWith('/api/') && !p.startsWith('/storage/')) return json(404, { detail: 'not found' });
      if (p === '/api/version') return state.version === null ? json(404, {}) : json(200, { version: state.version });
      if (p === '/api/auth/status') return json(200, { mode: state.mode, setup_required: state.setupRequired, authenticated: authed });
      const open = state.anonymousOpen.has(p);
      if (!authed && !open) return json(401, { detail: 'authentication required' });
      if (p === '/api/auth/me') {
        state.meCalls += 1;
        if (state.meDestroyFrom && state.meCalls >= state.meDestroyFrom) return req.socket.destroy();
        if (state.meFailFrom && state.meCalls >= state.meFailFrom) return json(500, { detail: 'boom' });
        return json(200, { id: 'acct-1', email: 'x', is_admin: state.isAdmin, disabled: false });
      }
      if (p === '/api/admin/storage-stats') return state.isAdmin ? json(200, {}) : json(403, {});
      if (p === '/api/sessions') return json(200, { sessions: [] });
      if (p === '/api/tools') return json(200, { tools: [] });
      if (p === '/api/bin-projects') return json(200, { projects: [] });
      if (p === '/api/bins' && req.method === 'GET') {
        return json(200, { bins: [...state.bins.values()].map((b) => ({ id: b.id, has_stl: b.hasStl })) });
      }
      if (p === '/api/bins' && req.method === 'POST') {
        counter += 1;
        const id = `00000000-0000-4000-8000-${String(counter).padStart(12, '0')}`;
        state.bins.set(id, { id, name: body.name, placed: [], hasStl: false, generating: false, deletedWhileGenerating: false });
        return json(200, { id });
      }
      const bin = /^\/api\/bins\/([0-9a-f-]{36})(\/generate)?$/.exec(p);
      if (bin) {
        const found = state.bins.get(bin[1]);
        if (!found) return json(404, { detail: 'bin not found' });
        if (bin[2] && req.method === 'POST') {
          if (state.failGenerate) return json(500, { detail: 'boom' });
          if (found.placed.length === 0) return json(400, { detail: 'bin has no tools placed' });
          const finish = () => {
            if (state.generateStatus) {
              if (state.generateStatus === 504) {
                res.writeHead(504, { 'content-type': 'text/html' });
                return res.end('<html>504 Gateway Time-out</html>');
              }
              return json(state.generateStatus, state.generateDetail ? { detail: state.generateDetail } : {});
            }
            found.generating = false;
            found.hasStl = true;
            return json(200, { stl_url: '/x' });
          };
          found.generating = true;
          // the worker keeps going after a client gives up: output is only produced at the end
          if (state.generateDelayMs > 0) {
            setTimeout(() => {
              found.generating = false;
              if (!state.bins.has(bin[1])) found.deletedWhileGenerating = true;
              found.hasStl = true;
              try { finish(); } catch { /* client already gone */ }
            }, state.generateDelayMs);
            return undefined;
          }
          return finish();
        }
        if (req.method === 'PUT') {
          found.placed = body.placed_tools;
          return json(200, { status: 'ok' });
        }
        if (req.method === 'DELETE') {
          state.log[state.log.length - 1].deleted = bin[1];
          if (!state.leakDelete) state.bins.delete(bin[1]);
          return json(200, { status: 'deleted' });
        }
        return json(200, found);
      }
      const file = /^\/api\/files\/bins\/([0-9a-f-]{36})\/bin\.stl$/.exec(p);
      if (file) {
        const found = state.bins.get(file[1]);
        if (!found || !found.hasStl) return json(404, {});
        res.writeHead(200, { 'content-type': 'application/sla' });
        if (state.malformedStl) return res.end(repeatedTrianglesStl());
        // a bigger pocket removes more material (a lower solid in this fake)
        const pocket = state.unpocketed ? 0 : area(found.placed[0].points);
        return res.end(boxStl(28 - pocket / 50));
      }
      return json(404, {});
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  return { state, origin, close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); }) };
}

function targetFor(origin, extra = {}) {
  return {
    candidateId: 'cand-1',
    environment: 'production',
    state: 'deployed',
    sourceSha: SHA,
    imageDigest: DIGEST,
    appVersion: SHA,
    approvalSha256: 'c'.repeat(64),
    deployedAt: '2026-11-13T12:00:00.000Z',
    publicOrigin: origin,
    allowLoopbackHttp: true,
    cookieFile: COOKIE_FILE,
    ...extra,
  };
}

/**
 * The release controller's four accessors. The backend log is the fake app's own
 * request log, so a nonce is only "seen" if the request really reached that app.
 */
function providerFor(raw, runtime, { app = null, routeProof = null, confirm = null } = {}) {
  const calls = { targets: 0, inspects: 0, proofs: 0, confirms: 0 };
  return {
    calls,
    loadAcceptanceTarget: async () => { calls.targets += 1; return raw; },
    inspectRunningImage: async () => {
      calls.inspects += 1;
      return typeof runtime === 'function' ? runtime(calls.inspects) : (runtime ?? { running: true, imageId: DIGEST, repoDigests: [] });
    },
    proveRouteBinding: async ({ candidateId }) => {
      calls.proofs += 1;
      if (routeProof) return routeProof(calls.proofs, candidateId);
      return { bound: true, candidateId, containerId: 'c1', imageId: DIGEST, ingressConfigSha256: 'e'.repeat(64) };
    },
    confirmBackendRequest: async ({ marker, sinceIso }) => {
      calls.confirms += 1;
      assert.match(marker, /^acceptance_nonce=[0-9a-f]{32}$/);
      assert.ok(Number.isFinite(Date.parse(sinceIso)));
      if (confirm) return confirm(calls.confirms, marker);
      if (app?.state) return { seen: app.state.log.some((e) => e.search.includes(marker)) };
      return { seen: true };
    },
  };
}

async function run(app, { runtime, raw, argv = [], routeProof, confirm, generationTimeoutMs } = {}) {
  const lines = { out: [], err: [] };
  const provider = providerFor(raw ?? targetFor(app.origin), runtime, { app, routeProof, confirm });
  const code = await main(['run', '--candidate', 'cand-1', ...argv], {
    provider, now: () => NOW, out: (t) => lines.out.push(t), err: (t) => lines.err.push(t), retryDelayMs: 0, generationTimeoutMs,
  });
  const record = lines.out.length ? JSON.parse(lines.out.join('\n')) : null;
  return { code, record, lines, provider };
}

// ---------------------------------------------------------------------------
// End-to-end happy path
// ---------------------------------------------------------------------------

test('an authenticated end-to-end run bound to the deployed candidate is eligible and leaks nothing', async () => {
  const app = await startApp();
  try {
    const { code, record, lines, provider } = await run(app);
    assert.equal(code, 0, lines.err.join('\n'));
    assert.equal(record.authenticated.state, 'passed');
    assert.deepEqual(record.authenticated.required, CONTRACT.requiredChecks);
    assert.deepEqual(record.authenticated.failed, []);
    assert.deepEqual(record.authenticated.skipped, []);
    assert.equal(record.candidateId, 'cand-1');
    assert.equal(record.authenticated.boundTo.sourceSha, SHA);
    assert.deepEqual(record.authenticated.boundTo.imageDigests, { tracefinity: DIGEST });
    assert.equal(record.authenticated.boundTo.contractSha256, contractSha256());
    assert.equal(record.authenticated.boundTo.runId, record.preflight.runId);
    assert.equal(record.health, 'pass');
    assert.ok(!('overall' in record));
    // the running image is read before and after the authenticated work; the route is proved before and after
    assert.equal(provider.calls.inspects, 2);
    assert.equal(provider.calls.proofs, 2);
    // two synthetic bins (large and small pocket) were created, generated, downloaded and removed
    assert.equal(app.state.bins.size, 0);
    assert.equal(app.state.log.filter((e) => e.method === 'POST' && e.path === '/api/bins').length, 2);
    assert.equal(app.state.log.filter((e) => e.method === 'DELETE').length, 2);
    // never logs out, never touches setup or login
    assert.ok(!app.state.log.some((e) => e.path.startsWith('/api/auth/') && !['/api/auth/status', '/api/auth/me'].includes(e.path)));
    // only routes the combined container actually forwards to the backend are used
    assert.ok(app.state.log.every((e) => e.path.startsWith('/api/')), 'every probe uses a routed /api/ path');
    // nothing sensitive in output or record
    const everything = `${lines.out.join('\n')}\n${lines.err.join('\n')}`;
    for (const secret of [COOKIE, app.origin, '127.0.0.1', os.tmpdir()]) assert.ok(!everything.includes(secret), `output must not contain ${secret}`);
  } finally {
    await app.close();
  }
});

test('the cookie is only ever sent after the identity and route gates pass, and never to unauthenticated probes', async () => {
  const app = await startApp();
  try {
    await run(app);
    const firstCookie = app.state.log.findIndex((e) => e.hasCookie);
    const lastAnonymousVersion = app.state.log.findLastIndex((e) => e.path === '/api/version');
    assert.ok(lastAnonymousVersion >= 0 && firstCookie > lastAnonymousVersion);
    assert.ok(app.state.log.slice(0, firstCookie).every((e) => !e.hasCookie));
    assert.ok(app.state.log.some((e) => e.path === '/api/version' && /acceptance_nonce=[0-9a-f]{32}/.test(e.search)), 'a nonce probe went through the route');
  } finally {
    await app.close();
  }
});

test('a dry run and a publish are independent fresh runs; publish writes only what it just measured', async () => {
  const app = await startApp();
  const gh = await startGithub();
  try {
    const outDir = path.join(tmp, 'out-roundtrip');
    const raw = targetFor(app.origin, { publish: { repository: 'owner/repo', stateBranch: 'production-state', tokenFile: TOKEN_FILE, verifier: VERIFIER, githubApiUrl: gh.origin } });
    const dry = await run(app, { raw, argv: ['--out-dir', outDir] });
    assert.equal(dry.code, 0, dry.lines.err.join('\n'));
    const dryRecord = JSON.parse(readFileSync(path.join(outDir, 'cand-1.json'), 'utf8'));
    assert.ok(readFileSync(path.join(outDir, 'cand-1.evidence.json'), 'utf8').includes('bin-generate-roundtrip'));
    assert.equal(gh.calls.filter((c) => c.method !== 'GET').length, 0, 'a dry run writes nothing to the repository');

    const requestsBefore = app.state.log.length;
    const lines = { err: [] };
    const published = await main(['publish', '--candidate', 'cand-1'], {
      provider: providerFor(raw, undefined, { app }), now: () => NOW, out: () => {}, err: (t) => lines.err.push(t), fetchImpl: globalThis.fetch, retryDelayMs: 0,
    });
    assert.equal(published, 0, lines.err.join('\n'));
    assert.ok(app.state.log.length > requestsBefore, 'publish performed its own authenticated run');
    const put = gh.calls.find((c) => c.method === 'PUT');
    assert.equal(put.body.branch, 'production-state');
    assert.equal(put.path, '/repos/owner/repo/contents/acceptance/cand-1.json');
    assert.ok(gh.calls.every((c) => c.auth === `Bearer ${TOKEN}`));
    // never creates or moves a ref
    assert.ok(gh.calls.every((c) => !/\/git\/refs|\/branches\/[^/]+\/(rename|merge)/.test(c.path) && c.method !== 'DELETE' && c.method !== 'PATCH'));
    const stored = JSON.parse(gh.stored);
    assert.equal(stored.candidateId, 'cand-1');
    assert.equal(stored.authenticated.state, 'passed');
    assert.notEqual(stored.preflight.runId, dryRecord.preflight.runId, 'the stored record is from a new run, not the dry run');
    assertNoLeak(gh.stored, [COOKIE, TOKEN, app.origin]);
  } finally {
    await app.close();
    await gh.close();
  }
});

// ---------------------------------------------------------------------------
// Failure semantics
// ---------------------------------------------------------------------------

test('a wrong served build fails the identity gate and the session is never sent', async () => {
  const app = await startApp({ version: 'e'.repeat(40) });
  try {
    const { code, record } = await run(app);
    assert.equal(code, 1);
    assert.equal(record.authenticated.state, 'failed');
    assert.ok(record.authenticated.failed.includes('served-identity'));
    assert.equal(record.preflight.verdict, 'fail');
    assert.ok(record.authenticated.skipped.includes('route-bound'));
    assert.ok(record.authenticated.skipped.includes('bin-generate-roundtrip'));
    assert.ok(app.state.log.every((e) => !e.hasCookie), 'no request carried the cookie');
    assert.equal(app.state.bins.size, 0);
  } finally {
    await app.close();
  }
});

test('a hidden version endpoint cannot prove identity', async () => {
  const app = await startApp({ version: null });
  try {
    const { code, record } = await run(app);
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('served-identity'));
    assert.ok(app.state.log.every((e) => !e.hasCookie));
  } finally {
    await app.close();
  }
});

test('a running image that differs from the receipt digest fails before anything else is trusted', async () => {
  const app = await startApp();
  try {
    const { code, record } = await run(app, { runtime: { running: true, imageId: OTHER_DIGEST, repoDigests: [`registry/x@${OTHER_DIGEST}`] } });
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('running-image'));
    assert.ok(record.authenticated.skipped.includes('served-identity'));
    assert.ok(app.state.log.every((e) => !e.hasCookie));
  } finally {
    await app.close();
  }
});

test('a stopped container is not the deployed candidate', async () => {
  const app = await startApp();
  try {
    const { code, record } = await run(app, { runtime: { running: false, imageId: DIGEST, repoDigests: [] } });
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('running-image'));
  } finally {
    await app.close();
  }
});

test('a running image that changes during the run is not stable', async () => {
  const app = await startApp();
  try {
    const { code, record } = await run(app, { runtime: (n) => ({ running: true, imageId: n === 1 ? DIGEST : OTHER_DIGEST, repoDigests: [] }) });
    assert.equal(code, 1);
    assert.deepEqual(record.authenticated.failed, ['running-image-stable']);
    assert.equal(record.authenticated.state, 'failed');
  } finally {
    await app.close();
  }
});

test('the registry digest of the running image is accepted when it equals the receipt digest', () => {
  assert.equal(runningImageMatches({ running: true, imageId: OTHER_DIGEST, repoDigests: [`registry.example/app@${DIGEST}`] }, DIGEST), true);
  assert.equal(runningImageMatches({ running: true, imageId: OTHER_DIGEST, repoDigests: [`registry.example/app@${OTHER_DIGEST}`] }, DIGEST), false);
  assert.equal(runningImageMatches({ running: true, imageId: 'latest', repoDigests: [] }, DIGEST), false);
});

test('anonymous access to a protected endpoint fails the run', async () => {
  const app = await startApp({ anonymousOpen: new Set(['/api/sessions']) });
  try {
    const { code, record } = await run(app);
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('unauthenticated-refused'));
    assert.equal(record.probe.result, 'fail');
  } finally {
    await app.close();
  }
});

test('an open first-run setup fails the run', async () => {
  const app = await startApp({ setupRequired: true });
  try {
    const { code, record, lines } = await run(app);
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('setup-closed'));
    assert.match(lines.err.join('\n'), /first-run setup is OPEN/);
  } finally {
    await app.close();
  }
});

test('a rejected or expired session fails without asking for credentials, and skips the rest', async () => {
  const app = await startApp({ cookieValid: false });
  try {
    const { code, record, lines } = await run(app);
    assert.equal(code, 1);
    assert.deepEqual(record.authenticated.failed, ['session-authenticated']);
    for (const id of ['least-privilege', 'library-read', 'bin-generate-roundtrip', 'cleanup-verified']) assert.ok(record.authenticated.skipped.includes(id));
    assert.match(lines.err.join('\n'), /fresh protected cookie/);
    assert.ok(!app.state.log.some((e) => e.method === 'POST'));
  } finally {
    await app.close();
  }
});

test('authentication alone is not acceptance: a working /api/auth/me with a failing generation is not eligible', async () => {
  const app = await startApp({ failGenerate: true });
  try {
    const { code, record } = await run(app);
    assert.equal(code, 1);
    assert.ok(record.authenticated.passed.includes('session-authenticated'));
    assert.ok(record.authenticated.failed.includes('bin-generate-roundtrip'));
    assert.equal(record.authenticated.state, 'failed');
    // the server answered, so generation is over and cleanup is safe and verified
    assert.ok(record.authenticated.passed.includes('cleanup-verified'));
    assert.equal(app.state.bins.size, 0);
  } finally {
    await app.close();
  }
});

test('an administrator session is refused', async () => {
  const app = await startApp({ isAdmin: true });
  try {
    const { code, record } = await run(app);
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('least-privilege'));
  } finally {
    await app.close();
  }
});

test('failed cleanup is a failure and names what to remove', async () => {
  const app = await startApp({ leakDelete: true });
  try {
    const { code, record, lines } = await run(app);
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('cleanup-verified'));
    assert.match(lines.err.join('\n'), /remove the leftover synthetic bin/);
  } finally {
    await app.close();
  }
});

test('an unreachable app is a failed run, not a pass', async () => {
  const app = await startApp();
  const origin = app.origin;
  await app.close();
  const { code, record } = await run({ origin });
  assert.equal(code, 1);
  assert.equal(record.health, 'fail');
  assert.notEqual(record.authenticated.state, 'passed');
});

test('no redirect is followed: a redirect from a protected endpoint is not a 401', async () => {
  const server = http.createServer((req, res) => {
    const p = new URL(req.url, 'http://x').pathname;
    const send = (body) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(body); };
    if (p === '/api/version') return send(JSON.stringify({ version: SHA }));
    if (p === '/api/auth/status') return send('{"mode":"native","setup_required":false,"authenticated":false}');
    res.writeHead(302, { location: 'https://elsewhere.invalid/login' });
    return res.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    const { code, record } = await run({ origin });
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('unauthenticated-refused'));
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

// ---------------------------------------------------------------------------
// The public route must reach the inspected container
// ---------------------------------------------------------------------------

test('a route that the controller cannot prove bound sends no credential and fails the run', async () => {
  const app = await startApp();
  try {
    const { code, record, provider } = await run(app, { routeProof: () => { throw new Error('ingress digest changed'); } });
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('route-bound'));
    assert.ok(record.authenticated.skipped.includes('session-authenticated'));
    assert.equal(record.preflight.verdict, 'fail');
    assert.ok(app.state.log.every((e) => !e.hasCookie), 'the session cookie was never sent');
    assert.equal(provider.calls.proofs, 1);
  } finally {
    await app.close();
  }
});

test('a proof for another candidate or another image does not bind the route', async () => {
  for (const proof of [
    (n, candidateId) => ({ bound: true, candidateId: 'cand-9', imageId: DIGEST }),
    (n, candidateId) => ({ bound: true, candidateId, imageId: OTHER_DIGEST }),
    () => ({ bound: false }),
    () => null,
  ]) {
    const app = await startApp();
    try {
      const { code, record } = await run(app, { routeProof: proof });
      assert.equal(code, 1);
      assert.ok(record.authenticated.failed.includes('route-bound'));
      assert.ok(app.state.log.every((e) => !e.hasCookie));
    } finally {
      await app.close();
    }
  }
});

test('a self-reported version through a route whose requests never reach the container is not accepted', async () => {
  const app = await startApp();
  try {
    // a redirected route can answer correctly yet the container never sees the nonce
    const { code, record } = await run(app, { confirm: () => ({ seen: false }) });
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('route-bound'));
    assert.ok(app.state.log.every((e) => !e.hasCookie));
  } finally {
    await app.close();
  }
});

test('a failed or missing final authenticated request fails route-stable even though the first marker was seen', async () => {
  // the first /api/auth/me succeeds and is logged; the final one (the second call) fails
  for (const [name, options, pattern] of [
    ['server error', { meFailFrom: 2 }, /HTTP 500/],
    ['transport error', { meDestroyFrom: 2 }, /transport error/],
  ]) {
    const app = await startApp(options);
    try {
      const { code, record, lines } = await run(app, { confirm: () => ({ seen: true }) });
      assert.equal(code, 1, name);
      assert.deepEqual(record.authenticated.failed, ['route-stable'], name);
      assert.ok(record.authenticated.passed.includes('session-authenticated'), name);
      assert.notEqual(record.authenticated.state, 'passed', name);
      assert.match(lines.err.join('\n'), pattern, name);
      const target = validateTarget(targetFor(app.origin), { candidateId: 'cand-1' });
      assert.equal(assessRecord(record, { target, now: NOW }).eligible, false, name);
    } finally {
      await app.close();
    }
  }
});

test('route-stable needs the final marker seen as well as the first, and is only judged for a session that finished', async () => {
  const app = await startApp();
  try {
    // first marker seen, final marker never seen
    const onlyStart = await run(app, { confirm: (n, marker) => ({ seen: n <= 2 }) });
    assert.equal(onlyStart.code, 1);
    assert.deepEqual(onlyStart.record.authenticated.failed, ['route-stable']);
  } finally {
    await app.close();
  }
  // a session rejected at the start never reaches its final request: route-stable stays skipped, not passed
  const rejected = await startApp({ cookieValid: false });
  try {
    const { code, record } = await run(rejected);
    assert.equal(code, 1);
    assert.ok(record.authenticated.skipped.includes('route-stable'));
    assert.ok(!record.authenticated.passed.includes('route-stable'));
  } finally {
    await rejected.close();
  }
});

test('a route that stops reaching the container during the run fails route-stable', async () => {
  const app = await startApp();
  try {
    const flipped = await run(app, { confirm: (n) => ({ seen: n <= 1 }) });
    assert.equal(flipped.code, 1);
    assert.deepEqual(flipped.record.authenticated.failed, ['route-stable']);
    const unproven = await run(app, { routeProof: (n, candidateId) => { if (n >= 2) throw new Error('dns changed'); return { bound: true, candidateId, imageId: DIGEST }; } });
    assert.equal(unproven.code, 1);
    assert.deepEqual(unproven.record.authenticated.failed, ['route-stable']);
  } finally {
    await app.close();
  }
});

test('the controller must provide every accessor, and a private deployment is refused outright', async () => {
  const app = await startApp();
  try {
    const full = providerFor(targetFor(app.origin), undefined, { app });
    for (const missing of ['loadAcceptanceTarget', 'inspectRunningImage', 'confirmBackendRequest', 'proveRouteBinding']) {
      const partial = { ...full, [missing]: undefined };
      await assert.rejects(() => main(['run', '--candidate', 'cand-1'], { provider: partial, now: () => NOW, out: () => {}, err: () => {} }), new RegExp(`does not provide ${missing}`));
    }
    const privateProvider = {
      ...full,
      loadAcceptanceTarget: async () => { throw Object.assign(new Error('private'), { code: 'private_deployment' }); },
      inspectRunningImage: async () => { throw new Error('must not be called'); },
    };
    for (const command of ['run', 'publish']) {
      await assert.rejects(
        () => main([command, '--candidate', 'cand-1'], { provider: privateProvider, now: () => NOW, out: () => {}, err: () => {} }),
        /deployed privately.*ACCEPTANCE INCOMPLETE/,
      );
    }
    const unavailable = { ...full, loadAcceptanceTarget: async () => { throw new Error('private target details'); } };
    await assert.rejects(
      () => main(['run', '--candidate', 'cand-1'], { provider: unavailable, now: () => NOW, out: () => {}, err: () => {} }),
      (error) => error instanceof Refusal && /could not establish a deployed candidate/.test(error.message) && !error.message.includes('private target details'),
    );
    assert.equal(app.state.log.length, 0);
  } finally {
    await app.close();
  }
});

// ---------------------------------------------------------------------------
// Generation: what is a solid, what is a pocket, and what happens when unsure
// ---------------------------------------------------------------------------

test('inspectBinaryStl accepts a closed solid and rejects everything else', () => {
  const good = inspectBinaryStl(boxStl(28));
  assert.equal(good.ok, true, good.detail);
  assert.ok(Math.abs(good.volume - 83.5 * 83.5 * 28) < 1, 'volume is the box volume');

  assert.equal(inspectBinaryStl(repeatedTrianglesStl()).ok, false, 'repeated triangles are not a solid');
  assert.equal(inspectBinaryStl(Buffer.from('solid x\nendsolid x\n')).ok, false);
  assert.equal(inspectBinaryStl(Buffer.alloc(10)).ok, false);
  assert.equal(inspectBinaryStl(boxStl(28).subarray(0, 200)).ok, false, 'size does not match the count');

  const triangles = boxTriangles(83.5, 83.5, 28);
  const open = inspectBinaryStl(stlFrom(triangles.slice(1)));
  assert.equal(open.ok, false);
  assert.match(open.detail, /not closed|no opposite/);

  const flipped = triangles.map((t, i) => (i === 7 ? [t[0], t[2], t[1]] : t));
  assert.equal(inspectBinaryStl(stlFrom(flipped)).ok, false, 'one reversed triangle breaks orientation');

  const inverted = triangles.map((t) => [t[0], t[2], t[1]]);
  const reversed = inspectBinaryStl(stlFrom(inverted));
  assert.equal(reversed.ok, false);
  assert.match(reversed.detail, /positive volume/);

  const degenerate = [...triangles];
  degenerate[3] = [triangles[3][0], triangles[3][0], triangles[3][1]];
  assert.match(inspectBinaryStl(stlFrom(degenerate)).detail, /degenerate/);

  const tiny = stlFrom(boxTriangles(2, 2, 2));
  assert.match(inspectBinaryStl(tiny).detail, /implausible extents/);

  const doubled = inspectBinaryStl(stlFrom([...triangles, ...triangles]));
  assert.equal(doubled.ok, false, 'a duplicated shell reuses every edge');
});

test('a generator that emits malformed repeated triangles fails the round trip', async () => {
  const app = await startApp({ malformedStl: true });
  try {
    const { code, record, lines } = await run(app);
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('bin-generate-roundtrip'));
    assert.match(lines.err.join('\n'), /not a valid solid/);
    assert.equal(app.state.bins.size, 0, 'finished bins are still cleaned up');
  } finally {
    await app.close();
  }
});

test('unpocketed output (the pocket does not change the solid) fails the round trip', async () => {
  const app = await startApp({ unpocketed: true });
  try {
    const { code, record, lines } = await run(app);
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('bin-generate-roundtrip'));
    assert.match(lines.err.join('\n'), /larger pocket did not remove materially more volume/);
  } finally {
    await app.close();
  }
});

test('a transport timeout during generation is uncertain: nothing is deleted and cleanup is never claimed', async () => {
  const app = await startApp({ generateDelayMs: 600 });
  try {
    const { code, record, lines } = await run(app, { generationTimeoutMs: 150 });
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('bin-generate-roundtrip'));
    assert.ok(record.authenticated.failed.includes('cleanup-verified'));
    assert.ok(!record.authenticated.passed.includes('cleanup-verified'));
    const report = lines.err.join('\n');
    assert.match(report, /outcome is uncertain/);
    assert.match(report, /NOT deleted/);
    assert.match(report, /only after generation has ended/);
    assert.equal(app.state.log.filter((e) => e.method === 'DELETE').length, 0, 'no DELETE raced the running generation');
    assert.equal(app.state.bins.size, 1, 'the uncertain bin is left for the operator');
    // the server finishes later, and nothing was destroyed underneath it
    await new Promise((resolve) => setTimeout(resolve, 700));
    const [bin] = [...app.state.bins.values()];
    assert.equal(bin.generating, false);
    assert.equal(bin.deletedWhileGenerating, false);
    assert.equal(bin.hasStl, true);
  } finally {
    await app.close();
  }
});

test('a proxy gateway timeout is uncertain too; an application 502 from the remote export is not', async () => {
  const gateway = await startApp({ generateStatus: 504 });
  try {
    const { code, record, lines } = await run(gateway);
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('cleanup-verified'));
    assert.match(lines.err.join('\n'), /backend may still be generating/);
    assert.equal(gateway.state.log.filter((e) => e.method === 'DELETE').length, 0);
    assert.equal(gateway.state.bins.size, 1);
  } finally {
    await gateway.close();
  }
  const exportFailed = await startApp({ generateStatus: 502, generateDetail: 'Bin generated locally, but remote export failed. Check server logs and retry generation.' });
  try {
    const { code, record, lines } = await run(exportFailed);
    assert.equal(code, 1);
    assert.ok(record.authenticated.failed.includes('bin-generate-roundtrip'));
    assert.match(lines.err.join('\n'), /remote export failed/);
    // the application answered, so generation had ended and cleanup is safe and verified
    assert.ok(record.authenticated.passed.includes('cleanup-verified'));
    assert.equal(exportFailed.state.bins.size, 0);
  } finally {
    await exportFailed.close();
  }
});

// ---------------------------------------------------------------------------
// The target is pinned, not supplied
// ---------------------------------------------------------------------------

test('the CLI has no way to name a target, receipt, URL, digest or config', () => {
  for (const flag of ['--deployed', '--config', '--url', '--base-url', '--origin', '--receipt', '--target', '--digest', '--image', '--sha', '--probe-url', '--insecure']) {
    assert.throws(() => parseArgs(['run', '--candidate', 'cand-1', flag, 'x']), /unknown argument/, flag);
  }
  assert.throws(() => parseArgs(['verdict', '--candidate', 'cand-1', '--record', '/x']), /usage/);
  assert.throws(() => parseArgs(['run', '--candidate', 'cand-1', '--credentials', '/y']), /unknown argument/);
  assert.throws(() => parseArgs(['publish', '--candidate', 'cand-1', '--credentials', '/y']), /unknown argument/);
  assert.throws(() => parseArgs(['run', '--candidate', '../x']), /candidate/);
  assert.throws(() => parseArgs(['run']), /candidate/);
  assert.throws(() => parseArgs(['deploy', '--candidate', 'cand-1']), /usage/);
  // there is no way to hand publish a record: only a fresh run is ever published
  for (const flag of ['--record', '--file', '--input', '--from', '--evidence', '--out-dir']) {
    assert.throws(() => parseArgs(['publish', '--candidate', 'cand-1', flag, '/x']), /unknown argument/, flag);
  }
  assert.throws(() => parseArgs(['run', '--candidate', 'cand-1', '--record', '/x']), /unknown argument/);
});

test('the environment cannot redirect the run: only the controller target is used', async () => {
  const app = await startApp();
  const saved = { ...process.env };
  try {
    Object.assign(process.env, {
      TRACEFINITY_BASE_URL: 'https://attacker.invalid', TRACEFINITY_ACCEPTANCE_TARGET: 'https://attacker.invalid', BASE_URL: 'https://attacker.invalid',
    });
    const { code, lines } = await run(app);
    assert.equal(code, 0, lines.err.join('\n'));
    assert.ok(app.state.log.length > 0);
  } finally {
    for (const key of ['TRACEFINITY_BASE_URL', 'TRACEFINITY_ACCEPTANCE_TARGET', 'BASE_URL']) {
      if (saved[key] === undefined) delete process.env[key];
    }
    await app.close();
  }
});

test('the target is asked of the controller for the named candidate and must be that candidate, deployed', () => {
  const ok = targetFor('https://app.example.test');
  assert.equal(validateTarget(ok, { candidateId: 'cand-1' }).publicOrigin, 'https://app.example.test');
  const bad = (change, pattern) => assert.throws(() => validateTarget({ ...ok, ...change }, { candidateId: 'cand-1' }), pattern, JSON.stringify(change));
  bad({ candidateId: 'cand-2' }, /different candidate/);
  bad({ state: 'queued' }, /not deployed/);
  bad({ state: 'production_incomplete' }, /not deployed/);
  bad({ environment: 'staging' }, /environment/);
  bad({ sourceSha: 'abc123' }, /40-hex/);
  bad({ imageDigest: 'sha256:abc' }, /imageDigest/);
  bad({ imageDigest: 'latest' }, /imageDigest/);
  bad({ appVersion: 'v1.2.3' }, /APP_VERSION/);
  bad({ approvalSha256: 'x' }, /approvalSha256/);
  bad({ deployedAt: 'never' }, /deployedAt/);
  bad({ publicOrigin: 'http://app.example.test' }, /https/);
  bad({ publicOrigin: 'ftp://app.example.test' }, /https/);
  bad({ publicOrigin: 'https://user:pw@app.example.test' }, /credentials/);
  bad({ publicOrigin: 'https://app.example.test/path?x=1' }, /bare origin/);
  bad({ probeUrl: 'https://evil.example.test' }, /unexpected field/);
  bad({ timeoutMs: 5 }, /timeoutMs/);
  assert.throws(() => validateTarget({ ...ok, allowLoopbackHttp: undefined, publicOrigin: 'http://127.0.0.1:9' }, { candidateId: 'cand-1' }), /https/);
  const withPublish = (publish) => validateTarget({ ...ok, publish }, { candidateId: 'cand-1' });
  assert.throws(() => withPublish({ repository: 'bad repo', stateBranch: 'production-state' }), /owner\/name/);
  assert.throws(() => withPublish({ repository: 'o/r', stateBranch: '../x' }), /branch/);
  // Station Zero reads records only from the branch .ade/config.json names
  for (const branch of ['main', 'master', 'production', 'prod-state', 'production-state-2', 'Production-State', 'production-state/x', 'sta0/acceptance']) {
    assert.throws(() => withPublish({ repository: 'o/r', stateBranch: branch }), /exactly production-state/, branch);
  }
  assert.equal(withPublish({ repository: 'o/r', stateBranch: 'production-state', verifier: VERIFIER }).publish.verifier, VERIFIER);
  assert.throws(() => withPublish({ repository: 'o/r', stateBranch: 'production-state', verifier: 'bad login!' }), /GitHub login/);
  assert.throws(() => withPublish({ repository: 'o/r', stateBranch: 'x', extra: 1 }), /unexpected/);
});

test('a refused target stops before any request or credential read', async () => {
  const app = await startApp();
  try {
    const provider = providerFor(targetFor(app.origin, { state: 'deploying' }), undefined, { app });
    await assert.rejects(
      () => main(['run', '--candidate', 'cand-1'], { provider, now: () => NOW, out: () => {}, err: () => {} }),
      /not deployed/,
    );
    assert.equal(app.state.log.length, 0);
    assert.equal(provider.calls.inspects, 0);
  } finally {
    await app.close();
  }
});

// ---------------------------------------------------------------------------
// Protected external input
// ---------------------------------------------------------------------------

test('credential files named by the pinned policy must be private, owned, regular and outside the repository', () => {
  const good = secretFile('good-cookie', `${COOKIE}\n`);
  assert.equal(loadCookie(good), COOKIE);
  assert.throws(() => loadCookie(secretFile('c-group', COOKIE, 0o640)), /group or others/);
  assert.throws(() => loadCookie(secretFile('c-world', COOKIE, 0o604)), /group or others/);
  assert.throws(() => loadCookie('relative/path'), /absolute/);
  assert.throws(() => loadCookie(path.join(tmp, 'missing')), /cannot be read/);
  const link = path.join(tmp, 'link');
  symlinkSync(good, link);
  assert.throws(() => loadCookie(link), /symbolic link/);
  assert.throws(() => loadCookie(good, { uid: (process.getuid?.() ?? 0) + 1 }), /owned by the user/);
  const inRepo = path.join(repoRoot, '.tracefinity-acceptance-test-credentials');
  writeFileSync(inRepo, COOKIE, { mode: 0o600 });
  try {
    assert.throws(() => readProtectedFile(inRepo, { label: 'f' }), /outside the repository/);
  } finally {
    rmSync(inRepo, { force: true });
  }
});

test('the session cookie is the operator\'s existing native cookie only', () => {
  assert.equal(loadCookie(secretFile('ck1', `${COOKIE}\n`)), COOKIE);
  assert.equal(loadCookie(secretFile('ck2', `tracefinity_auth=${COOKIE}`)), COOKIE);
  assert.throws(() => loadCookie(secretFile('ck3', 'tfadm_0123456789abcdef0123456789')), /administrator API token/);
  assert.throws(() => loadCookie(secretFile('ck4', `${COOKIE}\nsecond-line`)), /one tracefinity_auth value/);
  assert.throws(() => loadCookie(secretFile('ck5', `a=${COOKIE}; b=c`)), /one tracefinity_auth value/);
  assert.throws(() => loadCookie(secretFile('ck6', 'short')), /one tracefinity_auth value/);
  assert.throws(() => loadCookie(secretFile('ck7', `${COOKIE}`, 0o644)), /group or others/);
  assert.throws(() => loadToken(secretFile('tk1', 'two words here 0123456789')), /one token/);
});

test('the cookie never appears in any thrown refusal', () => {
  const bad = secretFile('ck-bad', `${COOKIE} extra`);
  try {
    loadCookie(bad);
    assert.fail('should refuse');
  } catch (error) {
    assert.ok(!String(error.message).includes(COOKIE));
  }
});

// ---------------------------------------------------------------------------
// The record: binding and the contract
// ---------------------------------------------------------------------------

async function goodRecord() {
  const app = await startApp();
  try {
    const result = await run(app);
    assert.equal(result.code, 0, result.lines.err.join('\n'));
    return { record: result.record, target: validateTarget(targetFor(app.origin), { candidateId: 'cand-1' }) };
  } finally {
    await app.close();
  }
}

test('assessRecord accepts the genuine record and refuses every tamper', async () => {
  const { record, target } = await goodRecord();
  const assess = (r, t = target, now = NOW) => assessRecord(r, { target: t, now });
  assert.equal(assess(record).eligible, true);
  const clone = () => structuredClone(record);

  const other = (mutate, pattern) => {
    const r = clone();
    mutate(r);
    const result = assess(r);
    assert.equal(result.eligible, false);
    assert.match(result.problems.join(';'), pattern);
  };
  other((r) => { r.candidateId = 'cand-2'; }, /another candidate/);
  other((r) => { r.authenticated.boundTo.sourceSha = 'f'.repeat(40); }, /source commit/);
  other((r) => { r.authenticated.boundTo.imageDigests = { tracefinity: OTHER_DIGEST }; }, /image digest/);
  other((r) => { r.authenticated.boundTo.planSha256 = 'f'.repeat(64); }, /approval/);
  other((r) => { r.authenticated.boundTo.contractSha256 = 'f'.repeat(64); }, /contract/);
  other((r) => { r.authenticated.boundTo.runId = 'other-run'; }, /different runs/);
  other((r) => { r.environment = 'staging'; }, /environment/);
  other((r) => { r.overall = 'VERIFIED_LIVE'; }, /overall/);
  other((r) => { r.waiver = { candidateId: 'cand-1', signatureBase64: 'x', expiresAt: '2030-01-01T00:00:00Z' }; }, /waiver/);
  other((r) => { delete r.authenticated.boundTo; }, /bound to the deployed identity/);
  other((r) => { delete r.authenticated.evidenceSha256; }, /evidence digest/);

  // the contract is the required set: authentication alone can never be sufficient
  other((r) => { r.authenticated.required = ['session-authenticated']; r.authenticated.passed = ['session-authenticated']; }, /required checks differ/);
  for (const dropped of ['bin-generate-roundtrip', 'running-image', 'route-bound', 'route-stable', 'cleanup-verified']) {
    other((r) => { r.authenticated.required = r.authenticated.required.filter((id) => id !== dropped); }, /required checks differ/);
  }

  const notEligible = (mutate, pattern, t = target, now = NOW) => {
    const r = clone();
    mutate(r);
    const result = assess(r, t, now);
    assert.deepEqual(result.problems, []);
    assert.equal(result.eligible, false);
    assert.match(result.missing.join(';'), pattern);
  };
  notEligible((r) => { r.authenticated.passed = r.authenticated.passed.filter((id) => id !== 'cleanup-verified'); }, /required but not passed: cleanup-verified/);
  notEligible((r) => { r.authenticated.state = 'unknown'; }, /unknown/);
  notEligible((r) => { r.health = 'fail'; }, /health/);
  notEligible((r) => { r.preflight.verdict = 'unknown'; }, /preflight/);
  notEligible((r) => { r.authenticated.skipped = ['library-read']; }, /skipped/);
  notEligible(() => {}, /stale/, target, new Date(NOW.getTime() + 2 * 86_400_000));
  notEligible(() => {}, /future/, target, new Date(NOW.getTime() - 3_600_000));
  notEligible(() => {}, /predates the deployment/, { ...target, deployedAt: '2026-11-13T13:00:00.001Z' }, NOW);
});

test('a record with only /api/auth/me proven cannot be built by the runner either', async () => {
  const app = await startApp({ failGenerate: true, leakDelete: true });
  try {
    const { record } = await run(app);
    assert.notEqual(record.authenticated.state, 'passed');
    assert.ok(record.authenticated.passed.includes('session-authenticated'));
    const target = validateTarget(targetFor(app.origin), { candidateId: 'cand-1' });
    assert.equal(assessRecord(record, { target, now: NOW }).eligible, false);
  } finally {
    await app.close();
  }
});

test('assertNoLeak refuses URLs, emails, paths, credentials and registered secrets', () => {
  assertNoLeak('{"candidateId":"cand-1","state":"passed"}', [COOKIE]);
  for (const text of ['see https://host.example/x', 'a@b.example', '/home/user/x', 'tracefinity_auth=abc', 'tfadm_abc', '-----BEGIN PRIVATE KEY-----', `v ${COOKIE}`]) {
    assert.throws(() => assertNoLeak(text, [COOKIE]), /refusing/, text);
  }
});

// ---------------------------------------------------------------------------
// Publication: only a restricted, existing branch, only a fresh run
// ---------------------------------------------------------------------------

// `update` rule parameters an attacker (or a mistake) could set; GitHub documents
// update_allows_fetch_and_merge as a required boolean, so absent means the default (false)
const UPDATE_PARAMS = {
  'fetch-merge-false': { update_allows_fetch_and_merge: false },
  'good-empty-params': {},
  'fetch-merge-true': { update_allows_fetch_and_merge: true },
  'fetch-merge-string': { update_allows_fetch_and_merge: 'yes' },
  'fetch-merge-null': { update_allows_fetch_and_merge: null },
  'params-string': 'x',
};
const listParams = (variant) => (UPDATE_PARAMS[variant] !== undefined ? { parameters: UPDATE_PARAMS[variant] } : {});
const detailParams = (variant) => (variant === 'detail-fetch-merge-true' ? { parameters: { update_allows_fetch_and_merge: true } } : listParams(variant));

const PROTECTION = {
  restricted: () => ({
    restrictions: { users: [{ login: VERIFIER }], teams: [], apps: [] },
    enforce_admins: { enabled: true },
    allow_force_pushes: { enabled: false },
    allow_deletions: { enabled: false },
  }),
  // protected, but anyone with write access can push: GitHub omits `restrictions`
  unrestricted: () => ({ enforce_admins: { enabled: true }, allow_force_pushes: { enabled: false }, allow_deletions: { enabled: false } }),
  team: () => ({ ...PROTECTION.restricted(), restrictions: { users: [{ login: VERIFIER }], teams: [{ slug: 'writers' }], apps: [] } }),
  app: () => ({ ...PROTECTION.restricted(), restrictions: { users: [{ login: VERIFIER }], teams: [], apps: [{ slug: 'some-app' }] } }),
  'two-users': () => ({ ...PROTECTION.restricted(), restrictions: { users: [{ login: VERIFIER }, { login: 'other-writer' }], teams: [], apps: [] } }),
  'other-user': () => ({ ...PROTECTION.restricted(), restrictions: { users: [{ login: 'someone-else' }], teams: [], apps: [] } }),
  'no-users': () => ({ ...PROTECTION.restricted(), restrictions: { users: [], teams: [], apps: [] } }),
  'admins-not-enforced': () => ({ ...PROTECTION.restricted(), enforce_admins: { enabled: false } }),
  'force-push': () => ({ ...PROTECTION.restricted(), allow_force_pushes: { enabled: true } }),
  deletions: () => ({ ...PROTECTION.restricted(), allow_deletions: { enabled: true } }),
};

async function startGithub({
  branch = 'protected', defaultBranch = 'main', readBackMismatch = false, fullName = 'owner/repo',
  tokenUser = VERIFIER, protection = 'restricted', rulesets = 'none', appRuleset = null,
} = {}) {
  const gh = { calls: [], stored: null };
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const url = new URL(req.url, 'http://x');
      const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : null;
      gh.calls.push({ method: req.method, path: url.pathname, auth: req.headers.authorization, body });
      const json = (status, value) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(value)); };
      const p = url.pathname;
      if (p === '/user') return appRuleset ? json(403, { message: 'Resource not accessible by integration' }) : json(200, { login: tokenUser });
      if (appRuleset && p === '/repos/owner/repo/rules/branches/production-state') {
        if (appRuleset === 'rules-unreadable') return json(403, {});
        if (appRuleset === 'no-rules') return json(200, []);
        const types = appRuleset === 'missing-deletion' ? ['update', 'non_fast_forward'] : ['update', 'deletion', 'non_fast_forward'];
        const source = appRuleset === 'org-source' ? 'Organization' : 'Repository';
        const list = types.map((type) => ({ type, ruleset_id: 11, ruleset_source_type: source, ruleset: 'x', ...(type === 'update' ? listParams(appRuleset) : {}) }));
        if (appRuleset === 'split-rules') return json(200, [{ type: 'update', ruleset_id: 11, ruleset_source_type: 'Repository' }, { type: 'deletion', ruleset_id: 12, ruleset_source_type: 'Repository' }, { type: 'non_fast_forward', ruleset_id: 12, ruleset_source_type: 'Repository' }]);
        if (appRuleset === 'extra-ruleset-restrictive') list.push(...types.map((type) => ({ type, ruleset_id: 12, ruleset_source_type: 'Repository' })));
        return json(200, list);
      }
      if (appRuleset && /^\/repos\/owner\/repo\/rulesets\/(11|12)$/.test(p)) {
        if (appRuleset === 'detail-unreadable') return json(403, {});
        const id = Number(p.split('/').pop());
        const ruleTypes = appRuleset === 'missing-deletion' ? ['update', 'non_fast_forward'] : ['update', 'deletion', 'non_fast_forward'];
        const app = { actor_id: APP_ID, actor_type: 'Integration', bypass_mode: 'always' };
        let bypass = [app];
        if (id === 12) bypass = [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }];
        if (appRuleset === 'extra-actor') bypass = [app, { actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }];
        if (appRuleset === 'admin-role-only') bypass = [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }];
        if (appRuleset === 'other-app') bypass = [{ ...app, actor_id: 999 }];
        if (appRuleset === 'pr-only') bypass = [{ ...app, bypass_mode: 'pull_request' }];
        if (appRuleset === 'empty-bypass') bypass = [];
        if (appRuleset === 'deploy-key') bypass = [{ actor_id: null, actor_type: 'DeployKey', bypass_mode: 'always' }];
        return json(200, {
          id,
          enforcement: appRuleset === 'evaluate' ? 'evaluate' : 'active',
          target: appRuleset === 'tag-target' ? 'tag' : 'branch',
          rules: ruleTypes.map((type) => ({ type, ...(type === 'update' ? detailParams(appRuleset) : {}) })),
          bypass_actors: bypass,
        });
      }
      if (p === '/repos/owner/repo') return json(200, { default_branch: defaultBranch, full_name: fullName });
      if (p === '/repos/owner/repo/branches/production-state') {
        if (branch === 'missing') return json(404, {});
        return json(200, { protected: branch === 'protected' });
      }
      if (p === '/repos/owner/repo/branches/production-state/protection') {
        if (protection === 'unreadable') return json(403, { message: 'Resource not accessible' });
        return json(200, PROTECTION[protection]());
      }
      if (p === '/repos/owner/repo/rulesets') {
        if (rulesets === 'unreadable') return json(403, {});
        if (rulesets === 'none') return json(200, []);
        if (rulesets === 'disabled-with-bypass') return json(200, [{ id: 7, enforcement: 'disabled' }]);
        return json(200, [{ id: 7, enforcement: 'active' }]);
      }
      if (p === '/repos/owner/repo/rulesets/7') {
        if (rulesets === 'detail-unreadable') return json(403, {});
        return json(200, { id: 7, bypass_actors: rulesets === 'bypass' ? [{ actor_id: 5, actor_type: 'RepositoryRole', bypass_mode: 'always' }] : [] });
      }
      if (p === '/repos/owner/repo/contents/acceptance/cand-1.json') {
        if (req.method === 'PUT') {
          gh.stored = Buffer.from(body.content, 'base64').toString('utf8');
          return json(201, { commit: { sha: '1'.repeat(40) } });
        }
        if (gh.stored === null) return json(404, {});
        return json(200, { sha: '2'.repeat(40), content: Buffer.from(readBackMismatch ? `${gh.stored} ` : gh.stored).toString('base64') });
      }
      return json(404, {});
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  gh.origin = `http://127.0.0.1:${server.address().port}`;
  gh.close = () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); });
  gh.writes = () => gh.calls.filter((c) => c.method !== 'GET');
  return gh;
}

async function publishScenario(ghOptions, {
  runtime, tokenless = false, appOptions = {}, stateBranch = 'production-state', repository = 'owner/repo', verifier = VERIFIER, verifierApp = null, routeProof,
} = {}) {
  const app = await startApp(appOptions);
  const gh = await startGithub(ghOptions);
  const publish = {
    repository, stateBranch, ...(tokenless ? {} : { tokenFile: TOKEN_FILE }), ...(verifier ? { verifier } : {}), ...(verifierApp ? { verifierApp } : {}), githubApiUrl: gh.origin,
  };
  const raw = targetFor(app.origin, { publish });
  const lines = { err: [] };
  const provider = providerFor(raw, runtime, { app, routeProof });
  const promise = main(['publish', '--candidate', 'cand-1'], {
    provider, now: () => NOW, out: () => {}, err: (t) => lines.err.push(t), fetchImpl: globalThis.fetch, retryDelayMs: 0,
  });
  promise.catch(() => {});
  return { app, gh, promise, lines, provider, close: async () => { await app.close(); await gh.close(); } };
}

test('publish refuses a branch that does not exist and never creates one', async () => {
  const { gh, promise, close } = await publishScenario({ branch: 'missing' });
  try {
    await assert.rejects(() => promise, /does not exist.*never by this publisher/);
    assert.equal(gh.writes().length, 0);
  } finally {
    await close();
  }
});

test('publish refuses an unprotected branch', async () => {
  const { gh, promise, close } = await publishScenario({ branch: 'unprotected' });
  try {
    await assert.rejects(() => promise, /not protected/);
    assert.equal(gh.writes().length, 0);
  } finally {
    await close();
  }
});

test('publish refuses a protected branch that does not restrict who can write, whatever the boolean says', async () => {
  for (const protection of ['unrestricted', 'team', 'app', 'two-users', 'other-user', 'no-users', 'admins-not-enforced', 'force-push', 'deletions', 'unreadable']) {
    const { app, gh, promise, close } = await publishScenario({ protection });
    try {
      await assert.rejects(() => promise, /does not restrict who can write|branch protection could not be read/, protection);
      assert.equal(gh.writes().length, 0, `${protection}: nothing was written`);
      assert.equal(gh.stored, null);
      assert.equal(app.state.log.length, 0, `${protection}: the session was never used`);
    } finally {
      await close();
    }
  }
});

test('publish refuses rulesets that grant bypass or cannot be examined', async () => {
  for (const [rulesets, pattern] of [['bypass', /grants bypass actors/], ['unreadable', /rulesets could not be read/], ['detail-unreadable', /could not be read in full/]]) {
    const { app, gh, promise, close } = await publishScenario({ rulesets });
    try {
      await assert.rejects(() => promise, pattern, rulesets);
      assert.equal(gh.writes().length, 0);
      assert.equal(app.state.log.length, 0);
    } finally {
      await close();
    }
  }
});

test('publish proceeds when the writers are exactly the verifier and no ruleset grants bypass', async () => {
  for (const rulesets of ['none', 'clean', 'disabled-with-bypass']) {
    const { gh, promise, close } = await publishScenario({ rulesets });
    try {
      assert.equal(await promise, 0, rulesets);
      assert.equal(gh.writes().length, 1);
    } finally {
      await close();
    }
  }
});

test('on a personal repository the only writer is the pinned GitHub App, established by a branch ruleset', async () => {
  for (const appRuleset of ['good', 'extra-ruleset-restrictive', 'fetch-merge-false', 'good-empty-params']) {
    const { app, gh, promise, close } = await publishScenario({ appRuleset, branch: 'unprotected' }, { verifier: null, verifierApp: APP_ID });
    try {
      assert.equal(await promise, 0, appRuleset);
      assert.equal(gh.writes().length, 1);
      assert.ok(gh.calls.every((c) => c.path !== '/user' && !c.path.endsWith('/protection')), 'no user identity or classic protection is consulted');
      assert.ok(gh.calls.some((c) => c.path === '/repos/owner/repo/rules/branches/production-state'));
      assert.equal(JSON.parse(gh.stored).authenticated.state, 'passed');
      assert.ok(app.state.log.length > 0);
    } finally {
      await close();
    }
  }
});

test('a personal repository whose branch is merely protected or whose ruleset is anything but app-only fails closed', async () => {
  for (const appRuleset of [
    'no-rules', 'rules-unreadable', 'missing-deletion', 'split-rules', 'org-source', 'detail-unreadable',
    'extra-actor', 'admin-role-only', 'other-app', 'pr-only', 'evaluate', 'tag-target', 'empty-bypass', 'deploy-key',
    'fetch-merge-true', 'fetch-merge-string', 'fetch-merge-null', 'params-string', 'detail-fetch-merge-true',
  ]) {
    // protected: true is present and says nothing about who can write
    const { app, gh, promise, close } = await publishScenario({ appRuleset, branch: 'protected' }, { verifier: null, verifierApp: APP_ID });
    try {
      await assert.rejects(() => promise, /does not confine writes to the pinned app|could not be read|no repository ruleset applies/, appRuleset);
      assert.equal(gh.writes().length, 0, `${appRuleset}: nothing was written`);
      assert.equal(gh.stored, null);
      assert.equal(app.state.log.length, 0, `${appRuleset}: the session was never used`);
    } finally {
      await close();
    }
  }
});

test('rulesetWriterProblems requires an active branch ruleset with the three rules and exactly the pinned app as an always-bypass actor', () => {
  const good = {
    enforcement: 'active',
    target: 'branch',
    rules: [{ type: 'update' }, { type: 'deletion' }, { type: 'non_fast_forward' }],
    bypass_actors: [{ actor_type: 'Integration', actor_id: APP_ID, bypass_mode: 'always' }],
  };
  assert.deepEqual(rulesetWriterProblems(good, APP_ID), []);
  const withChange = (change) => rulesetWriterProblems({ ...good, ...change }, APP_ID).join(';');
  assert.match(withChange({ enforcement: 'disabled' }), /not active/);
  assert.match(withChange({ enforcement: 'evaluate' }), /not active/);
  assert.match(withChange({ target: 'tag' }), /does not target branches/);
  assert.match(withChange({ rules: [{ type: 'update' }, { type: 'deletion' }] }), /non_fast_forward/);
  assert.match(withChange({ rules: [] }), /update rule/);
  assert.match(withChange({ bypass_actors: [] }), /0 actors/);
  assert.match(withChange({ bypass_actors: undefined }), /cannot be read/);
  assert.match(withChange({ bypass_actors: [...good.bypass_actors, { actor_type: 'Team', actor_id: 1, bypass_mode: 'always' }] }), /2 actors/);
  assert.match(withChange({ bypass_actors: [{ actor_type: 'Integration', actor_id: APP_ID + 1, bypass_mode: 'always' }] }), /not the pinned app/);
  assert.match(withChange({ bypass_actors: [{ actor_type: 'User', actor_id: APP_ID, bypass_mode: 'always' }] }), /not the pinned app/);
  assert.match(withChange({ bypass_actors: [{ actor_type: 'Integration', actor_id: APP_ID, bypass_mode: 'pull_request' }] }), /only for pull requests/);
  // update_allows_fetch_and_merge lets non-bypass actors update the branch, so it must be false or absent
  const withRules = (updateRule) => rulesetWriterProblems({ ...good, rules: [updateRule, { type: 'deletion' }, { type: 'non_fast_forward' }] }, APP_ID).join(';');
  assert.equal(withRules({ type: 'update' }), '');
  assert.equal(withRules({ type: 'update', parameters: {} }), '');
  assert.equal(withRules({ type: 'update', parameters: { update_allows_fetch_and_merge: false } }), '');
  assert.match(withRules({ type: 'update', parameters: { update_allows_fetch_and_merge: true } }), /fetch-and-merge updates without bypass/);
  assert.match(withRules({ type: 'update', parameters: { update_allows_fetch_and_merge: 'true' } }), /malformed/);
  assert.match(withRules({ type: 'update', parameters: { update_allows_fetch_and_merge: 1 } }), /malformed/);
  assert.match(withRules({ type: 'update', parameters: 'x' }), /parameters are malformed/);
  assert.match(withRules({ type: 'update', parameters: [] }), /parameters are malformed/);
  assert.deepEqual(updateRuleProblems({ type: 'update' }), []);
  assert.deepEqual(updateRuleProblems({ type: 'update', parameters: null }), []);
  assert.equal(updateRuleProblems({ type: 'update', parameters: { update_allows_fetch_and_merge: true } }).length, 1);
  assert.ok(rulesetWriterProblems(null, APP_ID).length > 0);
});

test('the policy pins either a verifier login or a verifier app, validated as such', () => {
  const ok = targetFor('https://app.example.test');
  const withPublish = (publish) => validateTarget({ ...ok, publish: { repository: 'o/r', stateBranch: 'production-state', ...publish } }, { candidateId: 'cand-1' });
  assert.equal(withPublish({ verifierApp: 12345 }).publish.verifierApp, 12345);
  for (const bad of [0, -1, 1.5, '5', 'x', Number.MAX_SAFE_INTEGER + 2]) {
    assert.throws(() => withPublish({ verifierApp: bad }), /positive GitHub App id/, String(bad));
  }
  assert.throws(() => withPublish({ verifier: VERIFIER, verifierApp: 12345 }), /either a verifier login or a verifier app/);
});

test('publish refuses a token that is not the pinned verifier, or a policy that pins none', async () => {
  const wrongToken = await publishScenario({ tokenUser: 'someone-else' });
  try {
    await assert.rejects(() => wrongToken.promise, /does not belong to the pinned verifier/);
    assert.equal(wrongToken.gh.writes().length, 0);
  } finally {
    await wrongToken.close();
  }
  const unpinned = await publishScenario({}, { verifier: null });
  try {
    await assert.rejects(() => unpinned.promise, /pins no verifier/);
    assert.equal(unpinned.gh.calls.length, 0);
    assert.equal(unpinned.app.state.log.length, 0);
  } finally {
    await unpinned.close();
  }
});

test('writerRestrictionProblems does not treat a protected branch as restricted', () => {
  assert.deepEqual(writerRestrictionProblems(PROTECTION.restricted(), VERIFIER), []);
  assert.deepEqual(writerRestrictionProblems(PROTECTION.restricted(), VERIFIER.toUpperCase()), []);
  for (const [name, problem] of [
    ['unrestricted', /not restricted to named actors/],
    ['team', /team is allowed/],
    ['app', /app is allowed/],
    ['two-users', /not exactly the pinned verifier/],
    ['no-users', /not exactly the pinned verifier/],
    ['admins-not-enforced', /administrators/],
    ['force-push', /force pushes/],
    ['deletions', /deletion/],
  ]) {
    assert.match(writerRestrictionProblems(PROTECTION[name](), VERIFIER).join(';'), problem, name);
  }
  assert.ok(writerRestrictionProblems(null, VERIFIER).length > 0);
  assert.ok(writerRestrictionProblems({}, VERIFIER).length > 0);
  assert.ok(writerRestrictionProblems({ restrictions: { users: [{ login: VERIFIER }] }, enforce_admins: { enabled: true } }, VERIFIER).length > 0, 'missing lists fail closed');
});

test('publish refuses the repository default branch', async () => {
  const { gh, promise, close } = await publishScenario({ defaultBranch: 'production-state' });
  try {
    await assert.rejects(() => promise, /default branch/);
    assert.equal(gh.writes().length, 0);
  } finally {
    await close();
  }
});

test('a policy naming any branch other than production-state is refused before anything runs or is written', async () => {
  for (const stateBranch of ['main', 'acceptance', 'production-state-old']) {
    const { app, gh, promise, close } = await publishScenario({}, { stateBranch });
    try {
      await assert.rejects(() => promise, /exactly production-state/);
      assert.equal(app.state.log.length, 0, 'the app was never contacted');
      assert.equal(gh.calls.length, 0, 'nothing was sent to the repository');
    } finally {
      await close();
    }
  }
});

test('publish refuses when the host reports a different repository than the pinned one', async () => {
  const { gh, promise, close } = await publishScenario({ fullName: 'someone-else/repo' });
  try {
    await assert.rejects(() => promise, /not the repository the host reports/);
    assert.equal(gh.writes().length, 0);
    assert.equal(gh.stored, null);
  } finally {
    await close();
  }
});

test('publish refuses when the stored record does not read back identically', async () => {
  const { promise, close } = await publishScenario({ readBackMismatch: true });
  try {
    await assert.rejects(() => promise, /read back/);
  } finally {
    await close();
  }
});

test('publish needs the pinned token file and proves it before the session cookie is used', async () => {
  const { app, gh, promise, close } = await publishScenario({}, { tokenless: true });
  try {
    await assert.rejects(() => promise, /no token file/);
    assert.equal(gh.calls.length, 0);
    assert.equal(app.state.log.length, 0, 'the app was never contacted');
  } finally {
    await close();
  }
});

test('a passing run is not published when the running image moved or the route is no longer proved', async () => {
  const moved = await publishScenario({}, { runtime: (n) => ({ running: true, imageId: n <= 2 ? DIGEST : OTHER_DIGEST, repoDigests: [] }) });
  try {
    await assert.rejects(() => moved.promise, /changed after the checks/);
    assert.equal(moved.gh.writes().length, 0);
  } finally {
    await moved.close();
  }
  // proofs: route-bound (1), route-stable (2), and once more immediately before the write (3)
  const rerouted = await publishScenario({}, { routeProof: (n, candidateId) => { if (n >= 3) throw new Error('ingress changed'); return { bound: true, candidateId, imageId: DIGEST }; } });
  try {
    await assert.rejects(() => rerouted.promise, /route binding could not be re-proved/);
    assert.equal(rerouted.gh.writes().length, 0);
  } finally {
    await rerouted.close();
  }
});

test('a fabricated pass cannot be promoted: with no genuine success only the honest failed record is published', async () => {
  // nothing a caller writes to disk can change what is published
  secretFile('planted-record.json', JSON.stringify({ schemaVersion: 1, authenticated: { state: 'passed' } }));
  const { gh, promise, close } = await publishScenario({}, { appOptions: { failGenerate: true } });
  try {
    assert.equal(await promise, 1);
    const stored = JSON.parse(gh.stored);
    assert.equal(stored.authenticated.state, 'failed');
    assert.ok(stored.authenticated.failed.includes('bin-generate-roundtrip'));
    assert.ok(!stored.authenticated.passed.includes('bin-generate-roundtrip'));
    assert.ok(!('overall' in stored));
  } finally {
    await close();
  }
});

test('a wrong deployment publishes an honest failed record without ever sending the session', async () => {
  const { app, gh, promise, close } = await publishScenario({}, { appOptions: { version: 'e'.repeat(40) } });
  try {
    assert.equal(await promise, 1);
    const stored = JSON.parse(gh.stored);
    assert.equal(stored.authenticated.state, 'failed');
    assert.ok(stored.authenticated.failed.includes('served-identity'));
    assert.equal(stored.preflight.verdict, 'fail');
    assert.ok(app.state.log.every((e) => !e.hasCookie));
  } finally {
    await close();
  }
});

// ---------------------------------------------------------------------------
// Repository hygiene
// ---------------------------------------------------------------------------

test('the script and the runbook carry no operator details or secrets', () => {
  const allowedHosts = new Set(['api.github.com', 'github.com', 'docs.github.com', 'example.com', 'app.example.com', 'owner.example.com']);
  for (const file of ['scripts/tracefinity-acceptance.mjs', 'docs/signed-deployment.md']) {
    const text = readFileSync(path.join(repoRoot, file), 'utf8');
    assert.ok(!/\/home\/[a-z]/i.test(text), `${file} has a home path`);
    assert.ok(!/BEGIN [A-Z ]*PRIVATE KEY/.test(text), `${file} has key material`);
    assert.ok(!/(?:ghp|gho|ghs|github_pat)_[A-Za-z0-9_]{20,}/.test(text), `${file} has a token`);
    assert.ok(!/[A-Za-z0-9._%+-]+@(?!example\.com)[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(text.replace(/@sha256/g, '')), `${file} has an email address`);
    for (const [, host] of text.matchAll(/https?:\/\/([A-Za-z0-9.-]+)/g)) {
      assert.ok(allowedHosts.has(host) || host.endsWith('.example.com') || host === 'localhost', `${file} names host ${host}`);
    }
  }
});

test('the release repository policy names the acceptance record location', () => {
  const ade = JSON.parse(readFileSync(path.join(repoRoot, '.ade/config.json'), 'utf8'));
  assert.deepEqual(ade.releaseAcceptance, { branch: 'production-state', path: 'acceptance/{candidate}.json', environment: 'production' });
});
