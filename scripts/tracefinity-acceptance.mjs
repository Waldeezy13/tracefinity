#!/usr/bin/env node

// Authenticated acceptance for a deployed Tracefinity candidate.
//
// Produces the schema-1 acceptance record Station Zero reads from the
// repository's `releaseAcceptance` policy (.ade/config.json) and derives
// VERIFIED LIVE from. The record never carries `overall`: Station Zero derives
// it. A green deployment is DEPLOYED; only a record this script produced from a
// real authenticated run against the deployed candidate can become VERIFIED LIVE.
//
//   run      a fresh identity-gated, authenticated end-to-end run; prints the
//            record (stdout) or stores it (--out-dir); writes nothing remote
//   publish  performs its OWN fresh run and writes exactly the record that run
//            produced (pass or honest fail) to an EXISTING state branch whose
//            writers are provably restricted to the pinned verifier. It accepts
//            no record from a file, so a hand-made or stale pass can never be
//            promoted
//
// Exit codes: 0 the fresh run passed and is eligible for VERIFIED LIVE (publish:
// and was published); 1 the run failed or is incomplete (publish: the honest
// failed record was still published); 2 refused (usage, unsafe input, wrong or
// undeployed candidate, untrusted target, unrestricted or missing branch).
//
// The target, candidate, source commit, image digest and approval digest are NOT
// inputs. They come from the signed release controller's fixed, operator-pinned
// policy and its durable receipt (scripts/release-controller.mjs
// `loadAcceptanceTarget`). What is running is read through the controller's own
// target access (`inspectRunningImage`) before and after the run, and the public
// route is bound to that container by the controller's `proveRouteBinding`
// (signed ingress and DNS unchanged, same container, nonce in its own request log)
// and by nonces of this script that must show up in the container's own log
// (`confirmBackendRequest`), before the session cookie is ever sent, again at the
// end, and before publishing. A failure at any point sends no credentials. There
// is no command-line or environment override of any of it; `--candidate` only
// names which receipt to read.
//
// The only secrets are the operator's already-issued native session cookie and,
// to publish, a repository token. Their file locations also come from the pinned
// policy (never from the command line or environment) and are read only from
// owner-only files outside the checkout. The operator's password and second
// factor are never asked for, read or sent, and nothing secret lives in this
// repository.

import { createHash, randomBytes } from 'node:crypto';
import { lstatSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(scriptDir, '..');

export const SERVICE = 'tracefinity';
export const COOKIE_NAME = 'tracefinity_auth';
export const MAX_AGE_SECONDS = 86_400;
/** Generation is allowed 120 s by the combined container's proxy; wait longer than that. */
export const GENERATION_TIMEOUT_MS = 150_000;
/** A larger pocket must remove at least this much material compared with a smaller one (mm^3). */
export const MIN_POCKET_VOLUME_DELTA = 2_500;

/**
 * The verification contract. Its sha256 is bound into every record. Dropping or
 * renaming a required check changes the hash and makes older records ineligible,
 * so a check is never removed to make a release read VERIFIED LIVE.
 */
export const CONTRACT = Object.freeze({
  schemaVersion: 1,
  kind: 'tracefinity.acceptance-contract',
  service: SERVICE,
  environment: 'production',
  requiredChecks: Object.freeze([
    'deployed-identity',
    'running-image',
    'served-identity',
    'route-bound',
    'setup-closed',
    'unauthenticated-refused',
    'session-authenticated',
    'least-privilege',
    'library-read',
    'bin-generate-roundtrip',
    'cleanup-verified',
    'running-image-stable',
    'route-stable',
  ]),
});

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const contractSha256 = () => sha256(JSON.stringify(CONTRACT));

const CANDIDATE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/;
const SHA1 = /^[0-9a-f]{40}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/;
const LOGIN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const MAX_RECORD_BYTES = 64 * 1024;
const FUTURE_SKEW_MS = 5 * 60 * 1000;
const PREFLIGHT_TTL_MS = 60 * 60 * 1000;
const MAX_RESPONSE_BYTES = 32 * 1024 * 1024;
const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]']);
const GITHUB_API = 'https://api.github.com';
/** What .ade/config.json `releaseAcceptance` pins; Station Zero reads records nowhere else. */
export const STATE_BRANCH = 'production-state';

export class Refusal extends Error {}

function refuse(message) {
  throw new Refusal(message);
}

// ---------------------------------------------------------------------------
// Protected external input
// ---------------------------------------------------------------------------

function inside(parent, child) {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

/**
 * Read a file the operator owns outside the checkout. Credentials are accepted
 * only from here: absolute, not a symbolic link, a regular file owned by this
 * user, unreadable by anyone else, and outside the repository.
 */
export function readProtectedFile(file, {
  label, secret = true, repoRoot = REPO_ROOT, uid = process.getuid?.(),
} = {}) {
  if (typeof file !== 'string' || !path.isAbsolute(file)) refuse(`${label} must be an absolute path`);
  let stat;
  try {
    stat = lstatSync(file);
  } catch {
    refuse(`${label} cannot be read`);
  }
  if (stat.isSymbolicLink()) refuse(`${label} must not be a symbolic link`);
  if (!stat.isFile()) refuse(`${label} must be a regular file`);
  if (uid !== undefined && stat.uid !== uid) refuse(`${label} must be owned by the user running the acceptance`);
  if ((stat.mode & (secret ? 0o077 : 0o022)) !== 0) {
    refuse(`${label} must not be accessible to group or others (${secret ? 'chmod 600' : 'not writable by others'})`);
  }
  if (secret && inside(realpathSync(repoRoot), realpathSync(file))) refuse(`${label} must live outside the repository checkout`);
  return readFileSync(file, 'utf8');
}

function exactObject(value, where, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) refuse(`${where} must be an object`);
  for (const key of Object.keys(value)) {
    if (!required.includes(key) && !optional.includes(key)) refuse(`${where} has an unexpected field ${JSON.stringify(key.slice(0, 40))}`);
  }
  for (const key of required) if (!(key in value)) refuse(`${where} is missing ${key}`);
  return value;
}

export function normaliseOrigin(raw, { allowLoopbackHttp = false, label = 'origin' } = {}) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    return refuse(`${label} is not a URL`);
  }
  if (url.username || url.password) refuse(`${label} must not carry credentials`);
  if ((url.pathname !== '/' && url.pathname !== '') || url.search || url.hash) refuse(`${label} must be a bare origin`);
  if (url.protocol === 'https:') return url.origin;
  if (url.protocol === 'http:' && allowLoopbackHttp && LOOPBACK.has(url.hostname)) return url.origin;
  return refuse(`${label} must be https`);
}

/**
 * The operator's already-issued native session cookie. Only the value is read.
 * It is never logged, never written to the record or the evidence, and only ever
 * sent to the controller-pinned origin. An administrator API token is not a login
 * and is refused.
 */
export function loadCookie(file, options = {}) {
  const raw = readProtectedFile(file, { label: 'the session cookie file', ...options }).replace(/\r?\n$/, '');
  const value = raw.startsWith(`${COOKIE_NAME}=`) ? raw.slice(COOKIE_NAME.length + 1) : raw;
  if (value.startsWith('tfadm_')) refuse('an administrator API token is not a login cookie');
  if (!/^[A-Za-z0-9_.~-]{16,512}$/.test(value)) refuse('the session cookie file must hold one tracefinity_auth value and nothing else');
  return value;
}

export function loadToken(file, options = {}) {
  const raw = readProtectedFile(file, { label: 'the publish token file', ...options }).replace(/\r?\n$/, '');
  if (!/^[A-Za-z0-9_.-]{20,255}$/.test(raw)) refuse('the publish token file must hold one token and nothing else');
  return raw;
}

// ---------------------------------------------------------------------------
// The deployed target (from the signed release controller, never from the CLI)
// ---------------------------------------------------------------------------

/**
 * Validate what the controller's pinned policy and durable receipt say is
 * deployed. Anything off-shape, for another candidate, or not in state
 * `deployed` refuses before any request is made.
 */
export function validateTarget(raw, { candidateId }) {
  const d = exactObject(raw, 'the deployed target',
    ['candidateId', 'environment', 'state', 'sourceSha', 'imageDigest', 'appVersion', 'approvalSha256', 'deployedAt', 'publicOrigin'],
    ['publish', 'timeoutMs', 'allowLoopbackHttp', 'cookieFile']);
  if (d.candidateId !== candidateId) refuse('the controller receipt is for a different candidate');
  if (d.environment !== CONTRACT.environment) refuse('the controller receipt is for a different environment');
  if (d.state !== 'deployed') refuse(`the candidate is not deployed (state ${JSON.stringify(String(d.state).slice(0, 40))})`);
  if (!SHA1.test(d.sourceSha)) refuse('the receipt sourceSha must be a full 40-hex commit');
  if (!IMAGE_DIGEST.test(d.imageDigest)) refuse('the receipt imageDigest must be sha256:<64 hex>');
  if (d.appVersion !== d.sourceSha) refuse('the image must be built with APP_VERSION equal to the full source SHA');
  if (!SHA256.test(d.approvalSha256)) refuse('the receipt approvalSha256 must be 64 hex');
  if (!Number.isFinite(Date.parse(d.deployedAt))) refuse('the receipt deployedAt cannot be read');
  const timeoutMs = d.timeoutMs ?? 15_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > 120_000) refuse('timeoutMs must be 1000-120000');
  const target = {
    candidateId: d.candidateId,
    environment: d.environment,
    state: d.state,
    sourceSha: d.sourceSha,
    imageDigest: d.imageDigest,
    appVersion: d.appVersion,
    approvalSha256: d.approvalSha256,
    deployedAt: d.deployedAt,
    publicOrigin: normaliseOrigin(d.publicOrigin, { allowLoopbackHttp: d.allowLoopbackHttp === true, label: 'the pinned origin' }),
    timeoutMs,
    githubApiUrl: GITHUB_API,
    cookieFile: null,
    publish: null,
  };
  if (d.cookieFile !== undefined && d.cookieFile !== null) {
    if (typeof d.cookieFile !== 'string' || !path.isAbsolute(d.cookieFile)) refuse('cookieFile must be an absolute path');
    target.cookieFile = d.cookieFile;
  }
  if (d.publish !== undefined && d.publish !== null) {
    const p = exactObject(d.publish, 'publish', ['repository', 'stateBranch'], ['tokenFile', 'verifier', 'verifierApp', 'githubApiUrl']);
    if (typeof p.repository !== 'string' || !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(p.repository)) refuse('publish.repository must be owner/name');
    if (p.stateBranch !== STATE_BRANCH) refuse(`publish.stateBranch must be exactly ${STATE_BRANCH}, the branch .ade/config.json tells Station Zero to read`);
    target.publish = { repository: p.repository, stateBranch: STATE_BRANCH, tokenFile: null, verifier: null, verifierApp: null };
    if (p.tokenFile !== undefined && p.tokenFile !== null) {
      if (typeof p.tokenFile !== 'string' || !path.isAbsolute(p.tokenFile)) refuse('publish.tokenFile must be an absolute path');
      target.publish.tokenFile = p.tokenFile;
    }
    if (p.verifier !== undefined && p.verifier !== null) {
      if (typeof p.verifier !== 'string' || !LOGIN.test(p.verifier)) refuse('publish.verifier must be a GitHub login');
      target.publish.verifier = p.verifier;
    }
    if (p.verifierApp !== undefined && p.verifierApp !== null) {
      if (!Number.isSafeInteger(p.verifierApp) || p.verifierApp < 1) refuse('publish.verifierApp must be a positive GitHub App id');
      target.publish.verifierApp = p.verifierApp;
    }
    if (target.publish.verifier && target.publish.verifierApp) refuse('publish pins either a verifier login or a verifier app, not both');
    if (p.githubApiUrl !== undefined) {
      target.githubApiUrl = normaliseOrigin(p.githubApiUrl, { allowLoopbackHttp: d.allowLoopbackHttp === true, label: 'publish.githubApiUrl' });
    }
  }
  return target;
}

export function runningImageMatches(observed, digest) {
  return observed?.running === true
    && IMAGE_DIGEST.test(observed.imageId ?? '')
    && (observed.imageId === digest || (Array.isArray(observed.repoDigests) && observed.repoDigests.some((d) => typeof d === 'string' && d.endsWith(`@${digest}`))));
}

/** The controller's own accessors: the only way a target, a running image or a backend request is learned. */
export async function loadControllerProvider() {
  const controller = await import('./release-controller.mjs');
  for (const name of ['loadAcceptanceTarget', 'inspectRunningImage', 'confirmBackendRequest', 'proveRouteBinding']) {
    if (typeof controller[name] !== 'function') refuse(`the release controller does not export ${name}`);
  }
  return {
    loadAcceptanceTarget: controller.loadAcceptanceTarget,
    inspectRunningImage: controller.inspectRunningImage,
    confirmBackendRequest: controller.confirmBackendRequest,
    proveRouteBinding: controller.proveRouteBinding,
  };
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

/** Replace anything that must not reach a record, an evidence file or a log. */
export function makeScrubber(secrets = []) {
  const needles = secrets.filter((s) => typeof s === 'string' && s.length >= 4);
  return (text) => {
    let out = String(text);
    for (const needle of needles) out = out.split(needle).join('[redacted]');
    return out
      .replace(/https?:\/\/[^\s"']+/gi, '[url]')
      .replace(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[email]')
      .replace(/\/home\/[^\s"']+/g, '[path]')
      .slice(0, 800);
  };
}

export function createClient({ origin, fetchImpl = globalThis.fetch, timeoutMs = 15_000, cookie = null }) {
  async function request(method, requestPath, { json, auth = false, binary = false, timeoutMs: override } = {}) {
    if (typeof requestPath !== 'string' || !requestPath.startsWith('/') || requestPath.startsWith('//')) refuse('internal: request path must be origin-relative');
    const url = new URL(requestPath, origin);
    if (url.origin !== origin) refuse('internal: request left the pinned origin');
    const headers = { accept: binary ? '*/*' : 'application/json' };
    if (auth) {
      if (!cookie) refuse('internal: an authenticated request was made without a session cookie');
      headers.cookie = `${COOKIE_NAME}=${cookie}`;
    }
    let body;
    if (json !== undefined) {
      headers['content-type'] = 'application/json';
      body = JSON.stringify(json);
    }
    const response = await fetchImpl(url, { method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(override ?? timeoutMs) });
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length > MAX_RESPONSE_BYTES) throw new Error('response too large');
    if (binary) return { status: response.status, bytes };
    const text = bytes.toString('utf8');
    let parsed = null;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }
    return { status: response.status, json: parsed };
  }
  return { request };
}

// ---------------------------------------------------------------------------
// STL: a closed solid, not just bytes
// ---------------------------------------------------------------------------

/**
 * A binary STL that is a closed, consistently oriented, positive-volume solid
 * with plausible bin extents. Every directed edge must occur exactly once and be
 * matched by its reverse (a closed 2-manifold), no triangle may be degenerate,
 * and the signed volume must be positive. This proves the generator emitted a
 * valid solid of bin size; it does not by itself prove any cavity (see
 * `bin-generate-roundtrip`, which compares two pockets).
 */
export function inspectBinaryStl(bytes) {
  if (bytes.length < 84) return { ok: false, detail: 'too short to be an STL' };
  const triangles = bytes.readUInt32LE(80);
  if (triangles < 100) return { ok: false, detail: `only ${triangles} triangles` };
  if (bytes.length !== 84 + triangles * 50) return { ok: false, detail: 'size does not match the triangle count (not binary STL)' };
  const index = new Map();
  const vertices = [];
  const idOf = (x, y, z) => {
    const key = `${x},${y},${z}`;
    let id = index.get(key);
    if (id === undefined) {
      id = vertices.length;
      index.set(key, id);
      vertices.push([x, y, z]);
    }
    return id;
  };
  const edges = new Map();
  const faces = [];
  for (let t = 0; t < triangles; t += 1) {
    const base = 84 + t * 50 + 12;
    const ids = [];
    for (let v = 0; v < 3; v += 1) {
      const x = bytes.readFloatLE(base + v * 12);
      const y = bytes.readFloatLE(base + v * 12 + 4);
      const z = bytes.readFloatLE(base + v * 12 + 8);
      if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(z)) return { ok: false, detail: 'non-finite vertex' };
      ids.push(idOf(x, y, z));
    }
    if (ids[0] === ids[1] || ids[1] === ids[2] || ids[0] === ids[2]) return { ok: false, detail: 'degenerate triangle' };
    faces.push(ids);
    for (let e = 0; e < 3; e += 1) {
      const key = `${ids[e]}>${ids[(e + 1) % 3]}`;
      edges.set(key, (edges.get(key) ?? 0) + 1);
    }
  }
  for (const [key, count] of edges) {
    if (count !== 1) return { ok: false, detail: 'an edge is used more than once in the same direction (not a consistently oriented solid)' };
    const [a, b] = key.split('>');
    if (edges.get(`${b}>${a}`) !== 1) return { ok: false, detail: 'an edge has no opposite edge (the surface is not closed)' };
  }
  let volume = 0;
  const min = [Infinity, Infinity, Infinity];
  const max = [-Infinity, -Infinity, -Infinity];
  for (const [x, y, z] of vertices) {
    min[0] = Math.min(min[0], x); max[0] = Math.max(max[0], x);
    min[1] = Math.min(min[1], y); max[1] = Math.max(max[1], y);
    min[2] = Math.min(min[2], z); max[2] = Math.max(max[2], z);
  }
  for (const [ia, ib, ic] of faces) {
    const [ax, ay, az] = vertices[ia];
    const [bx, by, bz] = vertices[ib];
    const [cx, cy, cz] = vertices[ic];
    volume += (ax * (by * cz - bz * cy) - ay * (bx * cz - bz * cx) + az * (bx * cy - by * cx)) / 6;
  }
  if (!(volume > 0)) return { ok: false, detail: 'the solid has no positive volume' };
  const extent = max.map((m, i) => m - min[i]);
  // A 2 x 2 grid, 4 unit bin is about 83.5 x 83.5 x 28+ mm.
  const plausible = extent[0] > 70 && extent[0] < 90 && extent[1] > 70 && extent[1] < 90 && extent[2] > 10 && extent[2] < 80;
  if (!plausible) return { ok: false, detail: `implausible extents ${extent.map((e) => e.toFixed(0)).join('x')} mm` };
  return { ok: true, volume, detail: `closed solid, ${triangles} triangles, ${extent.map((e) => e.toFixed(0)).join('x')} mm` };
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

const PASS = 'pass';
const FAIL = 'fail';
const SKIPPED = 'skipped';

const unauthenticatedPaths = ['/api/auth/me', '/api/sessions', '/api/tools', '/api/bins', '/api/bin-projects', '/api/admin/storage-stats'];
const newMarker = () => `acceptance_nonce=${randomBytes(16).toString('hex')}`;
const sleep = (ms) => (ms > 0 ? new Promise((resolve) => setTimeout(resolve, ms)) : Promise.resolve());

/** A marker must appear in the inspected container's own request log; retried briefly because logging trails the response. */
async function backendSaw({ confirmBackend, marker, sinceIso, retryDelayMs }) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const answer = await confirmBackend({ marker, sinceIso });
    if (answer?.seen === true) return true;
    await sleep(retryDelayMs);
  }
  return false;
}

/**
 * Run the contract against the controller-pinned target. The cookie is read and
 * used only after the candidate is proven to be the one running: the receipt, the
 * running image, the served version, then the route bound to that container by a
 * nonce in its own log. A failed gate skips every later check, so a wrong or
 * undetermined deployment never receives the session.
 */
export async function executeChecks({
  target, readCookie, inspect, confirmBackend, proveRoute, fetchImpl, scrub, now = () => new Date(), retryDelayMs = 500,
  generationTimeoutMs = GENERATION_TIMEOUT_MS,
}) {
  const results = new Map(CONTRACT.requiredChecks.map((id) => [id, { status: SKIPPED, detail: 'not run' }]));
  const set = (id, status, detail) => results.set(id, { status, detail: scrub(detail) });
  const runFail = (id, error) => set(id, FAIL, error instanceof Error ? error.message : String(error));

  set('deployed-identity', PASS, 'the controller receipt names this candidate as deployed');
  const anon = createClient({ origin: target.publicOrigin, fetchImpl, timeoutMs: target.timeoutMs });

  // gate 2: what is running right now
  let first = null;
  try {
    first = await inspect();
    if (runningImageMatches(first, target.imageDigest)) set('running-image', PASS, 'the running container image equals the receipt digest');
    else set('running-image', FAIL, first?.running ? 'the running image does not match the receipt digest' : 'the container is not running');
  } catch (error) {
    runFail('running-image', error);
  }

  let health = FAIL;
  try {
    // The combined container routes only /api/ and /storage/ to the backend, so
    // /health is not reachable through the public origin; the unauthenticated
    // auth status is the reachable proof that the backend answers.
    const response = await anon.request('GET', '/api/auth/status');
    health = response.status === 200 && typeof response.json?.mode === 'string' ? PASS : FAIL;
  } catch {
    health = FAIL;
  }

  // gate 3: what the app says it is
  if (results.get('running-image').status === PASS) {
    try {
      const version = await anon.request('GET', '/api/version');
      if (version.status === 200 && version.json?.version === target.sourceSha) set('served-identity', PASS, 'the served build is the deployed commit');
      else set('served-identity', FAIL, version.status === 200 ? 'the served build is not the deployed commit' : `version endpoint answered ${version.status}`);
    } catch (error) {
      runFail('served-identity', error);
    }
  }

  // gate 4: the public route reaches THE inspected container. The served version
  // is self-reported, so it alone cannot tell a redirected route from the real one.
  // The controller proves the signed ingress and DNS are unchanged, the container is
  // the deployed one, and a nonce sent through the route appears in its own log; then
  // a nonce of this script must appear there too.
  if (results.get('served-identity').status === PASS) {
    try {
      const proof = await proveRoute();
      if (proof?.bound !== true || proof.candidateId !== target.candidateId || (proof.imageId && first?.imageId && proof.imageId !== first.imageId)) {
        set('route-bound', FAIL, 'the controller did not prove the public route is bound to the deployed container');
      } else {
        const marker = newMarker();
        const sinceIso = new Date(now().getTime() - 5_000).toISOString();
        const through = await anon.request('GET', `/api/version?${marker}`);
        if (through.status !== 200 || through.json?.version !== target.sourceSha) {
          set('route-bound', FAIL, 'the answer through the route is not the deployed commit');
        } else if (await backendSaw({ confirmBackend, marker, sinceIso, retryDelayMs })) {
          set('route-bound', PASS, 'the controller proved the route binding and a nonce sent through it appeared in the inspected container log');
        } else {
          set('route-bound', FAIL, 'a nonce sent through the public route did not appear in the inspected container log: the route may not reach the deployed container');
        }
      }
    } catch (error) {
      runFail('route-bound', error);
    }
  }

  const gateOpen = ['deployed-identity', 'running-image', 'served-identity', 'route-bound'].every((id) => results.get(id).status === PASS);
  if (gateOpen) {
    await unauthenticatedChecks({ anon, set, runFail });
    const session = await authenticatedChecks({ target, readCookie, fetchImpl, set, runFail, now, generationTimeoutMs });
    try {
      const second = await inspect();
      const same = second?.imageId === first.imageId && runningImageMatches(second, target.imageDigest);
      set('running-image-stable', same ? PASS : FAIL, same ? 'the running image did not change during the run' : 'the running image changed or stopped during the run');
    } catch (error) {
      runFail('running-image-stable', error);
    }
    // Only a session that got through every authenticated step is judged here. It
    // needs BOTH its first and its final request seen in the container log, and the
    // final request must have succeeded: a missing or failed final request fails.
    if (session.reachedEnd) {
      try {
        const proof = await proveRoute();
        const bothMarkers = typeof session.start === 'string' && typeof session.end === 'string';
        const startSeen = bothMarkers && await backendSaw({ confirmBackend, marker: session.start, sinceIso: session.sinceIso, retryDelayMs });
        const endSeen = bothMarkers && await backendSaw({ confirmBackend, marker: session.end, sinceIso: session.sinceIso, retryDelayMs });
        if (session.endStatus !== 200) {
          set('route-stable', FAIL, `the final authenticated request did not succeed (${session.endStatus === 0 ? 'transport error' : `HTTP ${session.endStatus}`}), so the route could not be confirmed after the run`);
        } else if (proof?.bound !== true || proof.candidateId !== target.candidateId) {
          set('route-stable', FAIL, 'after the run the controller no longer proves the public route is bound to the deployed container');
        } else if (startSeen && endSeen) {
          set('route-stable', PASS, 'the route binding still held and the first and last authenticated requests both appeared in the inspected container log');
        } else {
          set('route-stable', FAIL, 'an authenticated request did not appear in the inspected container log: the route changed or does not reach the deployed container');
        }
      } catch (error) {
        runFail('route-stable', error);
      }
    }
  }
  return { results, health, finishedAt: now() };
}

async function unauthenticatedChecks({ anon, set, runFail }) {
  try {
    const status = await anon.request('GET', '/api/auth/status');
    const body = status.json ?? {};
    if (status.status === 200 && body.mode === 'native' && body.setup_required === false && body.authenticated === false) {
      set('setup-closed', PASS, 'native mode, no first-run setup advertised');
    } else {
      set('setup-closed', FAIL, status.status === 200 && body.setup_required === true
        ? 'first-run setup is OPEN: anyone reaching the app could become administrator'
        : `unexpected auth status (HTTP ${status.status}, mode ${JSON.stringify(String(body.mode).slice(0, 20))})`);
    }
  } catch (error) {
    runFail('setup-closed', error);
  }
  try {
    const bad = [];
    for (const p of unauthenticatedPaths) {
      const response = await anon.request('GET', p);
      if (response.status !== 401) bad.push(`${p} answered ${response.status}`);
    }
    if (bad.length === 0) set('unauthenticated-refused', PASS, `${unauthenticatedPaths.length} protected endpoints answered 401 without a session`);
    else set('unauthenticated-refused', FAIL, bad.join('; '));
  } catch (error) {
    runFail('unauthenticated-refused', error);
  }
}

async function authenticatedChecks({ target, readCookie, fetchImpl, set, runFail, now, generationTimeoutMs }) {
  const session = { start: null, end: null, endStatus: null, reachedEnd: false, sinceIso: new Date(now().getTime() - 5_000).toISOString() };
  let cookie;
  try {
    cookie = readCookie();
  } catch (error) {
    runFail('session-authenticated', error);
    return session;
  }
  const client = createClient({ origin: target.publicOrigin, fetchImpl, timeoutMs: target.timeoutMs, cookie });
  let me = null;
  const startMarker = newMarker();
  session.start = startMarker;
  try {
    const status = await client.request('GET', '/api/auth/status', { auth: true });
    const account = await client.request('GET', `/api/auth/me?${startMarker}`, { auth: true });
    if (account.status === 401 || status.json?.authenticated !== true) {
      set('session-authenticated', FAIL, 'the supplied session was rejected; the operator must provide a fresh protected cookie');
      return session;
    }
    if (status.status === 200 && account.status === 200 && typeof account.json?.id === 'string' && account.json.disabled === false) {
      me = account.json;
      set('session-authenticated', PASS, 'the native session authenticates an enabled account');
    } else {
      set('session-authenticated', FAIL, `unexpected session answers (${status.status}, ${account.status})`);
      return session;
    }
  } catch (error) {
    runFail('session-authenticated', error);
    return session;
  }

  try {
    const stats = await client.request('GET', '/api/admin/storage-stats', { auth: true });
    if (me.is_admin === false && stats.status === 403) set('least-privilege', PASS, 'the acceptance account is not an administrator and the admin surface refuses it');
    else set('least-privilege', FAIL, me.is_admin ? 'the session belongs to an administrator; use a dedicated non-admin account' : `admin surface answered ${stats.status}, expected 403`);
  } catch (error) {
    runFail('least-privilege', error);
  }

  try {
    const lists = [['/api/sessions', 'sessions'], ['/api/tools', 'tools'], ['/api/bin-projects', 'projects'], ['/api/bins', 'bins']];
    const bad = [];
    for (const [p, key] of lists) {
      const response = await client.request('GET', p, { auth: true });
      if (response.status !== 200 || !Array.isArray(response.json?.[key])) bad.push(`${p} answered ${response.status}`);
    }
    if (bad.length === 0) set('library-read', PASS, 'the account library lists answer with their expected shape');
    else set('library-read', FAIL, bad.join('; '));
  } catch (error) {
    runFail('library-read', error);
  }

  await roundTrip({ client, set, runFail, candidateId: target.candidateId, generationTimeoutMs });

  // the last authenticated request: proves the route still reaches the container.
  // It must itself succeed; a failed or missing one is a failure, not a skipped check.
  const endMarker = newMarker();
  session.end = endMarker;
  session.reachedEnd = true;
  try {
    const last = await client.request('GET', `/api/auth/me?${endMarker}`, { auth: true });
    session.endStatus = last.status;
  } catch {
    session.endStatus = 0;
  }
  return session;
}

const rect = (x0, y0, x1, y1) => [{ x: x0, y: y0 }, { x: x1, y: y0 }, { x: x1, y: y1 }, { x: x0, y: y1 }];
const POCKETS = Object.freeze([
  { label: 'large', points: rect(20, 20, 50, 40) },
  { label: 'small', points: rect(20, 20, 30, 30) },
]);

/** Statuses where the proxy gave up but the backend may still be generating. */
const uncertainGeneration = (response) => [502, 503, 504].includes(response.status)
  && !/remote export failed/i.test(String(response.json?.detail ?? ''));

/**
 * Create two synthetic bins in the acceptance account with a large and a small
 * rectangular pocket, generate each with the candidate's geometry pipeline,
 * download and inspect the STL, and require the larger pocket to remove
 * materially more volume. Then delete what is certainly finished and prove it is
 * gone. The backend does not serialize DELETE with generation, so a bin whose
 * generation outcome is uncertain (transport timeout or error after submission,
 * or a proxy timeout) is never deleted here: that could race a still-running
 * worker and recreate output. It is reported as an uncertain leftover.
 */
async function roundTrip({ client, set, runFail, candidateId, generationTimeoutMs }) {
  const created = [];
  const uncertain = [];
  const volumes = {};
  let failure = null;
  try {
    for (const pocket of POCKETS) {
      const name = `tracefinity-acceptance-${candidateId.slice(0, 24)}-${pocket.label}-${randomBytes(4).toString('hex')}`;
      const made = await client.request('POST', '/api/bins', {
        auth: true,
        json: { name, tool_ids: [], bin_config: { grid_x: 2, grid_y: 2, height_units: 4 } },
      });
      if (made.status !== 200 || typeof made.json?.id !== 'string' || !/^[0-9a-f-]{36}$/.test(made.json.id)) {
        failure = `creating the ${pocket.label} bin answered ${made.status}`;
        break;
      }
      const binId = made.json.id;
      created.push(binId);
      const placed = await client.request('PUT', `/api/bins/${binId}`, {
        auth: true,
        json: { placed_tools: [{ id: randomBytes(8).toString('hex'), tool_id: '', name: `acceptance-${pocket.label}`, points: pocket.points }] },
      });
      if (placed.status !== 200) {
        failure = `placing the ${pocket.label} pocket answered ${placed.status}`;
        break;
      }
      let generated;
      try {
        generated = await client.request('POST', `/api/bins/${binId}/generate`, { auth: true, timeoutMs: generationTimeoutMs });
      } catch (error) {
        // Submitted, but whether the server finished is unknown.
        uncertain.push(binId);
        failure = `generation of the ${pocket.label} bin did not complete over the transport (${error instanceof Error ? error.name : 'error'}); its outcome is uncertain`;
        break;
      }
      if (uncertainGeneration(generated)) {
        uncertain.push(binId);
        failure = `generation of the ${pocket.label} bin ended at the proxy with ${generated.status}; the backend may still be generating`;
        break;
      }
      if (generated.status !== 200) {
        failure = generated.status === 502
          ? 'generation answered 502: the bin was generated but the configured remote export failed'
          : `generation of the ${pocket.label} bin answered ${generated.status}`;
        break;
      }
      const stl = await client.request('GET', `/api/files/bins/${binId}/bin.stl`, { auth: true, binary: true, timeoutMs: generationTimeoutMs });
      if (stl.status !== 200) {
        failure = `downloading the ${pocket.label} STL answered ${stl.status}`;
        break;
      }
      const inspected = inspectBinaryStl(stl.bytes);
      if (!inspected.ok) {
        failure = `the ${pocket.label} STL is not a valid solid: ${inspected.detail}`;
        break;
      }
      volumes[pocket.label] = inspected.volume;
    }
    if (failure === null) {
      const delta = volumes.small - volumes.large;
      if (!(delta >= MIN_POCKET_VOLUME_DELTA)) {
        failure = `the larger pocket did not remove materially more volume (${Math.round(delta)} mm3, need ${MIN_POCKET_VOLUME_DELTA}); the pocket geometry is not being generated`;
      }
    }
    if (failure === null) {
      const listed = await client.request('GET', '/api/bins', { auth: true });
      const shown = created.every((id) => listed.json?.bins?.some?.((b) => b.id === id && b.has_stl === true));
      if (!shown) failure = 'the bin list does not show the generated STLs';
    }
    if (failure === null) set('bin-generate-roundtrip', PASS, `two pockets generated closed solids; the larger removed ${Math.round(volumes.small - volumes.large)} mm3 more`);
    else set('bin-generate-roundtrip', FAIL, failure);
  } catch (error) {
    runFail('bin-generate-roundtrip', error);
  } finally {
    await cleanup({ client, set, created, uncertain });
  }
}

async function cleanup({ client, set, created, uncertain }) {
  if (created.length === 0) {
    set('cleanup-verified', SKIPPED, 'no synthetic bin was created');
    return;
  }
  const certain = created.filter((id) => !uncertain.includes(id));
  const problems = [];
  try {
    for (const id of certain) {
      const removed = await client.request('DELETE', `/api/bins/${id}`, { auth: true });
      const gone = await client.request('GET', `/api/bins/${id}`, { auth: true });
      const stl = await client.request('GET', `/api/files/bins/${id}/bin.stl`, { auth: true, binary: true });
      if (removed.status !== 200 || gone.status !== 404 || stl.status !== 404) problems.push(`bin ${id} (delete ${removed.status}, read ${gone.status}, stl ${stl.status})`);
    }
    const listed = await client.request('GET', '/api/bins', { auth: true });
    for (const id of certain) {
      if (listed.json?.bins?.some?.((b) => b.id === id) ?? true) problems.push(`bin ${id} is still listed`);
    }
  } catch (error) {
    problems.push(`cleanup failed: ${error instanceof Error ? error.message : 'error'}`);
  }
  if (uncertain.length > 0) {
    set('cleanup-verified', FAIL, `generation outcome is uncertain for leftover bin ${uncertain.join(', ')}; it was NOT deleted because the server may still be generating and deleting now could race it. Inspect it and remove it only after generation has ended${problems.length ? `; also: ${problems.join('; ')}` : ''}`);
  } else if (problems.length > 0) {
    set('cleanup-verified', FAIL, `cleanup incomplete: ${problems.join('; ')}; remove the leftover synthetic bin by hand`);
  } else {
    set('cleanup-verified', PASS, 'the synthetic bins and their STLs are deleted and no longer listed');
  }
}

// ---------------------------------------------------------------------------
// Record
// ---------------------------------------------------------------------------

/**
 * Pure: the record and evidence for one run. `authenticated.state` is `passed`
 * only when every required check passed; nothing here can turn a skipped or
 * absent check into a pass.
 */
export function buildRecord({ target, run, runId, startedAt }) {
  const { results, health, finishedAt } = run;
  const status = (id) => results.get(id).status;
  const ids = (wanted) => CONTRACT.requiredChecks.filter((id) => status(id) === wanted);
  const evidence = {
    schemaVersion: 1,
    kind: 'tracefinity.acceptance-evidence',
    candidateId: target.candidateId,
    runId,
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    checks: CONTRACT.requiredChecks.map((id) => ({ id, status: status(id), detail: results.get(id).detail })),
  };
  const evidenceBytes = JSON.stringify(evidence, null, 2);
  const identityChecks = ['deployed-identity', 'running-image', 'served-identity', 'route-bound'].map(status);
  const probeChecks = ['setup-closed', 'unauthenticated-refused'].map(status);
  const contractHash = contractSha256();
  const passed = ids(PASS);
  const failed = ids(FAIL);
  const skipped = ids(SKIPPED);
  const record = {
    schemaVersion: 1,
    environment: CONTRACT.environment,
    candidateId: target.candidateId,
    health: health === PASS ? 'pass' : 'fail',
    probe: {
      result: probeChecks.includes(FAIL) ? 'fail' : probeChecks.every((s) => s === PASS) ? 'pass' : 'unknown',
      runId,
    },
    preflight: {
      verdict: identityChecks.includes(FAIL) ? 'fail' : identityChecks.every((s) => s === PASS) ? 'pass' : 'unknown',
      contractSha256: contractHash,
      runId,
      at: startedAt.toISOString(),
      expiresAt: new Date(startedAt.getTime() + PREFLIGHT_TTL_MS).toISOString(),
    },
    authenticated: {
      state: passed.length === CONTRACT.requiredChecks.length ? 'passed' : failed.length > 0 ? 'failed' : 'unknown',
      required: [...CONTRACT.requiredChecks],
      passed,
      failed,
      skipped,
      boundTo: {
        sourceSha: target.sourceSha,
        imageDigests: { [SERVICE]: target.imageDigest },
        environment: CONTRACT.environment,
        runId,
        planSha256: target.approvalSha256,
        contractSha256: contractHash,
      },
      evidenceSha256: sha256(evidenceBytes),
      at: finishedAt.toISOString(),
      maxAgeSeconds: MAX_AGE_SECONDS,
    },
  };
  return { record, evidenceBytes };
}

const RECORD_KEYS = ['schemaVersion', 'environment', 'candidateId', 'health', 'probe', 'preflight', 'authenticated'];

/**
 * Assess a record against the controller-pinned target. `problems` are binding or
 * contract violations. `missing` are the reasons it is not VERIFIED LIVE-eligible.
 * `eligible` mirrors Station Zero's derivation plus this repository's rules: every
 * contract check required and passed, bound to the deployed commit, image digest
 * and approval, and newer than the deployment. `/api/auth/me` alone can never
 * satisfy it: the required set is the whole contract.
 */
export function assessRecord(record, { target, now = new Date() }) {
  const problems = [];
  const missing = [];
  const problem = (message) => problems.push(message);
  const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
  if (!isObj(record)) return { problems: ['the record is not an object'], missing, eligible: false };
  for (const key of Object.keys(record)) {
    if (!RECORD_KEYS.includes(key)) problem(`unexpected field ${JSON.stringify(key.slice(0, 40))} (the record must not carry overall or a waiver)`);
  }
  for (const key of RECORD_KEYS) if (!(key in record)) problem(`missing ${key}`);
  if (problems.length > 0) return { problems, missing, eligible: false };

  if (record.schemaVersion !== 1) problem('schemaVersion must be 1');
  if (record.environment !== CONTRACT.environment) problem('wrong environment');
  if (record.candidateId !== target.candidateId) problem('the record is for another candidate');
  const auth = record.authenticated;
  const pre = record.preflight;
  const probe = record.probe;
  if (!isObj(auth) || !isObj(pre) || !isObj(probe)) return { problems: [...problems, 'malformed sections'], missing, eligible: false };
  const required = Array.isArray(auth.required) ? auth.required : [];
  if (required.length !== CONTRACT.requiredChecks.length || !CONTRACT.requiredChecks.every((id) => required.includes(id))) {
    problem('required checks differ from the contract (a record must require every contract check)');
  }
  const bound = auth.boundTo;
  if (bound !== undefined) {
    if (!isObj(bound)) problem('boundTo is malformed');
    else {
      if (bound.sourceSha !== target.sourceSha) problem('bound to a different source commit than the deployed one');
      if (JSON.stringify(bound.imageDigests) !== JSON.stringify({ [SERVICE]: target.imageDigest })) problem('bound to a different image digest than the deployed one');
      if (bound.planSha256 !== target.approvalSha256) problem('bound to a different approval than the deployed one');
      if (bound.contractSha256 !== contractSha256() || pre.contractSha256 !== contractSha256()) problem('bound to a different verification contract');
      if (bound.environment !== CONTRACT.environment) problem('bound to a different environment');
      if (String(bound.runId) !== String(pre.runId) || String(probe.runId) !== String(pre.runId)) problem('probe, preflight and evidence are from different runs');
    }
  }
  if (auth.state === 'passed' && bound === undefined) problem('a passed record must be bound to the deployed identity');
  if (auth.state === 'passed' && !SHA256.test(auth.evidenceSha256 ?? '')) problem('a passed record must carry its evidence digest');
  if (problems.length > 0) return { problems, missing, eligible: false };

  if (record.health !== 'pass') missing.push(`health is ${record.health}`);
  if (pre.verdict !== 'pass') missing.push(`preflight is ${pre.verdict}`);
  if (auth.state !== 'passed') missing.push(`authenticated acceptance is ${auth.state}`);
  if ((auth.failed ?? []).length > 0) missing.push(`failed: ${auth.failed.join(', ')}`);
  if ((auth.skipped ?? []).length > 0) missing.push(`skipped: ${auth.skipped.join(', ')}`);
  const notPassed = required.filter((id) => !(auth.passed ?? []).includes(id));
  if (notPassed.length > 0) missing.push(`required but not passed: ${notPassed.join(', ')}`);
  if (bound === undefined) missing.push('not bound to the deployed identity');
  const at = Date.parse(auth.at ?? '');
  if (!Number.isFinite(at) || !Number.isInteger(auth.maxAgeSeconds)) missing.push('no timestamp or maximum age');
  else {
    const age = now.getTime() - at;
    if (age < -FUTURE_SKEW_MS) missing.push('the evidence is dated in the future');
    else if (age > auth.maxAgeSeconds * 1000) missing.push('the evidence is stale');
    if (at < Date.parse(target.deployedAt)) missing.push('the evidence predates the deployment');
  }
  return { problems, missing, eligible: missing.length === 0 };
}

/** Last line of defence: nothing that looks like a location, address or credential reaches a record. */
export function assertNoLeak(text, secrets = []) {
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length >= 4 && text.includes(secret)) refuse('the record contains a secret; refusing');
  }
  if (/https?:\/\//i.test(text) || /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(text)
      || /\/home\//.test(text) || /BEGIN [A-Z ]*PRIVATE KEY/.test(text) || /tracefinity_auth=/.test(text) || /tfadm_/.test(text)) {
    refuse('the record contains a URL, address, path or credential; refusing');
  }
}

// ---------------------------------------------------------------------------
// Publication: an existing branch whose writers are provably restricted
// ---------------------------------------------------------------------------

export const acceptancePath = (candidateId) => `acceptance/${candidateId}.json`;

/**
 * Whether a branch-protection answer restricts pushes to exactly the pinned
 * verifier. `protected: true` is not evidence of this: a protected branch with
 * no push restriction can be written by anyone with write access, and a forged
 * record there would be read by Station Zero as the real one. Every control that
 * could let another identity write must be present, and anything absent or
 * unreadable fails closed. Returns the reasons it is not established.
 */
export function writerRestrictionProblems(protection, verifier) {
  const problems = [];
  const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
  if (!isObj(protection)) return ['branch protection could not be read'];
  const restrictions = protection.restrictions;
  if (!isObj(restrictions)) problems.push('pushes are not restricted to named actors (anyone with write access could publish)');
  else {
    const users = Array.isArray(restrictions.users) ? restrictions.users : null;
    const teams = Array.isArray(restrictions.teams) ? restrictions.teams : null;
    const apps = Array.isArray(restrictions.apps) ? restrictions.apps : null;
    if (!users || !teams || !apps) problems.push('the push restriction list cannot be read');
    else {
      if (teams.length > 0) problems.push('a team is allowed to push');
      if (apps.length > 0) problems.push('an app is allowed to push');
      const logins = users.map((u) => String(u?.login ?? '').toLowerCase());
      if (logins.length !== 1 || logins[0] !== String(verifier).toLowerCase()) problems.push('the allowed pushers are not exactly the pinned verifier');
    }
  }
  if (protection.enforce_admins?.enabled !== true) problems.push('administrators are not subject to the restriction');
  if (protection.allow_force_pushes?.enabled !== false) problems.push('force pushes are not disabled');
  if (protection.allow_deletions?.enabled !== false) problems.push('branch deletion is not disabled');
  return problems;
}

/**
 * Every read-only check that must hold before a record is written: the pinned
 * repository is the one the host reports, the branch exists, is not the default,
 * is protected, the token is the pinned verifier, only that verifier can push,
 * administrators are bound, and no ruleset grants anyone a bypass. Rulesets are not
 * used as proof of restriction (their reach cannot be evaluated here); any active
 * ruleset with a bypass actor, or one that cannot be read, fails closed. A GitHub
 * administrator can always reconfigure the repository: that is the trust boundary.
 */
export async function verifyPublicationTarget({ target, token, fetchImpl = globalThis.fetch }) {
  if (!target.publish) refuse('the controller policy names no repository and state branch to publish to');
  const { repository, stateBranch: branch, verifier, verifierApp } = target.publish;
  if (!verifier && !verifierApp) refuse('the controller policy pins no verifier identity (a GitHub login, or a GitHub App for a personal repository) to publish as');
  const api = async (method, apiPath, body) => {
    const url = new URL(apiPath, target.githubApiUrl);
    if (url.origin !== target.githubApiUrl) refuse('internal: publication request left the API origin');
    const response = await fetchImpl(url, {
      method,
      headers: {
        accept: 'application/vnd.github+json',
        authorization: `Bearer ${token}`,
        'x-github-api-version': '2022-11-28',
        ...(body ? { 'content-type': 'application/json' } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      redirect: 'manual',
      signal: AbortSignal.timeout(target.timeoutMs),
    });
    const text = await response.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return { status: response.status, json };
  };
  const repo = `/repos/${repository}`;
  const encodedBranch = branch.split('/').map(encodeURIComponent).join('/');

  if (verifier) {
    // a user token: it must be the pinned verifier's (an installation token has no /user)
    const me = await api('GET', '/user');
    if (me.status !== 200 || typeof me.json?.login !== 'string') refuse(`the publication token's identity could not be read (HTTP ${me.status})`);
    if (me.json.login.toLowerCase() !== verifier.toLowerCase()) refuse('the publication token does not belong to the pinned verifier identity');
  }

  const info = await api('GET', repo);
  if (info.status !== 200) refuse(`the repository could not be read (HTTP ${info.status})`);
  if (typeof info.json?.full_name !== 'string' || info.json.full_name.toLowerCase() !== repository.toLowerCase()) {
    refuse('the pinned repository is not the repository the host reports; refusing to publish');
  }
  if (info.json?.archived === true) refuse('the pinned repository is archived');
  if (info.json?.default_branch === branch || ['main', 'master'].includes(branch)) refuse('the state branch must not be the default branch');
  const state = await api('GET', `${repo}/branches/${encodedBranch}`);
  if (state.status === 404) refuse('the state branch does not exist; it is created by the operator, never by this publisher');
  if (state.status !== 200) refuse(`the state branch could not be read (HTTP ${state.status})`);
  if (verifier) {
    // Organisation-owned repository: push restrictions on branch protection.
    if (state.json?.protected !== true) refuse('the state branch is not protected');
    const protection = await api('GET', `${repo}/branches/${encodedBranch}/protection`);
    if (protection.status !== 200) {
      refuse(`branch protection could not be read (HTTP ${protection.status}); the verifier identity needs administration read access to prove who can write. Not publishing`);
    }
    const restricted = writerRestrictionProblems(protection.json, verifier);
    if (restricted.length > 0) refuse(`the state branch does not restrict who can write: ${restricted.join('; ')}`);

    const rulesets = await api('GET', `${repo}/rulesets?includes_parents=true&per_page=100`);
    if (rulesets.status !== 200 || !Array.isArray(rulesets.json)) refuse(`rulesets could not be read (HTTP ${rulesets.status}); not publishing`);
    if (rulesets.json.length >= 100) refuse('too many rulesets to examine; not publishing');
    for (const ruleset of rulesets.json) {
      if (ruleset?.enforcement === 'disabled') continue;
      if (!Number.isInteger(ruleset?.id)) refuse('a ruleset could not be identified; not publishing');
      const detail = await api('GET', `${repo}/rulesets/${ruleset.id}`);
      if (detail.status !== 200 || !Array.isArray(detail.json?.bypass_actors)) refuse(`ruleset ${ruleset.id} could not be read in full; not publishing`);
      if (detail.json.bypass_actors.length > 0) refuse(`ruleset ${ruleset.id} grants bypass actors; not publishing`);
    }
  } else {
    // Personal repository: branch protection push restrictions are organisation-only,
    // so the restriction is a repository ruleset whose only bypass actor is the pinned app.
    await verifyRulesetRestrictsToApp({ api, repo, encodedBranch, appId: verifierApp });
  }
  return { api, repo, branch };
}

const RULESET_REQUIRED_RULES = Object.freeze(['update', 'deletion', 'non_fast_forward']);

/**
 * Why a ruleset does not confine writes to the pinned GitHub App. A repository
 * ruleset applies to everyone, repository administrators and the owner included,
 * except its bypass list, so one active branch ruleset that restricts updates,
 * deletion and force pushes and bypasses only the pinned app leaves that app as
 * the sole writer. Any other bypass actor (a role, a team, another app, a deploy
 * key), a bypass limited to pull requests, or a ruleset that is not active and
 * branch-targeted, does not establish it.
 */
export function rulesetWriterProblems(detail, appId) {
  const problems = [];
  const isObj = (v) => v && typeof v === 'object' && !Array.isArray(v);
  if (!isObj(detail)) return ['the ruleset could not be read'];
  if (detail.enforcement !== 'active') problems.push('the ruleset is not active');
  if (detail.target !== 'branch') problems.push('the ruleset does not target branches');
  const kinds = new Set(Array.isArray(detail.rules) ? detail.rules.map((r) => r?.type) : []);
  for (const type of RULESET_REQUIRED_RULES) if (!kinds.has(type)) problems.push(`the ruleset does not include the ${type} rule`);
  for (const rule of Array.isArray(detail.rules) ? detail.rules : []) {
    if (rule?.type === 'update') problems.push(...updateRuleProblems(rule));
  }
  const actors = detail.bypass_actors;
  if (!Array.isArray(actors)) problems.push('the bypass list cannot be read');
  else if (actors.length !== 1) problems.push(`the bypass list has ${actors.length} actors, not exactly the pinned app`);
  else {
    const [actor] = actors;
    if (actor?.actor_type !== 'Integration' || actor.actor_id !== appId) problems.push('the only bypass actor is not the pinned app');
    if (actor?.bypass_mode !== 'always') problems.push('the pinned app bypasses only for pull requests, not for direct writes');
  }
  return problems;
}

/**
 * The `update` rule carries `parameters.update_allows_fetch_and_merge`: when true,
 * a branch may take changes from its upstream repository (a fork syncing) without
 * bypass permission, so the rule would not confine writes to the bypass list. It
 * must be exactly false, or absent (the documented default); true or anything
 * malformed fails closed.
 */
export function updateRuleProblems(rule) {
  const parameters = rule?.parameters;
  if (parameters === undefined || parameters === null) return [];
  if (typeof parameters !== 'object' || Array.isArray(parameters)) return ['the update rule parameters are malformed'];
  const flag = parameters.update_allows_fetch_and_merge;
  if (flag === undefined || flag === false) return [];
  if (flag === true) return ['the update rule allows fetch-and-merge updates without bypass (update_allows_fetch_and_merge is true)'];
  return ['the update rule update_allows_fetch_and_merge is malformed'];
}

/**
 * Fail closed unless GitHub itself reports (rules that apply to this branch) a
 * repository ruleset that restricts updates, deletion and force pushes, and that
 * ruleset's bypass list is exactly the pinned app. Other rulesets can only add
 * restrictions, so they are not examined. Nothing is inferred from `protected`.
 */
async function verifyRulesetRestrictsToApp({ api, repo, encodedBranch, appId }) {
  const rules = await api('GET', `${repo}/rules/branches/${encodedBranch}`);
  if (rules.status !== 200 || !Array.isArray(rules.json)) refuse(`the rules that apply to the branch could not be read (HTTP ${rules.status}); not publishing`);
  const byRuleset = new Map();
  const flagged = new Map();
  for (const rule of rules.json) {
    if (rule?.ruleset_source_type !== 'Repository' || !Number.isInteger(rule.ruleset_id) || typeof rule.type !== 'string') continue;
    if (!byRuleset.has(rule.ruleset_id)) byRuleset.set(rule.ruleset_id, new Set());
    byRuleset.get(rule.ruleset_id).add(rule.type);
    if (rule.type === 'update') {
      const bad = updateRuleProblems(rule);
      if (bad.length > 0) flagged.set(rule.ruleset_id, bad);
    }
  }
  const candidates = [...byRuleset]
    .filter(([id, types]) => !flagged.has(id) && RULESET_REQUIRED_RULES.every((type) => types.has(type)))
    .map(([id]) => id);
  if (candidates.length === 0) {
    const why = [...flagged].map(([id, bad]) => `ruleset ${id}: ${bad.join(', ')}`).join('; ');
    refuse(`no repository ruleset applies to the state branch that restricts updates, deletion and force pushes; anyone with write access could publish${why ? ` (${why})` : ''}. Not publishing`);
  }
  const reasons = [];
  for (const id of candidates) {
    const detail = await api('GET', `${repo}/rulesets/${id}`);
    if (detail.status !== 200) {
      reasons.push(`ruleset ${id} could not be read in full (HTTP ${detail.status}); the app needs administration read access`);
      continue;
    }
    const problems = rulesetWriterProblems(detail.json, appId);
    if (problems.length === 0) return;
    reasons.push(`ruleset ${id}: ${problems.join(', ')}`);
  }
  refuse(`the state branch does not confine writes to the pinned app: ${reasons.join('; ')}`);
}

/**
 * Write the record to the repository's state branch over the contents API after
 * re-verifying, immediately before the write, that only the pinned verifier can
 * write it. It never creates, moves or deletes a branch: it only adds a commit to
 * a branch the operator created and restricted.
 */
export async function publishRecord({ recordText, target, token, fetchImpl = globalThis.fetch }) {
  if (Buffer.byteLength(recordText) > MAX_RECORD_BYTES) refuse('the record is larger than 64 KiB');
  const { api, repo, branch } = await verifyPublicationTarget({ target, token, fetchImpl });
  const file = acceptancePath(target.candidateId);
  const contentsPath = `${repo}/contents/${file.split('/').map(encodeURIComponent).join('/')}`;
  const existing = await api('GET', `${contentsPath}?ref=${encodeURIComponent(branch)}`);
  if (existing.status !== 200 && existing.status !== 404) refuse(`the existing record could not be read (HTTP ${existing.status})`);
  const put = await api('PUT', contentsPath, {
    message: `acceptance(${target.candidateId}): authenticated record`,
    content: Buffer.from(recordText).toString('base64'),
    branch,
    ...(existing.status === 200 && existing.json?.sha ? { sha: existing.json.sha } : {}),
  });
  if (put.status !== 200 && put.status !== 201) refuse(`the record was not accepted (HTTP ${put.status})`);

  const back = await api('GET', `${contentsPath}?ref=${encodeURIComponent(branch)}`);
  const stored = back.status === 200 && typeof back.json?.content === 'string'
    ? Buffer.from(back.json.content.replace(/\n/g, ''), 'base64').toString('utf8')
    : null;
  if (stored !== recordText) refuse('the published record could not be read back identically');
  return { file, commit: String(put.json?.commit?.sha ?? '').slice(0, 40) };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const FLAGS = {
  run: ['candidate', 'out-dir'],
  publish: ['candidate'],
};

export function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (!FLAGS[command]) refuse('usage: tracefinity-acceptance.mjs <run|publish> --candidate ID [--out-dir DIR (run only)]');
  const args = { command };
  for (let i = 0; i < rest.length; i += 1) {
    const flag = rest[i];
    if (!flag.startsWith('--') || !FLAGS[command].includes(flag.slice(2))) refuse(`unknown argument ${flag.slice(0, 40)}`);
    const next = rest[i + 1];
    if (next === undefined || next.startsWith('--')) refuse(`${flag} needs a value`);
    args[flag.slice(2)] = next;
    i += 1;
  }
  if (!CANDIDATE.test(args.candidate ?? '')) refuse('--candidate must be a plain candidate id');
  return args;
}

/**
 * One fresh acceptance run against the controller-pinned target. This is the only
 * way a record comes into existence: the checks run here, the record is built from
 * their results, and there is no entry point that accepts a record from a file.
 */
async function freshRun({ target, controller, fetchImpl, now, options, err, retryDelayMs, generationTimeoutMs, extraSecrets = [] }) {
  const startedAt = now();
  const runId = `run-${startedAt.toISOString().replace(/[-:.]/g, '').slice(0, 15)}-${randomBytes(4).toString('hex')}`;
  let cookieValue = null;
  const readCookie = () => {
    if (!target.cookieFile) refuse('the controller policy names no session cookie file');
    cookieValue = loadCookie(target.cookieFile, options);
    return cookieValue;
  };
  const secrets = () => [cookieValue, ...extraSecrets, target.publicOrigin, new URL(target.publicOrigin).hostname];
  const run = await executeChecks({
    target,
    readCookie,
    inspect: () => controller.inspectRunningImage(),
    confirmBackend: (query) => controller.confirmBackendRequest(query),
    proveRoute: () => controller.proveRouteBinding({ candidateId: target.candidateId }),
    fetchImpl,
    scrub: (text) => makeScrubber(secrets())(text),
    now,
    retryDelayMs,
    generationTimeoutMs,
  });
  const { record, evidenceBytes } = buildRecord({ target, run, runId, startedAt });
  const recordText = `${JSON.stringify(record, null, 2)}\n`;
  assertNoLeak(recordText + evidenceBytes, secrets());
  for (const id of CONTRACT.requiredChecks) {
    const r = run.results.get(id);
    err(`${r.status.toUpperCase().padEnd(7)} ${id}: ${r.detail}`);
  }
  const assessment = assessRecord(record, { target, now: now() });
  if (assessment.problems.length > 0) refuse(`internal: the fresh record does not bind to the deployed candidate: ${assessment.problems.join('; ')}`);
  return { record, recordText, evidenceBytes, assessment };
}

export async function main(argv = process.argv.slice(2), {
  out = (t) => process.stdout.write(`${t}\n`), err = (t) => process.stderr.write(`${t}\n`),
  fetchImpl = globalThis.fetch, provider = null, now = () => new Date(), repoRoot = REPO_ROOT, retryDelayMs = 500,
  generationTimeoutMs = GENERATION_TIMEOUT_MS,
} = {}) {
  const args = parseArgs(argv);
  const options = { repoRoot };
  const controller = provider ?? await loadControllerProvider();
  for (const name of ['loadAcceptanceTarget', 'inspectRunningImage', 'confirmBackendRequest', 'proveRouteBinding']) {
    if (typeof controller[name] !== 'function') refuse(`the release controller does not provide ${name}`);
  }
  let rawTarget;
  try {
    rawTarget = await controller.loadAcceptanceTarget({ candidateId: args.candidate });
  } catch (error) {
    if (error?.code === 'private_deployment') {
      refuse('the candidate is deployed privately (no verified public route); authenticated acceptance cannot run and nothing is published, so the release stays ACCEPTANCE INCOMPLETE');
    }
    refuse('the controller could not establish a deployed candidate; inspect release status before acceptance');
  }
  const target = validateTarget(rawTarget, { candidateId: args.candidate });

  if (args.command === 'publish') {
    // Everything needed to publish is proven before the session cookie is used.
    if (!target.publish?.tokenFile) refuse('the controller policy names no token file to publish with');
    const token = loadToken(target.publish.tokenFile, options);
    await verifyPublicationTarget({ target, token, fetchImpl });
    const { record, recordText, assessment } = await freshRun({ target, controller, fetchImpl, now, options, err, retryDelayMs, generationTimeoutMs, extraSecrets: [token] });
    if (record.authenticated.state === 'passed') {
      // A passing record is only published while the candidate is still what runs.
      const observed = await controller.inspectRunningImage();
      if (!runningImageMatches(observed, target.imageDigest)) refuse('the running image changed after the checks; not publishing a passing record');
      let proof;
      try {
        proof = await controller.proveRouteBinding({ candidateId: target.candidateId });
      } catch (error) {
        refuse(`the route binding could not be re-proved before publishing: ${error instanceof Error ? error.message.slice(0, 200) : 'error'}`);
      }
      if (proof?.bound !== true || proof.candidateId !== target.candidateId) refuse('the public route is no longer proved bound to the deployed container; not publishing a passing record');
    }
    const result = await publishRecord({ recordText, target, token, fetchImpl });
    err(assessment.eligible
      ? `published ${result.file}: authenticated acceptance PASSED, eligible for VERIFIED LIVE`
      : `published ${result.file}: authenticated acceptance NOT passed (${assessment.missing.join('; ')}); the release stays ACCEPTANCE INCOMPLETE`);
    return assessment.eligible ? 0 : 1;
  }

  const { recordText, evidenceBytes, assessment } = await freshRun({ target, controller, fetchImpl, now, options, err, retryDelayMs, generationTimeoutMs });
  if (args['out-dir']) {
    const dir = path.resolve(args['out-dir']);
    if (inside(path.resolve(repoRoot), dir)) refuse('--out-dir must be outside the repository checkout');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    if (inside(realpathSync(repoRoot), realpathSync(dir))) refuse('--out-dir must be outside the repository checkout');
    writeFileSync(path.join(dir, `${args.candidate}.json`), recordText, { mode: 0o600 });
    writeFileSync(path.join(dir, `${args.candidate}.evidence.json`), evidenceBytes, { mode: 0o600 });
  } else {
    out(recordText.trimEnd());
  }
  err(assessment.eligible
    ? `authenticated acceptance PASSED for ${args.candidate}: run \`publish\` to record it (a fresh run is performed)`
    : `authenticated acceptance NOT passed for ${args.candidate}: ${assessment.missing.join('; ')}`);
  return assessment.eligible ? 0 : 1;
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main().then(
    (code) => { process.exitCode = code; },
    (error) => {
      process.stderr.write(`${error instanceof Refusal ? 'refused: ' : 'failed: '}${error instanceof Error ? error.message : 'unknown error'}\n`);
      process.exitCode = error instanceof Refusal ? 2 : 1;
    },
  );
}
