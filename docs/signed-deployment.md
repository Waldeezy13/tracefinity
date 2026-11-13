# Signed deployment and authenticated acceptance

This runbook covers how a Tracefinity release reaches a live instance and how
that instance is then proven to work. Deployment and acceptance are separate
facts and are reported with separate words:

| Word | Meaning | Established by |
|-|-|-|
| DEPLOYED | The signed cutover finished, health passed, and the running image is the signed one | The release controller's durable receipt |
| ACCEPTANCE INCOMPLETE | Deployed, but no passing acceptance record exists for exactly this candidate | Station Zero, reading the record |
| ACCEPTANCE UNKNOWN | Deployed, and the record cannot be read | Station Zero |
| VERIFIED LIVE | An authenticated end-to-end run, bound to the deployed commit, image digest and approval, passed every required check and is fresh | The acceptance record, derived by Station Zero |
| WAIVED / NOT APPLICABLE | Stated as exactly that, never as verified | Station Zero |

A green deployment, a healthy probe, a working login page or a valid
`/api/auth/me` never make a release VERIFIED LIVE. Only the record described
below can, and `overall` is never a field in it: Station Zero derives the state
from the record every time.

Nobody is asked to sign in, pass MFA or relay a browser as a routine check.
Operator involvement is limited to the real manual deployment signature and to
keeping an already-issued session cookie current in a protected file.

## What lives where

The repository contains the controller, the acceptance script, their tests and
this document. It contains no host, address, user name, key, cookie, token,
container name or filesystem location of any deployment. Everything private is in
operator-owned files outside the checkout, readable only by the operator's
account:

| Item | Where it comes from |
|-|-|
| Public signing key, deployment target, receipts location, public origin | The release controller's fixed, owner-only trust policy outside the repository. Nothing on the command line or in the environment can replace it |
| Session cookie file, publication token file, the record repository and exactly one pinned verifier: `verifier` (a GitHub login, organisation-owned repository) or `verifierApp` (a GitHub App id, personal repository) | The optional `acceptance` block of that same policy. Its state branch must be exactly `production-state`: anything else is refused, because Station Zero reads records only from the branch `.ade/config.json` names and a record published elsewhere would be silently missed |
| Candidate, source commit, image digest, approval digest | The controller's durable receipt for the candidate, read through the policy |
| What is running right now, and whether the public route reaches it | The controller's own read-only access to the target: `inspectRunningImage`, `proveRouteBinding` (signed ingress and DNS unchanged, same container, a nonce in that container's own request log) and `confirmBackendRequest` (a nonce of this script in the container's own log) |

`scripts/tracefinity-acceptance.mjs` takes only `--candidate` (which receipt to
read; it must match) and, for `run`, `--out-dir`. It has no option, and reads no
environment variable, that names a target, receipt, URL, digest, token or
credentials file, and it has no way to accept a record from a file. A hostile
environment or a hand-written receipt or record cannot point the run at a
different instance, make it believe a different image is live, or promote a
pass that was not just earned.

Credential files named by the policy are refused unless they are absolute, not
symbolic links, regular files owned by the running user, not readable by group or
others, and outside the repository checkout.

## Release policy and commands

The operator installs the public verification key and target in
`~/.config/station-zero/tracefinity-release-policy.json`. The file must be owned
by the account running the controller, mode `0600`, with no symlink components;
its directory must not be group- or world-writable. The controller never creates
or reads a signing key. Export and verify the raw Ed25519 public key through a
trusted channel. Do not copy the signing key, passphrase or credentials into
the policy or repository.

The following is a schema example, not an installed policy. Replace every
placeholder with an operator-verified value. Keep the real file private.

```json
{
  "schemaVersion": 1,
  "kind": "tracefinity.release-policy",
  "publicKeyBase64": "RAW_ED25519_PUBLIC_KEY_BASE64",
  "source": { "repository": "OWNER/REPOSITORY", "branch": "main" },
  "build": { "platform": "linux/amd64", "imageRepository": "tracefinity-release" },
  "target": {
    "kind": "unraid-docker",
    "nodePath": "/usr/bin/node",
    "receiptsRoot": "/absolute/private/receipts",
    "dockerPath": "/usr/bin/docker",
    "ssh": {
      "host": "TARGET_HOST",
      "port": 22,
      "user": "TARGET_USER",
      "identityFile": "/absolute/private/ssh-identity",
      "hostKey": "SSH_HOST_KEY_TYPE SSH_HOST_KEY_BASE64"
    },
    "container": {
      "name": "tracefinity",
      "hostPort": 3000,
      "storagePath": "/absolute/target/storage",
      "puid": 1000,
      "pgid": 1000
    },
    "exposure": { "mode": "private" }
  }
}
```

Confirm the SSH host key independently on the target. The storage directory
must exist before deployment. Optional container fields are `envFile`, `env`,
`mounts`, `memory` and `cpus`. Put credentials in the target's protected
`envFile` or protected mounts, never in policy `env`. The optional `acceptance`
object names `cookieFile`, `timeoutMs` and `publish`; `publish` contains
`repository`, `stateBranch`, `tokenFile` and exactly one of `verifier` or
`verifierApp`. Keep those files outside the checkout. See
[automatic remote export](usage/exporting.md#automatic-remote-export)
for rclone configuration.

For public mode, replace `exposure` with an object containing `mode: "public"`,
`publishAddress`, `lanUrl`, `publicUrl`, `publicStatus`, and `ingress`.
`ingress` contains `provider: "cloudflare-tunnel"`, `accountId`, `zoneId`,
`tunnelId`, `hostname`, `service`, `apiTokenFile` and `singleWriter: true`.
The hostname must match the public URL; the service must use the configured host
port. `publishAddress` must be a specific non-loopback IPv4 address, not
`0.0.0.0`. The token file is operator-owned and mode `0600`, with tunnel-edit
and DNS-read permissions. The remotely managed tunnel must have a catch-all;
its proxied CNAME must already point to the tunnel. Preparation reads these
settings but does not change them. The builder also needs Docker buildx.

Cloudflare's tunnel update API replaces the entire configuration and documents
no conditional update. `singleWriter: true` is the operator's attestation that
no other person or automation will change that tunnel during the signed
cutover. A concurrent write can be overwritten even when the version check
later detects it. Do not attest unless all other writers are stopped or
otherwise serialized. A local lock cannot enforce this across Cloudflare.

From the managed Release Task checkout, after the repair has merged:

```sh
node scripts/release-controller.mjs prepare --candidate UNIQUE_ID \
  --source FULL_CURRENT_MAIN_SHA --triggering-merge FULL_TRIGGERING_MERGE_SHA
node scripts/release-controller.mjs status --candidate UNIQUE_ID
```

IDs use lowercase letters, digits and hyphens. Preparation requires the exact
current remote integration commit containing the triggering merge. It exports
and tests that commit in isolation, builds and saves the image, and binds its
digest, target and previous state to the approval. It neither moves the checkout
nor alters the target or tunnel. The approval expires one hour after preparation;
an expired candidate needs a new ID and signature.

The operator signs the exact approval in Station Zero's signing panel. The panel
submits the candidate; the controller verifies the signature and expiry again
before dispatch and target changes. `status` without a candidate reports the
durable deployment receipt. A failed or uncertain cutover is not deployment;
inspect the receipt, worker journal, container and tunnel before recovery.
Never delete a lock or perform an unsigned rollback to force a retry.

An older preserved Release checkout can bootstrap the merged controller from a
fresh bare object database without moving its branch or using its Git
configuration or replacement refs:

```sh
bootstrap_dir=$(mktemp -d)
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_NO_REPLACE_OBJECTS=1
git init --bare "$bootstrap_dir/objects.git"
git --git-dir="$bootstrap_dir/objects.git" fetch --no-tags \
  https://github.com/OWNER/REPOSITORY.git FULL_CURRENT_MAIN_SHA
git --git-dir="$bootstrap_dir/objects.git" archive --format=tar \
  FULL_CURRENT_MAIN_SHA scripts/release-controller.mjs | tar -x -C "$bootstrap_dir"
node "$bootstrap_dir/scripts/release-controller.mjs" prepare --candidate UNIQUE_ID \
  --source FULL_CURRENT_MAIN_SHA --triggering-merge FULL_TRIGGERING_MERGE_SHA
```

Prepare and sign a private candidate first on a fresh installation. Provision
the administrator on the private container as described below. Then change the
private policy to public mode, prepare a new candidate and obtain a new
signature before the controller activates the tunnel route.

## Before the instance is exposed

Do these in order, before the signed candidate that activates public access (see
[Tunnel and exposure](#tunnel-and-exposure)) is prepared.

1. **Create the first administrator out of band.** Tracefinity's browser setup
   page makes whoever reaches an empty instance first its administrator, with
   the existing library. On an exposed instance that is a takeover. Provision the
   administrator with the command in [Authentication](auth.md#creating-the-first-administrator-out-of-band):

   ```bash
   printf '%s' "$ADMIN_PASSWORD" | docker exec -i -w /app/backend --user tracefinity \
     <container> python -m app.cli create-admin --email admin@example.com
   ```

   The password is read from standard input, never an argument. Do not paste it
   anywhere a session, log or agent can read it.
2. **Disable first-run setup.** The deployment must run with
   `AUTH_SETUP_ENABLED=false`, `AUTH_MODE=native` and `AUTH_COOKIE_SECURE=true`.
   `POST /api/auth/setup` then returns 404 whatever the account store holds and
   `GET /api/auth/status` never advertises a first run. The controller forces
   these values on deploy; verify them anyway before opening the route.
3. **Create a dedicated, non-administrator acceptance account.** The acceptance
   run writes and deletes one synthetic bin in whichever account's session it
   uses, so use an ordinary member account created by the administrator
   (`/api/admin/users`). The run refuses an administrator session
   (`least-privilege`): an administrator cookie is too much power to keep in a
   file for a verifier.
4. **Log in yourself and save the cookie.** In your own browser or with your own
   terminal, log in as the acceptance account (completing its second factor if
   enabled). Copy the value of the `tracefinity_auth` cookie into the cookie
   file named by the policy, mode `0600`, owned by you, outside the checkout. The
   file holds exactly that one value. Neither the script nor an agent ever sees
   the password or the second factor, and an administrator API token
   (`tfadm_...`) is refused: it is not a login.
5. **Create the record branch yourself.** Station Zero reads records from
   `production-state` at `acceptance/<candidate>.json` (`releaseAcceptance` in
   `.ade/config.json`). Create it as an orphan branch (so it shares no history
   with the product):

   ```bash
   git switch --orphan production-state
   git commit --allow-empty -m "production-state: acceptance records"
   git push origin production-state
   ```

   Then restrict who can write to it. A record on this branch is read by Station
   Zero as the verifier's word, so **anyone who can write to it can forge a pass**.
   `protected: true` is not enough: a protected branch with no push restriction
   can still be written by anyone with write access. Which control is available
   depends on who owns the repository, and the policy pins exactly one of two
   verifier identities. Anything absent, unreadable or different refuses
   publication, and the boolean `protected` is never used as proof.

   **Organisation-owned repository (policy `verifier`, a GitHub login).** Push
   restrictions on branch protection exist only here. The publisher requires the
   branch protection API to show all of:
   - pushes restricted to exactly one user, the pinned `verifier`, with no teams
     and no apps allowed;
   - administrators subject to that restriction (`enforce_admins`);
   - force pushes and branch deletion disabled;
   - no active ruleset (including inherited ones) with any bypass actor, and every
     ruleset readable in full.

   It also requires the publication token to belong to that user (a dedicated
   machine user, not a person), which needs contents write and administration
   read on this repository.

   **Personal repository (policy `verifierApp`, a GitHub App id).** GitHub offers
   no push restriction on branch protection for user-owned repositories, so the
   only native control is a repository ruleset, which applies to everyone
   including the owner and administrators except its bypass list. Create one
   active branch ruleset targeting exactly `production-state` with the rules
   **Restrict updates**, **Restrict deletions** and **Block force pushes**, and a
   bypass list holding exactly one entry: the verifier GitHub App, set to **Always
   allow**. No role (not even Repository admin), team, other app or deploy key may
   be listed, and **For pull requests only** does not count. The publisher asks
   GitHub which rules apply to the branch, then reads that ruleset in full and
   requires all of this, and that the update rule does not allow fetch-and-merge
   (`update_allows_fetch_and_merge` false or unset: when true, a fork may take
   upstream changes into the branch without bypass, so the rule would not confine
   writes; true or malformed values fail closed). The App is installed on this repository only, with
   contents write and administration read. Its installation access token (valid
   for about an hour) is what the token file holds: your own tooling mints it
   shortly before each publish and rewrites the file (`0600`, outside the
   checkout); the App's private key never enters this repository or any agent
   session. A token that is not that App's simply cannot write, so a wrong token
   fails publication rather than weakening anything. The owner can still edit the
   ruleset, which is the trust boundary below. If neither control can be set up,
   **publishing is blocked**: there is no fallback to `protected: true` and no
   report of VERIFIED LIVE.

   The publisher also requires that the host reports the pinned repository name
   (not a rename or lookalike), that it is not archived, and that the branch
   exists and is not the default branch. It never creates, moves or deletes a
   branch, and no agent or Station Zero session creates this branch.
   **Trust boundary:** a GitHub repository or organisation administrator can
   always change these settings. This control proves what the settings are at
   publication time, not that an administrator cannot change them later.
6. **Create the publication identity** named in the policy (the machine user, or
   the GitHub App above), scoped to this repository, and store its token in the
   token file named by the policy (`0600`, outside the checkout). It is read only
   by `publish` and is never written anywhere.

## Lifecycle

1. **Prepare.** The release controller exports exact `main`, runs the trusted
   gate and builds the image pinned by digest, with
   `APP_VERSION=<full source commit>`. The candidate directory under
   `.approval/<candidate>/` is immutable and never committed.
2. **Sign.** Only the operator, through the Station Zero signing panel, signs
   the exact approval bytes with their real key. Agents never read or create a
   key and there is no unsigned path. A candidate expires after the controller's
   approval window; an expired or failed candidate needs a new one.
3. **Deploy.** The controller re-verifies the signature and every artifact
   immediately before each mutation, switches the container to the signed image
   and records the receipt only after the running image, version and health match.
   `status` reports `deployed` only from that receipt. Queued, signed and merged
   are not deployed. A failure after any mutation is `production_incomplete`,
   never success; there is no unsigned rollback.
4. **Accept.** Run the acceptance (below). It re-reads the receipt, asks the
   controller what is running and whether the public route provably reaches it,
   and only then uses the session cookie.
5. **Publish.** `publish` performs its own fresh run and writes exactly that
   record, pass or fail, to the protected branch. Station Zero reads it on its
   next facts poll and derives the state.

Never remove a deployment lock, replay a queued job or edit a receipt to force
a different outcome. Inspect the actual unit, container and receipt first.

## Running acceptance

```bash
node scripts/tracefinity-acceptance.mjs run --candidate <candidate> --out-dir <private-dir>
node scripts/tracefinity-acceptance.mjs publish --candidate <candidate>
```

`run` is a dry run for the operator: it prints or stores the record and writes
nothing to the repository. `publish` does not take a record. It performs a new
run against the controller-pinned target and publishes the record that run just
produced, so there is no way to publish a hand-edited, copied or older file, and
no `--record` option exists. A failed or incomplete run is still published, because
an honest failed record is what tells Station Zero why the release is ACCEPTANCE
INCOMPLETE. Everything `publish` needs (token, branch, protection) is proven
before the session cookie is used.

`--out-dir` (run only) must be outside the checkout and receives
`<candidate>.json` (the record) and `<candidate>.evidence.json` (the per-check
evidence whose sha256 the record carries), both `0600`. Without `--out-dir` the
record is printed to standard output and the per-check summary to standard error.

| Exit | Meaning |
|-|-|
| 0 | The fresh run passed and is eligible for VERIFIED LIVE (`publish`: and was published) |
| 1 | The run failed or is incomplete. Nothing is accepted (`publish`: the honest failed record was still published) |
| 2 | Refused: unsafe or unrecognised input, wrong or undeployed candidate, untrusted target, or an unprotected, missing or default record branch |

### What a run proves

The checks run in this order. A failed gate skips everything after it and the
session cookie is never sent to a deployment whose identity is not proven.

| Check | Proves | Fails when |
|-|-|-|
| `deployed-identity` | The controller's receipt, read through the pinned policy, says this candidate is `deployed` | Receipt missing, for another candidate, another environment or not deployed (refusal, exit 2) |
| `running-image` | The container running now is the receipt's image, read through the controller's own access to the target | Different digest, container not running, or target unreachable |
| `served-identity` | The app itself reports `/api/version` equal to the full source commit | Hidden version endpoint, different build |
| `route-bound` | The controller proves the signed ingress and DNS are unchanged and the route reaches the deployed container, and a fresh nonce sent through the route appears in that container's own request log | Any proof fails, the nonce is not in the container's log, or the answer through the route is not the deployed commit. No cookie is sent |
| `setup-closed` | `/api/auth/status` is native mode with no first run advertised | First-run setup is open, or another mode |
| `unauthenticated-refused` | Protected endpoints (`/api/auth/me`, sessions, tools, bins, projects, admin) answer 401 without a session | Anything other than 401, including a redirect (redirects are never followed) |
| `session-authenticated` | The supplied native session authenticates an enabled account | Cookie rejected or expired |
| `least-privilege` | The account is not an administrator and the admin surface refuses it | Administrator session |
| `library-read` | The account's session, tool, project and bin lists answer with their shape | Any list fails |
| `bin-generate-roundtrip` | Two synthetic bins (a large and a small rectangular pocket) are generated with the candidate's geometry pipeline and downloaded; each STL is a closed, consistently oriented, positive-volume solid of bin size (every edge matched by its reverse, no degenerate triangle), and the larger pocket removes materially more volume than the smaller | Any step fails, a surface is open, duplicated, degenerate or inverted, or the pocket does not change the volume |
| `cleanup-verified` | Every synthetic bin whose generation certainly ended is deleted, its STL is gone and it is no longer listed | Anything left behind, or generation whose outcome is uncertain (see below) |
| `running-image-stable` | The running image is unchanged after the authenticated work | Image changed or stopped during the run |
| `route-stable` | The route binding still holds after the run; the final authenticated request itself succeeded (HTTP 200); and both the first and the final authenticated requests appeared in the inspected container's log | The proof fails, the final request failed or never ran, or either request never reached that container. A session that never got through its authenticated steps leaves this check skipped, which also cannot pass |

`/api/auth/me` alone proves nothing: it is one of thirteen required checks, and a
record is built only from a run that executed the whole contract. The geometry
check proves the generator emits valid bin-sized solids that respond to the
pocket; it does not prove exact pocket dimensions or fit.

The setup route itself is never called: a probe could create an administrator on
an instance that was wrongly left open. Closure of setup is established from the
status endpoint plus the deployment configuration above.

### The record

Schema 1 (Station Zero's `acceptance-record`), published at
`acceptance/<candidate>.json`:

- `candidateId`, `environment` (`production`), `health`, `probe` and `preflight`
  (identity gates) all from this run.
- `authenticated.required` is the full contract; `passed`, `failed` and
  `skipped` partition it. `state` is `passed` only when every check passed.
- `authenticated.boundTo` carries the deployed `sourceSha`, the image digest, the
  signed approval digest (as `planSha256`), the run id and the contract's sha256.
  Station Zero checks that the source contains the triggering merge and equals the
  live commit; this script checks the digest and approval against the receipt.
- `evidenceSha256`, `at` and `maxAgeSeconds` (24 hours). The state returns to
  ACCEPTANCE INCOMPLETE on its own when the evidence ages out, and evidence older
  than the deployment is refused.
- No `overall`, no waiver, no URL, address, path, account detail, cookie or token.
  Writers refuse to emit anything matching those patterns.

Changing a check, adding or removing a required id changes the contract hash, so
earlier records stop matching. A required check is never dropped to make a
release read VERIFIED LIVE.

## Failure semantics

- **Not VERIFIED LIVE is the default.** Absent, unreadable, failed, partial,
  stale, wrong-candidate or unbound evidence is ACCEPTANCE INCOMPLETE or UNKNOWN
  and the release stays in Needs You. Publishing a failed record is allowed and
  expected: it says exactly what failed.
- **Deployment health does not move acceptance.** A deployed release with a
  failing acceptance remains DEPLOYED and is never rolled back automatically.
  Rollback or repair is a new reviewed candidate with a fresh signature.
- **Expired or rejected session.** `session-authenticated` fails and the rest are
  skipped. The remedy is for the operator to refresh the cookie file. Nobody
  requests a password or second factor, and the run is never retried in a loop.
- **Wrong image or version.** Nothing authenticated runs. Investigate the
  receipt and the target before anything else.
- **Cleanup failed.** Delete the leftover bin named `tracefinity-acceptance-...`
  from the acceptance account and run again.
- **Generation outcome uncertain.** Generation is allowed up to 120 seconds by the
  proxy, so the script waits 150 seconds. If the request ends by a transport
  timeout or error, or the proxy answers 502, 503 or 504 (other than the
  application's own remote-export 502), the server may still be generating, and
  the backend does not serialize deleting a bin with generating it. The script
  then does **not** delete that bin and does not claim cleanup: `cleanup-verified`
  fails and names the leftover bin. Inspect it, and remove it only after
  generation has ended (the bin's STL appears in the library, or the backend log
  shows the request finished).
- **Unreachable target.** An unreachable target is a failure, never "not running".
- **Private deployment.** A candidate whose exposure is private, or whose public
  routing was not applied and verified by the signed cutover, has no origin to
  run against. The controller refuses it, the script exits 2 and publishes
  nothing, and the release stays ACCEPTANCE INCOMPLETE until a signed cutover
  makes it reachable. It is never reported as accepted or as "not applicable".
- **Publish refused.** Missing, default or unprotected branch, a branch whose
  writers are not provably restricted to the pinned verifier, a token that is not
  the verifier's, unreadable protection or rulesets, a missing token file, a
  passing record while the running image changed or the route binding can no longer
  be proved, or a read-back that differs: nothing is written.

## Risks and limits

- **The run writes to a real library.** It creates and deletes two clearly
  named synthetic bins in the acceptance account. A crash between create and
  delete, or an uncertain generation, leaves a bin. Use a dedicated account so
  nothing else is affected.
- **A stored cookie is a standing credential.** It lasts up to 14 days sliding.
  Keep it `0600`, outside the checkout, in a dedicated non-administrator account,
  and revoke it by logging that account out or disabling the account. The script
  never logs out, so acceptance does not revoke what it uses.
- **The version endpoint is disclosed.** Identity is proven through
  `/api/version`, so `SHOW_APP_VERSION` must stay true; a hidden endpoint fails
  `served-identity`. The version is a commit hash.
- **Strict 401.** An unauthenticated protected request must be answered by the
  app with 401. If an access gateway answers first with a redirect or 403,
  `unauthenticated-refused` fails and, as no redirect is followed, so does the
  session path. Point the pinned origin at a route that reaches the app, not at
  a login page.
- **The origin is pinned, the app is not trusted.** The cookie is only sent to
  the policy's origin, over https (plain http only for loopback in tests), never
  through a redirect.
- **Records are public to whoever can read the branch.** They contain
  commits, digests and check names only.
- **The verifier is not an auditor of the deployment configuration.** It proves
  behaviour (no setup route advertised, protected endpoints refuse anonymous
  access) rather than reading the container environment. Keep the deployment
  environment as listed above.
- **Station Zero cannot compare digests.** That is what `running-image` and
  `running-image-stable` do, against the controller's own target access.
- **Route binding has a residual limit.** A transparent relay that forwards
  requests to the real container could pass the nonce check. The proof also
  depends on the pinned DNS, tunnel configuration and TLS endpoint remaining
  trustworthy. If an access gate blocks unauthenticated `/api/auth/status`,
  the binding is unprovable and the run fails closed.
- **The branch restriction is a point-in-time proof.** GitHub administrators can
  always reconfigure the repository, and the verifier identity holds
  administration read access. Review the branch settings after any permission
  change.

## Optional rclone export

`RCLONE_EXPORT_REMOTE` (see [Exporting](usage/exporting.md#automatic-remote-export))
is optional and disabled by default. If it is set on the deployment, every saved-bin
generation copies its files to the remote, including the acceptance run's
synthetic bin, and deleting the bin does not delete the remote copy. Two
consequences:

- A failing remote makes generation answer 502, so `bin-generate-roundtrip` fails.
  That is deliberate: a configured export that does not work is a deployment
  problem, not an acceptance pass.
- Files from acceptance runs accumulate on the remote under a directory named
  `tracefinity-acceptance-...`. Prune them periodically, or point the export at a
  location you are happy to prune.

The rclone configuration is a secret. Keep it in an owner-only file or secret
volume and set `RCLONE_CONFIG` to its container path; never commit it or place it
in a record.

## Tunnel and exposure

Public exposure is part of a signed deployment, never a side action.

- Creating, changing or removing a tunnel, route or access rule is a mutation of
  production. It is made only inside a fresh signed candidate and controller
  cutover, with the operator's real signature over the exact approval bytes. It is
  never done by hand, by an agent, by Station Zero or by this verifier, and no
  agent holds tunnel credentials.
- Route activation belongs in that candidate only after the checklist above:
  administrator provisioned out of band, first-run setup disabled, secure cookie
  on, acceptance account and protected branch ready. If the release controller
  does not implement signed route activation, **public exposure is blocked**.
  There is no manual workaround and no unsigned tunnel change.
- After the signed cutover, run acceptance. It exercises the origin the policy
  pins: a green run over an internal address proves the application, not that the
  public path is guarded, so the pinned origin must be the one the route serves.
- Treat a failed `setup-closed` as an emergency. Withdrawing exposure is also a
  signed change; report it, stop acceptance and investigate before anything is
  retried.
- The controller may withdraw a pre-existing signed route during replacement.
  If the approval expires before a compensating route change, it cannot make
  that change; the receipt reports the route as uncertain and needs operator
  action. The LAN health probe is not an authenticated browser login: secure
  cookies require the public HTTPS origin.
- Terminate TLS at the tunnel or proxy, keep `AUTH_COOKIE_SECURE=true`, and set
  `CORS_ORIGINS` only to the real front-end origin. A wildcard is refused under
  native authentication.
- Never publish the pinned origin, host names, addresses, container names or
  file locations in a record, issue, pull request or commit.

## Verification

`node --test tests/tracefinity-acceptance.test.mjs` runs deterministic tests
against local fakes of the Tracefinity API and of the GitHub API. They cover the
happy path, every failed gate, wrong image or version, a route that cannot be
proved bound (no credential sent), unauthenticated access, open setup, a rejected
session, an administrator session, repeated-triangle, open, inverted and
unpocketed STL output, transport and gateway timeouts during generation (no
delete is raced), failed cleanup, a changed running image, record tampering,
protected-but-unrestricted branches (teams, apps, extra users, unenforced admins,
force pushes, deletions, unreadable protection, ruleset bypass) and leak
scanning. No real service, credential or key is used.
