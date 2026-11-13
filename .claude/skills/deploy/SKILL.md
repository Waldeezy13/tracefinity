---
name: deploy
description: Prepare and operate a signature-gated Tracefinity release, including deployment and authenticated acceptance.
---

# Signed Tracefinity releases

Read `docs/signed-deployment.md` and the Station Zero workflow and release
instructions before preparing, submitting, or reporting a release. Use the
repository controller and the fixed operator-managed trust policy; never deploy
from a mutable tag or unverified source.

Prepare from the current integration commit containing the triggering merge.
Preserve the release checkout and candidate. The operator reviews and signs the
exact approval bytes through the Station Zero signing flow. Never read or create
signing keys, forge approval, bypass expiry or signature verification, or make
an unsigned deployment or rollback. A missing policy or signature is a stop.

Do not modify a live tunnel or expose first-run administrator setup. Report the
actual deployed SHA and health from the controller receipt. Authenticated
acceptance is a separate, candidate-bound record; a healthy deployment alone is
not VERIFIED LIVE. Follow the runbook for failure and recovery.
