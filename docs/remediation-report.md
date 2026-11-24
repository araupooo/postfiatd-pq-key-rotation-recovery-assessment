# Remediation report

Prioritized operator remediations. Each item names the finding it
answers (see `docs/findings-report.md`), the concrete action, and the
evidence for the expected effect. Severities are the scenario
severities; priority is by expected loss avoided.

## P0 — Run every validator on a token/manifest setup; never on a seed

- Finding: S8 (HIGH). A seed-mode validator has no rotation mechanism;
  rotating is an identity change, untrusted until the UNL is updated
  on every peer (30/120 ledgers untrusted in the model).
- Action: generate the master key offline, issue a manifest, and run
  the validator on `[validator_token]`. Keep the master secret offline
  and use it only to sign manifests. Do not start a new validator on
  `[validation_seed]` — conversion later costs the same identity
  change as rotating does.
- Evidence: `ValidatorKeys.cpp:35-91`; S8 (`outputs/S8.json`).

## P0 — Rotate only on a whole network; verify propagation before retiring the old key

- Finding: S10 (HIGH). Rotating inside a 5/5 partition left the new
  key trusted by 5/10 peers, below the 80% quorum, for 10 ledgers.
- Action: before any rotation, confirm the network is whole (all
  peers reachable, no ongoing partition). After publishing the new
  manifest, confirm the new sequence is visible on a quorum of peers
  (`validator_info` reports the sequence) before shutting down the
  old signing node. Retiring first is what turns partial propagation
  into a quorum loss.
- Evidence: S10 (`outputs/S10.json`); `ValidatorInfo.cpp:31-62`.

## P1 — Pre-stage the new key and manifest before every rotation

- Finding: S1 vs S2 (INFO vs LOW). A scheduled rotation with a
  pre-staged key lost 0 ledgers; the emergency rotation lost 1 ledger
  to the handover.
- Action: generate the new ephemeral keypair and the signed manifest
  ahead of the rotation window, distribute the manifest to the peers,
  and start the new signing node before stopping the old one. Keep the
  handover inside one ledger close (4000 ms in the model; the manifest
  propagated in 2000 ms).
- Evidence: S1, S2 (`outputs/S1.json`, `outputs/S2.json`).

## P1 — Treat a conflicting verdict as an incident, with a runbook

- Finding: S4 (MEDIUM). A duplicated token is flagged conflicting
  100/100 times, but nothing in the code excludes the validator or
  stops the double-signing.
- Action: alert on `ValStatus::conflicting` (and on `multiple`) from
  validation monitoring; the runbook is: identify the duplicated
  token, shut down one of the two nodes immediately, then rotate the
  ephemeral key (the token itself is now suspect — both copies held
  it) and publish the new manifest. Never run two nodes with one
  token, including during migrations and restores — check for a live
  copy before starting a restored node.
- Evidence: S4 (`outputs/S4.json`); `Validations.h:623-700`.

## P1 — Put the master key offline and rehearse revocation

- Finding: S3 (LOW) and the no-expiry finding. Revocation works
  (0/600 validations counted after it; post-revocation manifests
  stale 10/10), but only if the operator can publish it — and a
  compromised key stays valid until they do, because manifests never
  expire.
- Action: the master secret lives offline, never on the validating
  host. Pre-generate and safely store a signed revocation manifest
  (sequence `0xFFFFFFFF`) for each validator, so revocation is a
  publication, not a signing ceremony under pressure. Rehearse the
  revocation path: publish, confirm `validator_info` shows the
  revocation, confirm peers drop the validator. Keep the pre-signed
  revocation under the same access control as the master key — anyone
  who can publish it can remove the validator.
- Evidence: S3 (`outputs/S3.json`); `Manifest.cpp:226-241,640-700`.

## P2 — Add a rotation checklist with a rollback step

- Finding: S5 (LOW). A failed rotation cost 10 ledgers; the rollback
  (new manifest, higher sequence, old key reinstated) was accepted
  10/10 and issuance resumed.
- Action: every rotation plan includes the rollback manifest ready
  before the rotation starts (a manifest reinstating the current key
  at the next sequence, signed and held, not published). If the new
  node fails to start, publish the rollback manifest instead of
  improvising. Note the sequence never goes backwards — the rollback
  is a forward step that happens to name the old key.
- Evidence: S5 (`outputs/S5.json`); `Manifest.cpp:411-425,567-590`.

## P2 — Monitor for superseded-key and stale-manifest traffic

- Finding: S2, S6 (LOW). Attacker validations with a superseded key
  counted 0/590 and 0/600, and replayed manifests were stale 10/10 —
  but only a peer that looks will notice the attempts.
- Action: log and alert on `superseded_key` validation rejections,
  `stale` manifest dispositions, and `invalid` manifest dispositions
  from peers. A burst of any of them is evidence of compromise or
  misconfiguration, not noise: the old key is being used somewhere,
  or an old manifest is circulating.
- Evidence: S2, S6 (`outputs/S2.json`, `outputs/S6.json`).

## P3 — Plan the post-quantum key-type plumbing before promising rotation

- Finding: S9 (MEDIUM). A post-quantum signing key cannot be
  expressed in the pinned code at all; ML-DSA-65 would be 54.2x the
  ed25519 key material.
- Action: do not promise post-quantum rotation dates until the
  plumbing exists: a third `KeyType` member, a variable-length
  public-key representation replacing the fixed 33-byte buffer, manifest
  and validation serialization that tolerates 1952-byte keys and
  3309-byte signatures, and a UNL migration path (validators are keyed
  by master key). When that lands, re-run this pack's S9 against the
  new code before rotating any production validator.
- Evidence: S9 (`outputs/S9.json`); `KeyType.h:28-31`;
  `PublicKey.h:65`; `PublicKey.cpp:223-236`;
  `ValidationCreate.cpp:45-62`.
