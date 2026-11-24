# Post-Quantum Validator Key Rotation and Compromise Recovery Assessment

Assessment of how postfiatd validator operators rotate signing keys and
recover from suspected compromise without downtime or double-signing,
at pinned postfiatd commit
`0085a1ff885d6a446369cf73a4430f75af22be55`
(2026-10-10, "Merge pull request #50 from postfiatorg/hotfix/upstream-hardening-1.0.9").

## The one-paragraph answer

The rotation machinery works, for classical keys. A validator's master
key signs a manifest naming an ephemeral signing key and a sequence
number; peers keep the highest-sequence valid manifest, discard the old
key, and never accept a lower sequence again. A compromised ephemeral
key is rotated out with a new manifest, a compromised master key is
revoked terminally with sequence `0xFFFFFFFF`, and a failed rotation
rolls back by publishing a newer manifest that reinstates the old key.
Every one of those paths was exercised in the simulator and held:
attacker validations after a rotation counted 0 of 590 (S2) and 0 of
600 after a revocation (S3), a duplicated token's double-sign was
flagged conflicting 100 of 100 times (S4), and every replay and forgery
was rejected on every peer (S6). The post-quantum part is the gap, not
the machinery: the pinned code admits exactly two key types
(`secp256k1`, `ed25519`), the public-key buffer is fixed at 33 bytes,
and a search of the pinned tree finds no post-quantum algorithm at
all — so a post-quantum signing key cannot be expressed in a manifest
today. Modelled with ML-DSA-65 (FIPS 204), a manifest would carry
10,522 bytes of key material against 194 for ed25519 (54.2x), and a
validation 5,261 against 97 (54.2x). Two operational gaps are real and
measured: a seed-mode validator has no rotation mechanism — rotating
means a new node identity, untrusted until the UNL is updated (30 of
120 ledgers untrusted in S8) — and rotating during a partition leaves
half the network unable to trust the new key, so the 80% quorum is not
met for ten ledgers (S10).

## How to reproduce

```sh
bash scripts/run_all.sh
```

Runs all 11 scenarios, builds the matrix and control measurements,
writes the pack manifest, regenerates `SHA256SUMS`, commits a
fresh-copy reproduction transcript into
`outputs/fresh-clone-reproduction.log`, re-runs everything in a scratch
copy for the determinism check, and verifies digests. Exit 0 means
every step passed.

```sh
bash scripts/verify_digests.sh
```

Verifies every committed file against `SHA256SUMS`. The transcript in
`outputs/fresh-clone-reproduction.log` is the same check run from a
fresh copy of the pack, with its full output and exit status.

## Layout

- `docs/source-inventory.md` — every cited source file, verified
  blob-by-blob against the pinned commit, with the exact lines used.
- `docs/environment.md` — the simulator, its fidelity to the pinned
  code, its stand-ins, and its limits.
- `docs/methodology.md` — labels (OBSERVED / SIMULATED / UNMEASURED),
  the severity rubric, determinism.
- `docs/control-inventory.md` — the 18 controls, with code citations
  and measured effectiveness.
- `docs/findings-report.md` — what the scenarios found, scenario by
  scenario.
- `docs/remediation-report.md` — prioritized operator remediations.
- `docs/decision-memo.md` — the sourced decision memo.
- `scenarios/` — the 11 scenario declarations (seed, ledgers, steps).
- `scripts/` — the simulator, harness, matrix builder, control
  measurer, manifest maker, reproduction-transcript maker, digest
  scripts, and `run_all.sh`.
- `outputs/` — unedited per-scenario CSV / JSON / log, the matrix,
  control measurements, the run manifest, and the fresh-copy
  reproduction transcript.
- `manifest.json`, `SHA256SUMS` — the pack inventory and digests.

## Results at a glance

| Scenario | Severity | Headline |
|---|---|---|
| S0 Baseline | INFO | 120/120 validations accepted, 0 missed, uptime 100.00% |
| S1 Scheduled rotation | INFO | 0 missed ledgers; rotation propagated to 10/10 peers in 2000 ms (4 gossip rounds) |
| S2 Emergency rotation | LOW | attacker validations accepted after rotation 0/590; operator missed 1 ledger; uptime 99.17% |
| S3 Master revocation | LOW | validations accepted after revocation 0/600; post-revocation manifests rejected stale 10/10 |
| S4 Duplicated token | MEDIUM | conflicting validations flagged 100/100; duplicate counted 0 |
| S5 Rollback | LOW | missed 10/120 ledgers; rollback accepted on 10/10 peers |
| S6 Replay / forgery | LOW | every replay and forgery rejected 10/10 on every peer |
| S7 Key-reuse / flood | LOW | key-reuse/version/domain rejected 10/10 each; config 3/3; untrusted flood held at 1000/1000 (5 oldest evicted) |
| S8 Seed-mode rotation | HIGH | new identity trusted 0/30 ledgers before the UNL update; 90/120 ledgers trusted overall |
| S9 PQ sizes | MEDIUM | ML-DSA-65 manifest 10,522 vs ed25519 194 bytes (54.2x); pinned code rejects the 1952-byte key on 10/10 peers |
| S10 Partition rotation | HIGH | validations accepted by 5/10 peers during the partition (quorum 8 not met); 10/10 after the heal |

Severity counts: 0 CRITICAL, 2 HIGH, 2 MEDIUM, 5 LOW, 2 INFO.
Controls: 18 measured, 0 unmeasured; every measured control stopped
100% of the attempts made against it in these scenarios. That is a
statement about these scripted attacks, not a claim that the system
is invulnerable — see `docs/findings-report.md` for what the numbers
do not cover.
