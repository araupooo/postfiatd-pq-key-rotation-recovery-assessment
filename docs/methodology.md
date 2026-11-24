# Methodology

## Labels

Every measured claim in this pack carries one of three labels:

- **OBSERVED** — read directly from the pinned source (a constant, a
  check, a code path), with a file:line citation.
- **SIMULATED** — produced by the protocol simulator from scripted
  scenarios. The numbers are real outputs of the harness, but they
  describe the model, not a live network.
- **UNMEASURED** — verified in code but not exercised by any scenario.
  No number is claimed for it.

No claim in this pack is presented as a measurement of a live postfiatd
network. In this pack every control is MEASURED (18 of 18); there are
no UNMEASURED controls. Code paths no scenario exercises — the
validator-site fetch, the RPC handlers, the overlay gossip internals —
are listed in `docs/source-inventory.md` as code-verified only and are
not given numbers.

## How a scenario is built

1. The scenario file (`scenarios/S*.json`) declares an id, a title, a
   fixed seed, a peer count, a severity with its reason, the validator
   setup, and an ordered step list: `{"run": N}` advances N ledgers,
   `{"action": ...}` performs one operator or attacker action at the
   current ledger boundary.
2. `scripts/load_harness.py` runs the scenario against
   `scripts/simulator.py`, which implements the pipeline in
   `docs/environment.md`. The driver records every event (validation
   issuance, manifest publication, rotation, revocation, replay,
   forgery, partition, UNL update) with its virtual timestamp, ledger,
   actor, and outcome.
3. Per scenario the harness writes three files under `outputs/`:
   `S*-events.csv` (one row per event), `S*.json` (metrics, control
   measurements, final state, peer counters), and `S*.log` (unedited
   run log, including the full SHA-256 of the scenario file, the
   simulator and the harness, and the summary numbers).
4. `scripts/build_matrix.py` reads the 11 summary JSON files and builds
   the severity-ranked matrix (`outputs/matrix.json`, `outputs/matrix.md`).
5. `scripts/measure_controls.py` reads the same summaries and measures
   each control's effectiveness (`outputs/control-measurements.json`,
   `outputs/control-measurements.md`).
6. `scripts/make_manifest.py` writes `manifest.json` (SHA-256 per
   file, excluding the reproduction transcript — see below).
7. `scripts/make_reproduction_transcript.py` copies the pack to a
   fresh directory, runs the digest check there, and writes the full
   output plus the exit status to
   `outputs/fresh-clone-reproduction.log`.
8. `scripts/run_all.sh` runs steps 2-7, then re-runs the harness into
   a scratch copy and diffs every committed output (determinism
   check, including a regenerated transcript), regenerates
   `SHA256SUMS`, and verifies it.

## The reproduction transcript

`outputs/fresh-clone-reproduction.log` is the full output of the
digest check run from a fresh copy of the pack, with its exit status
and the pack's `manifest.json` SHA-256. It verifies every file listed
in `SHA256SUMS` except the transcript itself: the transcript records
the run and cannot verify its own future bytes, so it is excluded
from the verified set it records — and the exclusion is stated in the
transcript. The transcript is still covered by `SHA256SUMS` itself and
by the final `verify_digests.sh` run in `run_all.sh`. The transcript
contains no wall-clock time and no absolute paths (the fresh copy is
labelled `fresh-copy`), so it reproduces byte-identically; the
determinism check in `run_all.sh` verifies that.

## Determinism

The harness uses a virtual clock and fixed seeds (`20261125` for every
scenario). No wall clock, no network, no randomness outside the seeded
generator. Re-running `bash scripts/run_all.sh` produces byte-identical
outputs except `outputs/run_all.log`, which holds the wall-clock start
line and is excluded from digests. The determinism check in `run_all.sh`
verifies this on every run by diffing a second run in a scratch
directory.

## Severity rubric

The matrix percentage is a measurement; the severity is a judgment on
whether the attacker's or failure's goal was achieved:

| Severity | Meaning |
|---|---|
| CRITICAL | The attack achieves its goal (success at or near 100%), with no effective control in the way. |
| HIGH | The attack mostly succeeds (success >= 50%), or causes a severe but bounded and self-healing availability loss. |
| MEDIUM | The attack has a measurable but bounded effect (success >= 10%), or the behaviour is by design and the exposure is configuration trust rather than a control failure, or the run exposes a real asymmetry that needs an operator's attention. |
| LOW | The attack is contained by a control (success < 10%), or the control bounds the abuse even though the pre-cap share looks high. |
| INFO | No attack in this scenario (baseline / reference measurement). |

Counts in this pack: 0 CRITICAL, 2 HIGH, 2 MEDIUM, 5 LOW, 2 INFO.

## Control effectiveness

Effectiveness is the share of attack attempts a control stopped, counted
from the committed scenario outputs. Where a control was not the binding
constraint, the effectiveness is 0% and the note says why. A control no
scenario exercised is UNMEASURED, never assigned a number. In this pack
all 18 controls stopped 100% of the attempts made against them — which
is a statement about these scripted attacks in this model, not a claim
that the controls are unbreakable. The severities carry the real
findings: the controls held, but the S8 and S10 availability losses
and the S9 architectural gap happened anyway, because they are not
failures of a control — they are properties of the design.

## What changed between runs (model fixes found during verification)

The first harness runs exposed four model bugs, all fixed in the
simulator and harness before the numbers in this pack were produced:

1. **Attack actions consumed ledgers.** The first `attacker_sign_old`
   ran the attacker as the sole issuer over a ledger range, which
   counted the operator's ledgers as missed. Fixed: the attacker now
   signs concurrently with the operator over the same ledgers, so the
   measurement is per-ledger rejection, not downtime.
2. **Flood accounting counted the pre-existing manifest.** The
   untrusted-flood metric subtracted the total cache size instead of
   the flood entries kept, undercounting evictions by one (4 instead
   of 5). Fixed: cache size is recorded before the flood and only
   flood entries are counted.
3. **Unregistered keys short-circuited verification.** Keys created
   for forged, reused, and flood manifests were never registered in
   the verification oracle, so those manifests failed signature
   verification instead of reaching the check under test (a reused
   ephemeral key reported `invalid` instead of `badEphemeralKey`).
   Fixed: every key used in a manifest is registered, so the
   signature verifies and the intended check fires.
4. **Trust used node identity for manifest-mode validators.** The
   first trust check accepted any validation whose node ID was
   listed, regardless of whether the peer had seen the manifest
   binding that key. That mis-models the pinned code, where the UNL
   lists master keys and a signing key counts only through its
   current manifest binding. Fixed: manifest-mode trust goes through
   the current signing-key-to-master binding; only seed-mode
   identities are trusted by node ID. A peer that has not seen the
   current manifest now treats the new key's validations as
   untrusted, which is the property the S10 partition measurement
   rests on.

The numbers in this pack are from the fixed model. The fixes are
recorded here so a reviewer can see what the first run got wrong.
