# Decision memo

## Question

Can postfiatd validator operators rotate signing keys — including
post-quantum signing keys — and recover from suspected compromise
without downtime or double-signing?

## Answer in brief

For classical keys, yes, with two operational conditions. For
post-quantum keys, not yet: the code cannot express one.

## What the evidence shows

**The rotation machinery is sound for classical keys (OBSERVED +
SIMULATED).** The manifest system is a clean indirection: the master
key vouches for an ephemeral signing key at a sequence number, peers
keep the highest valid manifest, and the old key is discarded on
update (`Manifest.h:36-80`; `Manifest.cpp:393-590`). The simulator
exercised every path: scheduled rotation lost 0 ledgers (S1),
emergency rotation after a suspected ephemeral compromise lost 1
ledger and the attacker's 590 subsequent validations counted 0 (S2),
master-key revocation removed the validator entirely and no later
manifest for that master was accepted (S3), and a failed rotation
rolled back through a newer manifest naming the old key (S5). Replay
and forgery were rejected on every peer in every shape tried (S6, S7).
All 18 inventoried controls stopped 100% of the attempts made against
them in these scenarios.

**Two conditions (SIMULATED).** First, the validator must already run
on a token/manifest setup: a seed-mode validator has no rotation
mechanism, and rotating is an identity change that costs every ledger
until the UNL is updated on every peer (S8: 30/120 ledgers untrusted).
Second, rotation must happen on a whole network: rotating inside a
partition leaves half the network unable to trust the new key, so the
validator contributes nothing toward the 80% quorum for the duration
(S10: 10 ledgers at 5/10 acceptance).

**Double-signing is detected, not prevented (OBSERVED + SIMULATED).**
A duplicated token was flagged conflicting 100/100 times and never
double-counted (S4), but the code does not exclude the validator or
stop the signing. The control is a detector with an operator runbook
attached, not a prevention mechanism.

**Post-quantum rotation is not currently expressible (OBSERVED).**
The pinned tree has no post-quantum cryptography; the key-type enum
has two members; the public-key buffer is 33 bytes; the operator RPC
hardcodes secp256k1. Modelled with ML-DSA-65, a manifest would carry
54.2x the ed25519 key material (10,522 vs 194 bytes) and a validation
54.2x (5,261 vs 97 bytes) — large but not disqualifying. The blocker
is the plumbing, not the size.

## Recommendation

1. **Adopt the token/manifest setup for every validator now** (P0 in
   `docs/remediation-report.md`). It is the precondition for every
   rotation and recovery path in this pack, and converting later costs
   the same identity change as rotating does.
2. **Codify rotation as a checklist** — whole-network check, pre-staged
   key and manifest, propagation verified on a quorum before retiring
   the old key, rollback manifest prepared, conflicting-verdict
   runbook, pre-signed revocation stored offline. The pack's scenarios
   are the test cases for that checklist.
3. **Do not promise post-quantum rotation** until the key-type
   plumbing exists (third `KeyType` member, variable-length public
   keys, serialization and UNL migration). When it lands, re-run this
   pack against the new code before any production rotation.
4. **Do not over-read the 100% control figures.** Every measured
   control stopped every scripted attempt — but the scenarios are one
   validator against 10 peers, with toy signatures and model
   parameters for gossip, timing, and quorum. The severities (S8 and
   S10 HIGH, S4 and S9 MEDIUM) are where the real exposure sits, and
   none of it is a control failure: it is the design's shape showing
   through the controls.

## Sources

- Pinned postfiatd commit
  `0085a1ff885d6a446369cf73a4430f75af22be55`; full file and line
  citations in `docs/source-inventory.md` (22 files verified
  blob-by-blob).
- Scenario outputs: `outputs/S*.json`, `outputs/matrix.md`,
  `outputs/control-measurements.md`.
- ML-DSA sizes: NIST FIPS 204 Table 2, as repeated in RFC 9964
  Table 1. Ed25519 signature size: RFC 8032 section 5.1.6.
