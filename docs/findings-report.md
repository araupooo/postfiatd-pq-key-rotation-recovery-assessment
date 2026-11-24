# Findings report

Pinned commit `0085a1ff885d6a446369cf73a4430f75af22be55`. Labels:
**OBSERVED** (pinned source), **SIMULATED** (harness output),
**UNMEASURED** (code-verified, no number). Every number below is read
from the committed per-scenario outputs.

## The rotation machinery works — for classical keys

**OBSERVED.** A validator's identity is its master key. The master key
signs a manifest naming an ephemeral signing key and a sequence number
(`src/xrpld/app/misc/Manifest.h:36-80`). Peers keep the highest-sequence
valid manifest, verify both signatures, and discard the old key
(`src/xrpld/app/misc/detail/Manifest.cpp:393-590`). Rotation is a new
manifest with a higher sequence; revocation is sequence `0xFFFFFFFF`
with no signing key, terminal by construction because no higher
sequence exists (`Manifest.cpp:226-241`).

**SIMULATED.** S1 (scheduled rotation): 0 missed ledgers across 120,
rotation propagated to 10/10 peers in 2000 ms (4 gossip rounds, inside
one 4000 ms ledger close), and 50 old-key validations attempted after
the rotation counted 0. S2 (emergency rotation after suspected
ephemeral compromise): the attacker kept signing with the compromised
key for 59 ledgers — 590 peer events, 0 accepted — and the operator
lost exactly 1 ledger to the emergency handover (uptime 99.17%). S3
(master-key compromise): after the revocation, 600 attacker
validations counted 0, and a post-revocation manifest at sequence
`0xFFFFFFFE` — signed with the stolen master secret — was rejected
stale on 10/10 peers. S5 (rollback): a failed rotation cost 10
ledgers, and the rollback — a new manifest at a higher sequence
reinstating the old key — was accepted on 10/10 peers and issuance
resumed. The sequence never goes backwards; rollback works because a
new manifest vouches for the old key, not because the sequence does.

## Double-signing is detected, not prevented

**SIMULATED.** S4 ran a second node with the same token (same master,
same ephemeral key) signing divergent ledgers for the same 10
sequences. Peers flagged the second validation conflicting 100/100
times and counted the duplicate 0 times. **OBSERVED.** That is exactly
what `Validations::add` does (`src/xrpld/consensus/Validations.h:623-700`):
`conflicting` is a verdict, not an exclusion — nothing in that path
removes the validator from the UNL or stops its future validations.
Detection is reliable in the model; prevention depends on the operator
never running two nodes with one token, and on out-of-band response to
a conflicting verdict. A duplicated token is an operator error with a
detector, not a control that stops the error happening.

## Replay and forgery are rejected everywhere

**SIMULATED.** S6: a replayed superseded manifest was stale 10/10; a
manifest with a forged master signature was invalid 10/10; a manifest
with a forged ephemeral signature was invalid 10/10; a validation
replayed 360 s after signing was stale 10/10 (outside the 180 s
`CURRENT_EARLY` window); a validation with one flipped signature byte
was `invalid_sig` 10/10. **OBSERVED.** Each of those rejections traces
to a distinct check in the pinned code (C00, C01, C02, C09, C15 in
`docs/control-inventory.md`). S7 adds the structural rejections: all
three key-reuse shapes rejected 10/10 each, a version-1 manifest
invalid 10/10, a malformed domain invalid 10/10, the three config
shapes 3/3 as coded, and a 1005-manifest untrusted flood held at the
1000-entry bound with the 5 oldest evicted.

## There is no expiry and no automation

**OBSERVED.** The manifest format has no expiry or not-after field
(`Manifest.cpp:59-89`), and no code path schedules a rotation (the
only `rotat` matches in the validator/consensus code are database
rotation). A manifest stays valid until a higher-sequence manifest
supersedes it or a revocation terminates it. Rotation is entirely a
manual operator action: generate a keypair, sign a manifest with the
master key (kept offline, by design), distribute it through
`[validator_token]` and peer gossip. Consequences: a forgotten rotation
never happens on its own, and a compromised key stays valid for as
long as the operator takes to notice and act. The 2000 ms gossip
propagation in the model is fast once the operator acts; the delay
that matters is the human one, which this pack does not measure.

## Seed-mode validators cannot rotate — they reincarnate

**OBSERVED.** A validator configured with `[validation_seed]` has no
manifest: master, public and secret are the same secp256k1 key, the
node ID derives from that key, and the sequence is 0
(`src/xrpld/app/misc/detail/ValidatorKeys.cpp:77-91`). There is no
indirection to rotate through.

**SIMULATED.** S8: after a seed rotation the new key is a new node
identity. Peers have no manifest linking the identities, so the new
identity is unlisted and its validations are untrusted: 0/30 ledgers
trusted before the operator updated the UNL on every peer, 90/120
ledgers trusted overall. The 30-ledger update delay is a scenario
parameter, not a measured network property — the honest statement is
that the cost is exactly the time between the rotation and the UNL
update on every peer, and during that window the validator contributes
nothing. **ANALYSIS.** Seed mode is the easy configuration and the
dangerous one for rotation: it works fine until the day a key must
change, and then it is an identity change with a coordination cost,
not a rotation. Any validator that may ever need to rotate must run
on a token/manifest setup from the start; converting later costs the
same identity change.

## Rotation during a partition loses quorum

**SIMULATED.** S10 split the network 5/5 for 10 ledgers and rotated
inside the partition. The new manifest reached only the reachable
half; the other half kept the old manifest, so the new key's
validations were untrusted there. Validations were accepted by 5/10
peers for 10 ledgers — below the modelled 80% quorum (8 of 10) — so
the validator contributed nothing toward consensus for that window,
even though it was signing correctly. After the heal, the manifest
synced in 2000 ms and acceptance resumed 10/10. **ANALYSIS.** The
failure mode is silent from the operator's side: the rotating node
sees its own validations accepted by the peers it can reach. The
operational rule is to rotate only when the network is whole, and to
verify manifest propagation (sequence visible on a quorum of peers)
before retiring the old key — retiring first, as this scenario does,
is what turns a partial propagation into a quorum loss.

## The post-quantum gap is architectural, not a missing control

**OBSERVED.** The pinned tree contains no post-quantum cryptography
at all: case-insensitive searches for `quantum`, `ML-DSA`, `ML-KEM`,
`Dilithium`, `Kyber`, `SPHINCS`, `Falcon`, `liboqs`, and `pqcrypto`
across `src/`, `include/`, and `docs/` return no hits. The key-type
enum has exactly two members (`include/xrpl/protocol/KeyType.h:28-31`),
the public-key buffer is fixed at 33 bytes
(`include/xrpl/protocol/PublicKey.h:65`), `publicKeyType` returns
nullopt for anything else
(`src/libxrpl/protocol/PublicKey.cpp:223-236`), and the operator key
generation RPC hardcodes secp256k1
(`src/xrpld/rpc/handlers/ValidationCreate.cpp:45-62`). A post-quantum
signing key cannot be expressed in a manifest, a validation, or a
token today.

**SIMULATED.** S9 models ML-DSA-65 (FIPS 204 Table 2, via RFC 9964
Table 1) against the classical baselines, counting key-material plus
signature bytes only (framing excluded and stated):

| Algorithm | Public key | Signature | Manifest key material | Validation key material |
|---|---|---|---|---|
| ed25519 | 33 | 64 | 194 | 97 |
| secp256k1 | 33 | 72 | 210 | 105 |
| ML-DSA-65 | 1952 | 3309 | 10,522 | 5,261 |

ML-DSA-65 is 54.2x the ed25519 key material for both a manifest and a
validation. Per rotation gossiped to 10 peers that is 105,220 bytes
against 1,940; per ledger across 10 validators fanned out to 10 peers
that is 526,100 bytes against 9,700. The pinned code rejects the
1952-byte key on 10/10 peers at deserialization — the gate is absolute,
and it is also the blocker. **ANALYSIS.** The size ratio is large but
not disqualifying on its own: manifests are rare (one per rotation)
and validations are small in absolute terms. The real work is the
key-type plumbing — a third `KeyType` member, a variable-length public
key representation (the 33-byte buffer and every place that assumes
it), manifest and validation serialization that tolerates 1952-byte
keys and 3309-byte signatures, and a migration path for the UNL (which
keys validators by master key). Until that plumbing exists, "rotate
the post-quantum key" is not an operation the code can express, and
any rotation plan that assumes it is planning against a future
codebase.

## What this pack does not establish

- **No live-network measurement.** All numbers are simulator outputs.
  Gossip rounds, ledger timing, and quorum are model parameters.
- **No cryptographic measurement.** Signatures are toy HMACs; no
  claim is made about real signing or verification cost, timing, or
  failure rates. The ML-DSA numbers are standard sizes, not
  measurements.
- **No human-factor measurement.** Detection-to-action delay, UNL
  update delay, and the chance of an operator running two nodes with
  one token are scenario parameters, not observations.
- **No validator-site or RPC measurement.** Those paths are
  code-verified only.
- **No multi-validator interaction.** Every scenario rotates one
  validator against 10 peers. Simultaneous rotations, or a rotation
  during a UNL publisher outage, are not modelled.
