# Environment

## The system under assessment

postfiatd at pinned commit `0085a1ff885d6a446369cf73a4430f75af22be55`
(2026-10-10). The assessment reads the pinned source only; no live
network was measured, no node was run, and no full build was
attempted (the task-1 build attempt showed the full build is too heavy
for this environment: Conan/grpc from source, killed by a VM restart).

## The simulator

`scripts/simulator.py` is a protocol-level simulator of the validator
key lifecycle: manifest publication and gossip, manifest-cache
admission, validation issuance and acceptance, and the operator actions
(scheduled rotation, emergency rotation, revocation, rollback, seed
rotation, UNL update, partition). `scripts/load_harness.py` drives it
from the declarative scenario files in `scenarios/`.

### What is ported faithfully from the pinned code

- `ManifestCache.applyManifest` — the disposition state machine is
  ported from `src/xrpld/app/misc/detail/Manifest.cpp:393-590`, in the
  same check order: stale sequence, signature verification, revocation
  flag, master-key-as-ephemeral ban, ephemeral-key reuse bans,
  untrusted-capacity bound, then accept / accept-update. Dispositions
  use the exact names from `src/xrpld/app/misc/Manifest.h:217-236`.
- Manifest format — the field set of `manifestFormat`
  (`Manifest.cpp:59-89`): master public key, master signature,
  sequence, version (only 0 understood), domain, ephemeral signing
  key, ephemeral signature. Revocation is sequence `0xFFFFFFFF` with
  no signing key and no ephemeral signature (`Manifest.cpp:120-131`,
  `226-241`).
- Validation acceptance — the per-node checks of
  `src/xrpld/consensus/Validations.h`: `SeqEnforcer` monotonic
  sequence (`Validations.h:92-135`), conflicting-validation detection
  (`Validations.h:623-700`, `ValStatus::conflicting`), and the
  currency windows of `ValidationParms` (`Validations.h:46-89`) with
  the exact `isCurrent` predicate (`Validations.h:149-166`).
- Trust — the UNL lists master keys; a manifest-mode validation
  counts only when its signing key is currently bound to a listed
  master (via the manifest cache's signing-to-master map, mirroring
  `ManifestCache::getMasterKey` and `ValidatorList.cpp:220-231`). A
  key with no manifest binding counts only when its node identity
  itself is listed (the seed-mode path, mirroring
  `ManifestCache::getSigningKey` returning the key itself when no
  manifest is known, `Manifest.cpp:311-319`).
- Key sizes — secp256k1 / ed25519 public keys are 33 bytes
  (`include/xrpl/protocol/PublicKey.h:47-58,65`); the key-type
  allowlist admits exactly two types
  (`include/xrpl/protocol/KeyType.h:28-31`); `publicKeyType` returns
  nullopt for anything else
  (`src/libxrpl/protocol/PublicKey.cpp:223-236`). ML-DSA sizes are
  the FIPS 204 Table 2 values (ML-DSA-65: public key 1952, private key
  4032, signature 3309 bytes), as repeated in RFC 9964 Table 1.
- Constants taken verbatim: revocation sequence `0xFFFFFFFF`;
  untrusted manifest bound 1000 (`Manifest.h:283`); currency windows
  300 / 180 / 180 / 600 / 20 seconds (`Validations.h:46-89`).

### Stand-ins (stated honestly)

- **Signatures are toy HMAC-SHA256 codes, not secp256k1 / ed25519 /
  ML-DSA signatures.** They model the binding property the code
  relies on — only the holder of a key's secret can produce a
  signature that verifies under that key, and any tampering breaks
  verification — but they are not the real algorithms. No timing or
  size claim about real signatures is derived from them. Real
  signature sizes come from the cited sources, never from the toy MAC
  (which is always 32 bytes).
- **Verification runs through a registry oracle**: the simulator keeps
  the public-identity-to-secret mapping that stands in for a
  public-key verification algorithm. Actors can only sign with keys in
  their own store; the oracle never lets an actor sign with a key it
  does not own. A forgery therefore fails exactly as it would against
  the real `verifyDigest` path.
- **Superseded keys.** The pinned code verifies a validation's
  signature against the validation's own claimed key
  (`STValidation::isValid`), so a validation signed with a superseded
  key still has a valid signature — but it is attributed to an
  identity that is no longer listed, so it never counts toward
  consensus. The simulator rejects such validations at the
  manifest-binding step as `superseded_key`. The measured quantity —
  validations from a superseded key never count — is identical either
  way, and the mapping is stated here so a reviewer is not misled.
- **Gossip is a deterministic round model** (500 ms per round, one new
  peer informed per informed peer per round), not a measured overlay.
  A 10-peer network reaches full propagation in 4 rounds (2000 ms).
  Ledger close is a fixed 4000 ms virtual tick. Quorum is a model
  parameter (80% of peers = 8 of 10), not a measured value.
- **The ML-DSA-65 model (S9) is forward-looking.** The pinned code
  has no post-quantum key type, so the S9 manifest is built in a
  hypothetical mode and the pinned-code outcome — deserialize rejects
  the 1952-byte key — is measured alongside the size arithmetic. The
  size totals are key-material plus signature bytes only; framing is
  excluded and the exclusion is stated wherever the totals appear.

### What the simulator does not model

- Real cryptography (see above), CPU cost of signing/verification,
  and wall-clock timing of any kind.
- Overlay internals: peer selection, connection limits, message
  sizes, and the validator-site fetch path are not simulated; the
  validator-site manifest fetch (`ValidatorSite.cpp:391-420`) and
  peer gossip (`OverlayImpl.cpp:713`) are code-verified only.
- The `validation_create` / `validator_info` RPCs are code-verified
  only; no RPC traffic is simulated.
- Amendment voting, UNL publisher fetching, and negative-UNL voting
  are out of scope; the UNL is a fixed set in every scenario except
  S8, where the operator updates it once at a declared ledger.
- Ledger contents: ledgers are opaque hashes; only sequences, signing
  times, and signing keys affect acceptance.

## Determinism

Fixed seed `20261125` for every scenario, a virtual clock, no wall
clock, no network, no randomness outside the seeded generator.
Re-running `bash scripts/run_all.sh` produces byte-identical outputs
except `outputs/run_all.log`, which holds the wall-clock start line
and is excluded from digests. The determinism check in `run_all.sh`
verifies this on every run by diffing a second run in a scratch
directory, including a regenerated reproduction transcript.
