# Control inventory

Pinned commit `0085a1ff885d6a446369cf73a4430f75af22be55`. Effectiveness
is measured from the committed scenario outputs; see
`outputs/control-measurements.json` and `.md` for the numbers. All 18
controls are MEASURED; none is UNMEASURED in this pack.

## C00 — Manifest sequence monotonicity (stale rejection)

- Citation: `src/xrpld/app/misc/detail/Manifest.cpp:411-425`.
- What it does: a manifest whose sequence is not strictly greater than
  the stored one is rejected as `stale`.
- Measured: S6 replayed a superseded manifest (sequence 1 after
  sequence 2 was current) to 10 peers: 10/10 stale. Effectiveness
  100.00% (10 attempts, 10 stopped).

## C01 — Master-signature verification on manifests

- Citation: `src/xrpld/app/misc/detail/Manifest.cpp:198-214`
  (`Manifest::verify`).
- What it does: the master signature must verify against the master
  key, or the manifest is `invalid`.
- Measured: S6 forged a manifest with the master signature made by an
  attacker's key: 10/10 invalid. Effectiveness 100.00%.

## C02 — Ephemeral-signature verification on manifests

- Citation: `src/xrpld/app/misc/detail/Manifest.cpp:198-214`.
- What it does: the ephemeral signature must verify against the
  signing key, or the manifest is `invalid`.
- Measured: S6 forged a manifest with the ephemeral signature made by
  an attacker's key: 10/10 invalid. Effectiveness 100.00%.

## C03 — Revocation is terminal (sequence 0xFFFFFFFF)

- Citation: `src/xrpld/app/misc/detail/Manifest.cpp:226-241` (revoked
  is the maximum uint32), `438-444` (revocation handling).
- What it does: a revocation manifest carries the highest possible
  sequence, so no later manifest for that master can ever be strictly
  greater, and no signing key is stored.
- Measured: S3 published a revocation, then an attacker holding the
  master secret tried sequence `0xFFFFFFFE`: 10/10 stale.
  Effectiveness 100.00%.

## C04 — Key-reuse bans (master/ephemeral cross-use)

- Citation: `src/xrpld/app/misc/detail/Manifest.cpp:447-497`.
- What it does: a master key already used as an ephemeral key is
  `badMasterKey`; an ephemeral key already used as an ephemeral key,
  or used as a master key, is `badEphemeralKey`; a signing key equal
  to the master key fails deserialization.
- Measured: S7 submitted all three shapes to 10 peers each: 10/10
  `badEphemeralKey`, 10/10 `invalid`, 10/10 `badMasterKey`.
  Effectiveness 100.00% (30 attempts, 30 stopped).

## C05 — Validator token / seed config rules

- Citation: `src/xrpld/app/misc/detail/ValidatorKeys.cpp:35-75`.
- What it does: `[validator_token]` and `[validation_seed]` are
  mutually exclusive; a token is valid only when the derived public
  key equals the manifest's signing key.
- Measured: S7 evaluated the three config shapes against the coded
  rules: both present, token with mismatched key, valid token — 3/3
  as coded. Effectiveness 100.00%.

## C06 — Untrusted manifest cache bound (1000 entries)

- Citation: `src/xrpld/app/misc/Manifest.h:283`
  (`defaultMaxUntrustedManifests = 1000`).
- What it does: gossip for unlisted master keys is capped; once the
  bound is reached the oldest unlisted entry is evicted for each new
  one, so a flood churns the set but can never grow the cache.
- Measured: S7 submitted 1005 capped unlisted manifests: the
  untrusted set held at 1000/1000 and the 5 oldest were evicted.
  Effectiveness 100.00% (1005 attempts, bound held for all).

## C07 — SeqEnforcer: monotonic validation sequence per node

- Citation: `src/xrpld/consensus/Validations.h:92-135`.
- What it does: a validation's ledger sequence must exceed every
  unexpired sequence previously seen from that node (window resets
  after `validationSET_EXPIRES`, 10 min).
- Measured: S4's duplicate signed the same 10 sequences a second time:
  100/100 second validations were not counted (they were flagged
  conflicting under C08; the enforcer is what routes them there).
  Effectiveness 100.00% (100 attempts, 100 stopped).

## C08 — Conflicting-validation detection (double-sign)

- Citation: `src/xrpld/consensus/Validations.h:623-700`
  (`ValStatus::conflicting`).
- What it does: two validations for the same sequence from one node
  with different ledger hashes — or the same ledger with different
  signing times — are flagged `conflicting`, not counted twice.
- Measured: S4's duplicate signed divergent ledgers for 10 sequences:
  100/100 flagged conflicting, 0 counted. Effectiveness 100.00%.

## C09 — Validation currency windows

- Citation: `src/xrpld/consensus/Validations.h:46-89` (parameters),
  `149-166` (`isCurrent`).
- What it does: a validation is current only when its signing time is
  within 3 min in the past and 5 min in the future, and its seen time
  within 3 min.
- Measured: S6 replayed a validation signed 360 s ago: 10/10 stale.
  Effectiveness 100.00%.

## C10 — UNL trust gating (node identity must be listed)

- Citation: `src/xrpld/app/misc/detail/ValidatorList.cpp:220-231`.
- What it does: the local validator's master key is resolved from its
  signing key via the manifest cache and promoted to trusted; only
  listed identities count toward consensus.
- Measured: S8's rotated seed-mode identity issued 30 ledgers before
  the UNL update: 300/300 peer events untrusted (never counted).
  Effectiveness 100.00%.

## C11 — Fixed 33-byte public-key buffer

- Citation: `include/xrpl/protocol/PublicKey.h:65`
  (`static constexpr std::size_t size_ = 33;`).
- What it does: every public key the code can hold is 33 bytes. A
  1952-byte ML-DSA-65 public key cannot be stored.
- Measured: S9 submitted a manifest carrying an ML-DSA-65 signing key
  to 10 peers: 10/10 rejected at deserialization. Effectiveness
  100.00% — as a gate it is absolute, and it is also the post-quantum
  blocker (see S9).

## C12 — Key-type allowlist (secp256k1, ed25519 only)

- Citation: `include/xrpl/protocol/KeyType.h:28-31`;
  `src/libxrpl/protocol/PublicKey.cpp:223-236`.
- What it does: the key-type enum has exactly two members, and
  `publicKeyType` returns nullopt for any other key shape.
- Measured: S9, same attempt as C11: 10/10 rejected. Effectiveness
  100.00%.

## C13 — Manifest version gate (only version 0)

- Citation: `src/xrpld/app/misc/detail/Manifest.cpp:91-93`.
- What it does: a manifest carrying a version other than 0 fails
  deserialization.
- Measured: S7 submitted a version-1 manifest to 10 peers: 10/10
  invalid. Effectiveness 100.00%.

## C14 — Manifest domain format check

- Citation: `src/xrpld/app/misc/detail/Manifest.cpp:103-111`.
- What it does: a malformed domain fails deserialization.
- Measured: S7 submitted a manifest with domain `bad..domain` to 10
  peers: 10/10 invalid. Effectiveness 100.00%.

## C15 — Validation signature verification (STValidation)

- Citation: `src/libxrpl/protocol/STValidation.cpp:123-150`
  (`STValidation::isValid`).
- What it does: a validation's signature must verify against its own
  claimed signing key.
- Measured: S6 delivered a validation with one flipped signature byte
  to 10 peers: 10/10 `invalid_sig`. Effectiveness 100.00%.

## C16 — Manifest key-currency (superseded key never counts)

- Citation: `src/xrpld/app/misc/Manifest.h:357`
  (`getSigningKey`); `src/xrpld/app/misc/detail/Manifest.cpp:567-590`
  (accept-update unseats the old signing key).
- What it does: once a manifest is superseded, the old signing key is
  no longer the current key for its master, so validations signed with
  it never count toward consensus.
- Measured: S1 (50), S2 (590), S3 (600) attacker validations with
  superseded keys: 1240/1240 never counted. Effectiveness 100.00%.

## C17 — Seed mode has no rotation mechanism (negative control)

- Citation: `src/xrpld/app/misc/detail/ValidatorKeys.cpp:77-91`.
- What it does: nothing — that is the point. A seed-configured
  validator has no manifest, so rotating its key produces a new node
  identity with no link to the old one. There is no control here to
  stop the failure; the measurement is the cost.
- Measured: S8's rotation cost 30 ledgers of untrusted validations
  (300/300 peer events) before the UNL update. Effectiveness 100.00%
  is reported for consistency (every affected validation was kept out
  of consensus), but the honest reading is the opposite of the other
  controls: the gate held, and the operator still lost 30 ledgers.
  See S8 in `docs/findings-report.md`.
