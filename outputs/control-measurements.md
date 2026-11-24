# Control measurements

| Control | Effectiveness | Attempts | Stopped | Status | Scenarios |
|---|---|---|---|---|---|
| C00 Manifest sequence monotonicity (stale rejection) | 100.00% | 10 | 10 | MEASURED | S6 |
| C01 Master-signature verification on manifests | 100.00% | 10 | 10 | MEASURED | S6 |
| C02 Ephemeral-signature verification on manifests | 100.00% | 10 | 10 | MEASURED | S6 |
| C03 Revocation is terminal (sequence 0xFFFFFFFF) | 100.00% | 10 | 10 | MEASURED | S3 |
| C04 Key-reuse bans (master/ephemeral cross-use) | 100.00% | 30 | 30 | MEASURED | S7 |
| C05 Validator token / seed config rules | 100.00% | 3 | 3 | MEASURED | S7 |
| C06 Untrusted manifest cache bound (1000 entries) | 100.00% | 1005 | 1005 | MEASURED | S7 |
| C07 SeqEnforcer: monotonic validation sequence per node | 100.00% | 100 | 100 | MEASURED | S4 |
| C08 Conflicting-validation detection (double-sign) | 100.00% | 100 | 100 | MEASURED | S4 |
| C09 Validation currency windows | 100.00% | 10 | 10 | MEASURED | S6 |
| C10 UNL trust gating (node identity must be listed) | 100.00% | 300 | 300 | MEASURED | S8 |
| C11 Fixed 33-byte public-key buffer | 100.00% | 10 | 10 | MEASURED | S9 |
| C12 Key-type allowlist (secp256k1, ed25519 only) | 100.00% | 10 | 10 | MEASURED | S9 |
| C13 Manifest version gate (only version 0) | 100.00% | 10 | 10 | MEASURED | S7 |
| C14 Manifest domain format check | 100.00% | 10 | 10 | MEASURED | S7 |
| C15 Validation signature verification (STValidation) | 100.00% | 10 | 10 | MEASURED | S6 |
| C16 Manifest key-currency (superseded key never counts) | 100.00% | 1240 | 1240 | MEASURED | S1, S2, S3 |
| C17 Seed mode has no rotation mechanism (negative control) | 100.00% | 300 | 300 | MEASURED | S8 |

## C00 Manifest sequence monotonicity (stale rejection)

Citation: `src/xrpld/app/misc/detail/Manifest.cpp:411-425` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- superseded manifest replay rejected stale

## C01 Master-signature verification on manifests

Citation: `src/xrpld/app/misc/detail/Manifest.cpp:198-214` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- forged master signature rejected

## C02 Ephemeral-signature verification on manifests

Citation: `src/xrpld/app/misc/detail/Manifest.cpp:198-214` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- forged ephemeral signature rejected

## C03 Revocation is terminal (sequence 0xFFFFFFFF)

Citation: `src/xrpld/app/misc/detail/Manifest.cpp:226-241,438-444` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- no manifest accepted after revocation; revocation is terminal

## C04 Key-reuse bans (master/ephemeral cross-use)

Citation: `src/xrpld/app/misc/detail/Manifest.cpp:447-497` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- key-reuse manifest rejected (ephemeral_reuse)
- key-reuse manifest rejected (master_is_ephemeral)
- key-reuse manifest rejected (signing_is_master)

## C05 Validator token / seed config rules

Citation: `src/xrpld/app/misc/detail/ValidatorKeys.cpp:35-75` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- config rules enforced as coded

## C06 Untrusted manifest cache bound (1000 entries)

Citation: `src/xrpld/app/misc/Manifest.h:283` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- cache held at the 1000-entry bound; oldest evicted

## C07 SeqEnforcer: monotonic validation sequence per node

Citation: `src/xrpld/consensus/Validations.h:92-135` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- second validation for a sequence never counted

## C08 Conflicting-validation detection (double-sign)

Citation: `src/xrpld/consensus/Validations.h:623-700` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- same-sequence divergent-ledger validations flagged

## C09 Validation currency windows

Citation: `src/xrpld/consensus/Validations.h:46-89,149-166` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- 360 s old validation outside the currency window

## C10 UNL trust gating (node identity must be listed)

Citation: `src/xrpld/app/misc/detail/ValidatorList.cpp:220-231` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- validations from an unlisted identity never counted toward consensus

## C11 Fixed 33-byte public-key buffer

Citation: `include/xrpl/protocol/PublicKey.h:65` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- 1952-byte ML-DSA-65 key fails the 33-byte publicKeyType check

## C12 Key-type allowlist (secp256k1, ed25519 only)

Citation: `include/xrpl/protocol/KeyType.h:28-31; src/libxrpl/protocol/PublicKey.cpp:223-236` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- mldsa65 is not a member of the pinned KeyType enum

## C13 Manifest version gate (only version 0)

Citation: `src/xrpld/app/misc/detail/Manifest.cpp:91-93` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- version 1 manifest rejected at deserialize

## C14 Manifest domain format check

Citation: `src/xrpld/app/misc/detail/Manifest.cpp:103-111` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- malformed-domain manifest rejected at deserialize

## C15 Validation signature verification (STValidation)

Citation: `src/libxrpl/protocol/STValidation.cpp:123-150` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- tampered validation signature rejected

## C16 Manifest key-currency (superseded key never counts)

Citation: `src/xrpld/app/misc/Manifest.h:357; src/xrpld/app/misc/detail/Manifest.cpp:567-590` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- superseded-key validations never counted

## C17 Seed mode has no rotation mechanism (negative control)

Citation: `src/xrpld/app/misc/detail/ValidatorKeys.cpp:77-91` at pinned commit 0085a1ff885d6a446369cf73a4430f75af22be55.

- seed-mode rotation produced a new unlisted identity; every validation until the UNL update was untrusted

