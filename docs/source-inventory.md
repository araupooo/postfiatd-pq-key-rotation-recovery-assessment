# Source inventory

Pinned postfiatd commit: `0085a1ff885d6a446369cf73a4430f75af22be55`
(2026-10-10, "Merge pull request #50 from postfiatorg/hotfix/upstream-hardening-1.0.9").

Every file below was verified blob-by-blob: the local checkout's
`git hash-object` output and byte size agree with the GitHub API tree
for the pinned commit (22 of 22 files). Line numbers were read with
`grep -n` on the local checkout of the pinned commit, never from a
fetched raw-file view.

## Key types and key sizes

| File | Lines | What was taken from it |
|---|---|---|
| `include/xrpl/protocol/KeyType.h` | 28-31 | `KeyType` admits exactly two values: `secp256k1 = 0`, `ed25519 = 1`. No post-quantum member exists. |
| `include/xrpl/protocol/KeyType.h` | 33-42 | `keyTypeFromString` accepts only `"secp256k1"` and `"ed25519"`. |
| `include/xrpl/protocol/PublicKey.h` | 47-58 | "As of this writing two systems are supported: secp256k1, ed25519." secp256k1 public keys are 33-byte compressed keys (lead byte 0x02/0x03); ed25519 keys are a 1-byte 0xED prefix plus 32 bytes. |
| `include/xrpl/protocol/PublicKey.h` | 65 | `static constexpr std::size_t size_ = 33;` — the public-key buffer is fixed at 33 bytes. |
| `src/libxrpl/protocol/PublicKey.cpp` | 223-236 | `publicKeyType`: a 33-byte slice starting 0xED is ed25519, starting 0x02/0x03 is secp256k1, anything else returns `std::nullopt`. |
| `include/xrpl/protocol/SecretKey.h` | 160-165 | `signDigest` declarations. |
| `src/libxrpl/protocol/SecretKey.cpp` | 230 | `signDigest` implementation. |
| `include/xrpl/protocol/STValidation.h` | 260 | Validation signing: `setFieldVL(sfSignature, signDigest(pk, sk, getSigningHash()))`. |

## Manifests: rotation and revocation

| File | Lines | What was taken from it |
|---|---|---|
| `src/xrpld/app/misc/Manifest.h` | 36-80 | Design comment: the master key signs a manifest naming an ephemeral signing key and a sequence; on compromise, a new manifest with a higher sequence replaces the key; if the master key is compromised, sequence `0xFFFFFFFF` supersedes everything and discards the key with no replacement, and no further manifests are accepted. |
| `src/xrpld/app/misc/Manifest.h` | 82-151 | `Manifest` struct: serialized form, master key, optional signing key ("A revoked manifest does not have a signingKey"), sequence, domain; `revoked()`; `verify()`; `hash()`; `getSignature()`; `getMasterSignature()`. |
| `src/xrpld/app/misc/Manifest.h` | 217-236 | `ManifestDisposition`: accepted, stale, badMasterKey, badEphemeralKey, invalid, untrustedCapacity. |
| `src/xrpld/app/misc/Manifest.h` | 265-290 | `ManifestRateLimitCapPolicy` (capped / uncapped) and `defaultMaxUntrustedManifests = 1000`. |
| `src/xrpld/app/misc/Manifest.h` | 295-430 | `ManifestCache`: `getSigningKey`, `getMasterKey`, `getSequence`, `getDomain`, `getManifest`, `getManifestIncludingRevoked`, `revoked`, `applyManifest`, `promoteToTrusted`, `untrustedCount`, `load`, `save`. |
| `src/xrpld/app/misc/detail/Manifest.cpp` | 59-89 | `manifestFormat`: required master public key, master signature, sequence; optional version (default 0), domain, ephemeral signing key, ephemeral signature. No expiry field exists anywhere in the format. |
| `src/xrpld/app/misc/detail/Manifest.cpp` | 91-160 | `deserializeManifest`: only version 0 is understood (91-93); master key must have a known type (95-99); domain must be properly formed (103-111); revocation manifests must carry no signing key and no ephemeral signature (120-131); regular manifests must carry both (132-145); signing key must differ from the master key (143-145). |
| `src/xrpld/app/misc/detail/Manifest.cpp` | 198-214 | `Manifest::verify`: the ephemeral signature is verified against the signing key, then the master signature against the master key; revocations skip the ephemeral check. |
| `src/xrpld/app/misc/detail/Manifest.cpp` | 226-241 | `Manifest::revoked`: sequence equals `std::numeric_limits<std::uint32_t>::max()`. |
| `src/xrpld/app/misc/detail/Manifest.cpp` | 311-319 | `getSigningKey`: returns the stored signing key, or the master key itself when no manifest is known (the seed-mode fallback). |
| `src/xrpld/app/misc/detail/Manifest.cpp` | 393-590 | `applyManifest`, in check order: stale sequence (411-425), signature verification (427-435), revocation logging (438-444), master-key-as-ephemeral ban (447-457), missing-signing-key and ephemeral-reuse bans (458-497), untrusted-capacity bound (535-548), accept-new (549-561), accept-update (567-590, old signing key unseated from the reverse map). |
| `src/xrpld/app/misc/detail/Manifest.cpp` | 640-700 | `load`: the configured `[validator_token]` manifest and `[validator_key_revocation]` entries are applied uncapped; a revocation entry must deserialize and be revoked or loading fails. |

## Validator configuration

| File | Lines | What was taken from it |
|---|---|---|
| `src/xrpld/app/misc/ValidatorKeys.h` | 37-62 | `ValidatorKeys::Keys`: master public key, public (signing) key, secret key; `manifest` string and `sequence` fields. |
| `src/xrpld/app/misc/detail/ValidatorKeys.cpp` | 35-42 | `[validator_token]` and `[validation_seed]` are mutually exclusive; specifying both is a fatal configuration error. |
| `src/xrpld/app/misc/detail/ValidatorKeys.cpp` | 46-75 | Token path: the token is loaded, the public key is derived with `KeyType::secp256k1`, the manifest is deserialized, and the configuration is invalid unless the derived key equals the manifest's signing key. |
| `src/xrpld/app/misc/detail/ValidatorKeys.cpp` | 77-91 | Seed path: the seed is parsed and the key is generated with `KeyType::secp256k1`; master, public and secret are the same key; node ID is derived from that key; sequence is 0; no manifest exists. |
| `src/xrpld/core/ConfigSections.h` | 89-96 | Section names: `[validation_seed]`, `[validator_key_revocation]`, `[validator_token]`. |

## Validation signing and acceptance

| File | Lines | What was taken from it |
|---|---|---|
| `src/xrpld/app/consensus/RCLConsensus.cpp` | 228-245 | Proposal signing: without validator keys nothing is proposed; otherwise `signDigest(keys.publicKey, keys.secretKey, proposal.signingHash())`. |
| `src/xrpld/app/consensus/RCLConsensus.cpp` | 826-860 | Validation signing: without validator keys nothing is validated (warning only); otherwise an `STValidation` is built with the validator's public key, secret key, and node ID. |
| `src/libxrpl/protocol/STValidation.cpp` | 56-73 | Validation format: `sfSigningPubKey` and `sfSignature` are required fields. |
| `src/libxrpl/protocol/STValidation.cpp` | 123-150 | `STValidation::isValid`: the signature is checked with `verifyDigest` against the validation's own signing key; a bad key type fails. |
| `src/xrpld/consensus/Validations.h` | 46-89 | `ValidationParms`: `validationCURRENT_WALL` 5 min, `validationCURRENT_LOCAL` 3 min, `validationCURRENT_EARLY` 3 min, `validationSET_EXPIRES` 10 min, `validationFRESHNESS` 20 s. |
| `src/xrpld/consensus/Validations.h` | 92-135 | `SeqEnforcer`: a validation's ledger sequence must exceed every unexpired sequence previously seen from that node; the window resets after `validationSET_EXPIRES`. |
| `src/xrpld/consensus/Validations.h` | 149-166 | `isCurrent`: a validation is current when its signing time is within `CURRENT_EARLY` in the past and `CURRENT_WALL` in the future, and its seen time is within `CURRENT_LOCAL`. |
| `src/xrpld/consensus/Validations.h` | 169-196 | `ValStatus`: current, stale, badSeq, multiple, conflicting. |
| `src/xrpld/consensus/Validations.h` | 623-700 | `Validations::add`: currency check first, then the sequence enforcer; two validations for the same sequence from one node with different ledger hashes return `conflicting`; same ledger with different signing times also `conflicting`; same ledger with different cookies `multiple`; otherwise `badSeq`. |

## Validator lists, sites, gossip, RPC

| File | Lines | What was taken from it |
|---|---|---|
| `src/xrpld/app/misc/detail/ValidatorList.cpp` | 178-183 | A validator-list publisher whose key is revoked gets `PublisherStatus::revoked`. |
| `src/xrpld/app/misc/detail/ValidatorList.cpp` | 220-231 | The local validator's master key is resolved from its signing key via the manifest cache, and the key is promoted to trusted. |
| `src/xrpld/app/misc/detail/ValidatorList.cpp` | 267 | Listed validator keys are promoted to trusted (freed from the untrusted bound). |
| `src/xrpld/app/misc/detail/ValidatorSite.cpp` | 391-420 | Validator-site blobs carry a manifest; the manifest is hashed with the blob set and version. |
| `src/xrpld/overlay/detail/OverlayImpl.cpp` | 713 | Manifests received from peers are added to the database (`addValidatorManifest`). |
| `src/xrpld/app/misc/NetworkOPs.cpp` | 2438 | The validation JSON resolves the signing key to its master key via the manifest cache for display. |
| `src/xrpld/rpc/handlers/ValidationCreate.cpp` | 45-62 | `validation_create` generates the key with `KeyType::secp256k1` hardcoded; no other key type can be produced by the operator RPC. |
| `src/xrpld/rpc/handlers/ValidatorInfo.cpp` | 31-62 | `validator_info` reports master key, ephemeral key, manifest, sequence, and domain from the manifest cache; a key with no manifest reports only the master key. |
| `src/xrpld/rpc/detail/Handler.cpp` | 184-193 | `validation_create` and `validator_info` are registered RPC handlers; `validator_info` requires the ADMIN role. |

## Negative findings (verified by search of the pinned tree)

- No file in `src/`, `include/`, or `docs/` at the pinned commit
  mentions post-quantum cryptography: case-insensitive searches for
  `quantum`, `post-quantum`, `ML-DSA`, `ML-KEM`, `Dilithium`, `Kyber`,
  `SPHINCS`, `Falcon`, `liboqs`, and `pqcrypto` return no hits.
- No code path schedules or automates a key rotation: the only
  matches for `rotat` in the validator/consensus code are database
  rotation (`SHAMapStore`, `DatabaseRotating`), unrelated to keys.
- No manifest expiry exists: the manifest format has no expiry or
  not-after field, so a manifest stays valid until a higher-sequence
  manifest supersedes it or a revocation terminates it.

## External primary sources (post-quantum sizes)

- NIST FIPS 204, Table 2 (August 2024), as repeated in RFC 9964
  (May 2026), Table 1: ML-DSA-44 public key 1312 / private key 2560 /
  signature 2420 bytes; ML-DSA-65 public key 1952 / private key 4032 /
  signature 3309 bytes; ML-DSA-87 public key 2592 / private key 4896 /
  signature 4627 bytes. This pack models ML-DSA-65 (security
  category 3).
- RFC 8032, section 5.1.6: an Ed25519 signature is 64 octets (used
  only for the classical baseline size in the S9 model).
