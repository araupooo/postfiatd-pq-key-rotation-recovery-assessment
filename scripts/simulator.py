#!/usr/bin/env python3
"""simulator.py — protocol-level simulator of postfiatd validator key
management, manifest rotation, and compromise recovery.

Pinned postfiatd commit: 0085a1ff885d6a446369cf73a4430f75af22be55
(2026-10-10, "Merge pull request #50 from postfiatorg/hotfix/upstream-hardening-1.0.9").

What is modelled, and how faithfully
-------------------------------------
* ManifestCache.applyManifest — the disposition state machine is ported
  from src/xrpld/app/misc/detail/Manifest.cpp:393-590, in the same check
  order: stale sequence, signature verification, revocation flag,
  master-as-ephemeral ban, ephemeral-key reuse bans, untrusted-capacity
  bound, then accept / accept-update. Dispositions use the exact names
  from src/xrpld/app/misc/Manifest.h:217-236 (accepted, stale,
  badMasterKey, badEphemeralKey, invalid, untrustedCapacity).
* Manifest format — the field set of manifestFormat
  (src/xrpld/app/misc/detail/Manifest.cpp:59-89): master public key,
  master signature, sequence, version (only 0 understood), domain,
  ephemeral signing key, ephemeral signature. Revocation is sequence
  0xFFFFFFFF with no signing key and no ephemeral signature
  (src/xrpld/app/misc/detail/Manifest.cpp:120-131, 226-241).
* Validation acceptance — the per-node checks of
  src/xrpld/consensus/Validations.h: SeqEnforcer monotonic sequence
  (Validations.h:92-135), conflicting-validation detection
  (Validations.h:623-700, ValStatus::conflicting), and the currency
  windows of ValidationParms (Validations.h:46-89:
  validationCURRENT_WALL 300 s, validationCURRENT_LOCAL 180 s,
  validationSET_EXPIRES 600 s, validationFRESHNESS 20 s).
* Key sizes — secp256k1 / ed25519 public keys are 33 bytes
  (include/xrpl/protocol/PublicKey.h:47-58, 65); the key-type allowlist
  admits exactly two types (include/xrpl/protocol/KeyType.h:28-31) and
  publicKeyType returns nullopt for anything else
  (src/libxrpl/protocol/PublicKey.cpp:223-236). ML-DSA sizes are the
  FIPS 204 Table 2 values (ML-DSA-65: public key 1952, private key 4032,
  signature 3309 bytes), as repeated in RFC 9964 Table 1.
* No expiry, no automatic rotation — manifests carry no expiry field and
  no code path schedules a rotation (verified by inspection of the
  pinned tree); rotation is a manual operator action.

What is NOT modelled (stand-ins, stated honestly)
-------------------------------------------------
* Signatures are toy HMAC-SHA256 message-authentication codes, not
  secp256k1 / ed25519 / ML-DSA signatures. They model the binding
  property the code relies on — only the holder of a key's secret can
  produce a signature that verifies under that key, and any tampering
  breaks verification — but they are not the real algorithms, and no
  timing or size claim about real signatures is derived from them.
  Real signature sizes come from the cited sources above, never from
  the toy MAC (which is always 32 bytes).
* Verification is performed through a registry oracle: the simulator
  keeps the (public identity -> secret) mapping that stands in for a
  public-key verification algorithm. Actors can only sign with keys in
  their own store; the oracle never lets an actor sign with a key it
  does not own. Forgery attempts therefore fail exactly as they would
  against the real verifyDigest path.
* Network propagation is a deterministic round model (500 ms per gossip
  round, one new peer informed per informed peer per round), not a
  measured overlay. Ledger close is a fixed 4000 ms virtual tick.
  Quorum is a model parameter (80% of peers), not a measured value.

Determinism: fixed seeds, a virtual clock, no wall clock, no network,
no randomness outside the seeded generator. Re-running the harness
produces byte-identical outputs.
"""

import hashlib
import hmac
import json

PINNED_COMMIT = "0085a1ff885d6a446369cf73a4430f75af22be55"

# --- Observed protocol constants (pinned code) -------------------------
LEDGER_MS = 4000            # model parameter: virtual ms per ledger close
GOSSIP_ROUND_MS = 500       # model parameter: virtual ms per gossip round
REVOKED_SEQ = 0xFFFFFFFF    # Manifest.cpp:236-241
MAX_UNTRUSTED = 1000        # Manifest.h:283 defaultMaxUntrustedManifests
CURRENT_WALL_S = 300        # Validations.h: ValidationParms
CURRENT_LOCAL_S = 180       # Validations.h: ValidationParms
CURRENT_EARLY_S = 180       # Validations.h: ValidationParms
SET_EXPIRES_S = 600         # Validations.h: ValidationParms
FRESHNESS_S = 20            # Validations.h: ValidationParms
QUORUM_FRACTION = 0.80      # model parameter: 8 of 10 peers

# --- Key / signature sizes (bytes) ------------------------------------
# Classical sizes: public keys OBSERVED (PublicKey.h:47-58, 65);
# ed25519 signature 64 bytes is the fixed size of RFC 8032 section 5.1.6;
# secp256k1 signature 72 bytes is the modelled DER maximum (70-72 bytes).
# ML-DSA-65 sizes: FIPS 204 Table 2, repeated in RFC 9964 Table 1.
KEY_SIZES = {
    "secp256k1": {"pubkey": 33, "signature": 72},
    "ed25519": {"pubkey": 33, "signature": 64},
    "mldsa65": {"pubkey": 1952, "signature": 3309},
}
# The pinned KeyType enum admits exactly two types (KeyType.h:28-31).
PINNED_KEY_TYPES = ("secp256k1", "ed25519")


def _secret(seed, key_id):
    return hashlib.sha256(("%s:%s" % (seed, key_id)).encode()).digest()


def _mac(secret, payload):
    return hmac.new(secret, payload, hashlib.sha256).digest()


class Key:
    """A key identity. `secret` is held only by its owner; the registry
    oracle stands in for public-key verification."""

    def __init__(self, key_id, algorithm, seed):
        self.key_id = key_id
        self.algorithm = algorithm
        self.secret = _secret(seed, key_id)

    @property
    def pubkey_bytes(self):
        return KEY_SIZES[self.algorithm]["pubkey"]

    @property
    def sig_bytes(self):
        return KEY_SIZES[self.algorithm]["signature"]

    def sign(self, payload):
        return _mac(self.secret, payload)

    def __repr__(self):
        return "Key(%s:%s)" % (self.key_id, self.algorithm)


# Registry oracle: public identity -> secret, standing in for the
# public-key verification algorithm. Actors sign only with keys in
# their own store; the oracle is consulted only to verify.
REGISTRY = {}


def register_key(key):
    REGISTRY[key.key_id] = key


def verify_with(key_id, payload, sig):
    key = REGISTRY.get(key_id)
    if key is None:
        return False
    return hmac.compare_digest(_mac(key.secret, payload), sig)


# ----------------------------------------------------------------------
# Manifest (port of src/xrpld/app/misc/detail/Manifest.cpp)
# ----------------------------------------------------------------------

class Manifest:
    def __init__(self, master, signing, sequence, domain="",
                 version=0, master_sig=None, ephemeral_sig=None):
        self.master = master            # Key (public identity)
        self.signing = signing          # Key or None (revocation)
        self.sequence = sequence        # uint32
        self.domain = domain
        self.version = version
        self.master_sig = master_sig
        self.ephemeral_sig = ephemeral_sig

    @property
    def revoked(self):
        return self.sequence == REVOKED_SEQ

    def unsigned_payload(self):
        signing_id = self.signing.key_id if self.signing else ""
        return json.dumps([
            self.master.key_id, signing_id, self.sequence,
            self.domain, self.version,
        ], sort_keys=True).encode()

    def sign_all(self):
        payload = self.unsigned_payload()
        self.master_sig = self.master.sign(payload)
        if self.signing is not None:
            self.ephemeral_sig = self.signing.sign(payload)

    def deserialize_ok(self):
        """Mirror of deserializeManifest (Manifest.cpp:59-160) structural
        checks that do not need the signature: version, key types,
        domain form, revocation shape, signing != master."""
        if self.version != 0:
            return False
        if self.master.algorithm not in PINNED_KEY_TYPES:
            return False
        if self.signing is not None and \
                self.signing.algorithm not in PINNED_KEY_TYPES:
            return False
        if self.domain and not _proper_domain(self.domain):
            return False
        if self.revoked:
            if self.signing is not None or self.ephemeral_sig is not None:
                return False
        else:
            if self.signing is None or self.ephemeral_sig is None:
                return False
            if self.signing.key_id == self.master.key_id:
                return False
        return True

    def verify(self):
        """Mirror of Manifest::verify (Manifest.cpp:198-214)."""
        if not self.revoked and self.signing is None:
            return False
        payload = self.unsigned_payload()
        if not self.revoked:
            if not verify_with(self.signing.key_id, payload,
                               self.ephemeral_sig):
                return False
        return verify_with(self.master.key_id, payload, self.master_sig)


def _proper_domain(domain):
    # Mirror of isProperlyFormedTomlDomain as used by deserializeManifest:
    # a dotted hostname of labels with alphanumerics and hyphens.
    if not domain or len(domain) > 253 or domain.startswith(".") or \
            domain.endswith(".") or ".." in domain:
        return False
    for label in domain.split("."):
        if not label or len(label) > 63:
            return False
        if not all(c.isalnum() or c == "-" for c in label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


class ManifestCache:
    """Port of ManifestCache::applyManifest (Manifest.cpp:393-590)."""

    def __init__(self, max_untrusted=MAX_UNTRUSTED):
        self.map_ = {}               # master key_id -> Manifest
        self.signing_to_master = {}  # signing key_id -> master key_id
        self.ever_signing = {}       # signing key_id -> master key_id,
        # ever bound (current or superseded); used to tell a
        # superseded key from an unknown one.
        self.untrusted = set()
        self.untrusted_order = []
        self.max_untrusted = max_untrusted

    def get_master_for_signing(self, signing_id):
        return self.ever_signing.get(signing_id)

    def get_signing_key(self, master_id):
        m = self.map_.get(master_id)
        if m is None or m.revoked:
            return None
        return m.signing.key_id if m.signing else None

    def get_master_key(self, signing_id):
        return self.signing_to_master.get(signing_id, signing_id)

    def get_sequence(self, master_id):
        m = self.map_.get(master_id)
        if m is None or m.revoked:
            return None
        return m.sequence

    def revoked(self, master_id):
        m = self.map_.get(master_id)
        return m is not None and m.revoked

    def apply_manifest(self, m, policy="uncapped"):
        # policy: "capped" (peer gossip for unlisted keys) or "uncapped"
        # (listed, configured, database-loaded). Mirror of the
        # prewriteCheck order in Manifest.cpp:411-497.
        existing = self.map_.get(m.master.key_id)
        if existing is not None and m.sequence <= existing.sequence:
            return "stale"
        if not m.deserialize_ok():
            return "invalid"
        if not m.verify():
            return "invalid"
        if m.master.key_id in self.signing_to_master:
            return "badMasterKey"
        if not m.revoked:
            if m.signing is None:
                return "invalid"
            if m.signing.key_id in self.signing_to_master:
                return "badEphemeralKey"
            if m.signing.key_id in self.map_:
                return "badEphemeralKey"
        if existing is None:
            if policy == "capped" and self.max_untrusted == 0:
                return "untrustedCapacity"
            if not m.revoked:
                self.signing_to_master[m.signing.key_id] = m.master.key_id
                self.ever_signing[m.signing.key_id] = m.master.key_id
            if policy == "capped":
                self.untrusted.add(m.master.key_id)
                self.untrusted_order.append(m.master.key_id)
            self.map_[m.master.key_id] = m
            if policy == "capped":
                self._evict_overflow()
            return "accepted"
        # Accept-update path (Manifest.cpp:567-590).
        if existing.signing is not None:
            self.signing_to_master.pop(existing.signing.key_id, None)
        if not m.revoked:
            self.signing_to_master[m.signing.key_id] = m.master.key_id
            self.ever_signing[m.signing.key_id] = m.master.key_id
        self.map_[m.master.key_id] = m
        return "accepted"

    def _evict_overflow(self):
        while len(self.untrusted) > self.max_untrusted and \
                self.untrusted_order:
            key = self.untrusted_order.pop(0)
            if key not in self.untrusted:
                continue
            self.untrusted.discard(key)
            old = self.map_.pop(key, None)
            if old is not None and not old.revoked and old.signing:
                self.signing_to_master.pop(old.signing.key_id, None)

    def promote_to_trusted(self, master_id):
        self.untrusted.discard(master_id)


# ----------------------------------------------------------------------
# Validations (port of src/xrpld/consensus/Validations.h)
# ----------------------------------------------------------------------

class Validation:
    def __init__(self, node_id, master_id, signing_key_id, ledger_seq,
                 ledger_hash, sign_time_ms, signature, cookie=0):
        self.node_id = node_id
        self.master_id = master_id
        self.signing_key_id = signing_key_id
        self.ledger_seq = ledger_seq
        self.ledger_hash = ledger_hash
        self.sign_time_ms = sign_time_ms
        self.signature = signature
        self.cookie = cookie

    def signing_payload(self):
        return json.dumps([
            self.ledger_seq, self.ledger_hash, self.sign_time_ms,
            self.cookie,
        ], sort_keys=True).encode()


class ValidationStore:
    """Per-peer validation acceptance, mirroring Validations::add
    (Validations.h:623-700) with SeqEnforcer (Validations.h:92-135)
    and ValidationParms currency windows (Validations.h:46-89)."""

    def __init__(self, manifest_cache):
        self.cache = manifest_cache
        self.seq_enforcer = {}   # node_id -> (largest_seq, when_ms)
        self.by_sequence = {}    # (node_id, seq) -> Validation
        self.current = {}        # node_id -> Validation
        self.trusted_nodes = set()    # node_ids listed directly
        # (seed-mode validators: identity is the key itself)
        self.trusted_masters = set()  # master key_ids on the UNL
        # (manifest-mode validators: the UNL lists master keys)
        self.counters = {
            "accepted": 0, "stale": 0, "badSeq": 0,
            "conflicting": 0, "multiple": 0,
            "invalid_sig": 0, "superseded_key": 0, "untrusted": 0,
        }

    def _currency_ok(self, now_ms, val):
        # isCurrent (Validations.h:149-166): signTime must be within
        # CURRENT_EARLY (180 s) in the past and CURRENT_WALL (300 s)
        # in the future; seenTime within CURRENT_LOCAL (180 s). The
        # model delivers within the ledger tick, so seenTime == now
        # and the seenTime clause holds trivially.
        return (val.sign_time_ms > now_ms - CURRENT_EARLY_S * 1000 and
                val.sign_time_ms < now_ms + CURRENT_WALL_S * 1000)

    def add(self, val, now_ms):
        # Order mirrors the pinned pipeline: currency
        # (Validations.h:623-627), signature validity against the
        # claimed signing key (STValidation::isValid,
        # STValidation.cpp:123-150), manifest key-currency (the
        # manifest cache's current signing key for the master), then
        # SeqEnforcer + conflict detection (Validations.h:640-700),
        # then trust (UNL node identity).
        if not self._currency_ok(now_ms, val):
            self.counters["stale"] += 1
            return "stale"
        if not verify_with(val.signing_key_id, val.signing_payload(),
                           val.signature):
            self.counters["invalid_sig"] += 1
            return "invalid_sig"
        # Manifest binding: is the claimed key the CURRENT signing
        # key for its master? A superseded or revoked key still
        # produces a valid signature, but the pinned code attributes
        # it to an identity that is no longer listed, so it never
        # counts toward consensus. The simulator rejects it here as
        # "superseded_key"; the measured quantity — validations from
        # a superseded key never count — is identical either way.
        master = self.cache.get_master_for_signing(val.signing_key_id)
        if master is not None:
            current = self.cache.get_signing_key(master)
            if current != val.signing_key_id:
                self.counters["superseded_key"] += 1
                return "superseded_key"
        # SeqEnforcer: ledger sequence must exceed every unexpired
        # sequence from this node (SET_EXPIRES window).
        largest, when = self.seq_enforcer.get(val.node_id, (0, 0))
        if now_ms > when + SET_EXPIRES_S * 1000:
            largest = 0
        if val.ledger_seq <= largest:
            prior = self.by_sequence.get((val.node_id, val.ledger_seq))
            if prior is not None and prior.ledger_hash != val.ledger_hash:
                self.counters["conflicting"] += 1
                return "conflicting"
            if prior is not None and \
                    prior.sign_time_ms != val.sign_time_ms:
                self.counters["conflicting"] += 1
                return "conflicting"
            if prior is not None and prior.cookie != val.cookie:
                self.counters["multiple"] += 1
                return "multiple"
            self.counters["badSeq"] += 1
            return "badSeq"
        self.seq_enforcer[val.node_id] = (val.ledger_seq, now_ms)
        self.by_sequence[(val.node_id, val.ledger_seq)] = val
        self.current[val.node_id] = val
        # Trust: the UNL lists master keys. A manifest-mode
        # validation counts only when its signing key is currently
        # bound to a listed master (ManifestCache::getMasterKey).
        # A key with no manifest binding (seed mode) counts when its
        # node identity itself is listed.
        current_master = self.cache.signing_to_master.get(
            val.signing_key_id)
        if current_master is not None:
            trusted = current_master in self.trusted_masters
        else:
            trusted = val.node_id in self.trusted_nodes
        if trusted:
            self.counters["accepted"] += 1
            return "accepted"
        self.counters["untrusted"] += 1
        return "untrusted"


# ----------------------------------------------------------------------
# Validator node + peer + network
# ----------------------------------------------------------------------

def node_id_for(master_key):
    # calcNodeID(masterKey) stands in for the real derivation: the
    # node identity is bound to the master key in token mode.
    return "node-" + hashlib.sha256(
        ("node:" + master_key.key_id).encode()).hexdigest()[:12]


class ValidatorNode:
    def __init__(self, name, master, signing, seed, mode="manifest"):
        self.name = name
        self.master = master
        self.signing = signing
        self.sequence = 1 if mode == "manifest" else 0
        self.mode = mode
        self.seed = seed
        self.up = True
        self.domain = ""
        register_key(master)
        register_key(signing)

    @property
    def node_id(self):
        # Token mode: nodeID from the master key. Seed mode: nodeID
        # from the (only) key — a new seed is a new node identity
        # (ValidatorKeys.cpp:77-91 sets nodeID = calcNodeID(pk)).
        key = self.master if self.mode == "manifest" else self.signing
        return node_id_for(key)

    def current_manifest(self):
        m = Manifest(self.master, self.signing, self.sequence,
                     domain=self.domain)
        m.sign_all()
        return m

    def rotate(self, new_signing):
        register_key(new_signing)
        self.signing = new_signing
        self.sequence += 1
        return self.current_manifest()

    def revoke(self):
        self.sequence = REVOKED_SEQ
        m = Manifest(self.master, None, REVOKED_SEQ, domain=self.domain)
        m.sign_all()
        return m


class Peer:
    def __init__(self, peer_id, seed):
        self.peer_id = peer_id
        self.cache = ManifestCache()
        self.validations = ValidationStore(self.cache)
        self.informed_manifests = set()  # (master_id, sequence) seen

    def receive_manifest(self, manifest, policy="uncapped"):
        disp = self.cache.apply_manifest(manifest, policy)
        if disp == "accepted":
            self.informed_manifests.add(
                (manifest.master.key_id, manifest.sequence))
        return disp


class Network:
    def __init__(self, seed, n_peers=10):
        self.seed = seed
        self.peers = [Peer("peer-%02d" % i, seed) for i in range(n_peers)]
        self.validators = []
        self.events = []
        self.time_ms = 0
        self.ledger = 0

    def log(self, ledger, actor, event, detail, outcome):
        self.events.append({
            "time_ms": self.time_ms,
            "ledger": ledger,
            "actor": actor,
            "event": event,
            "detail": detail,
            "outcome": outcome,
        })

    def add_validator(self, validator, trusted=True):
        self.validators.append(validator)
        for peer in self.peers:
            if validator.mode == "manifest":
                # The UNL lists master keys; the manifest binds the
                # ephemeral signing key to its master.
                peer.validations.trusted_masters.add(
                    validator.master.key_id)
                peer.receive_manifest(validator.current_manifest())
            else:
                # Seed mode: no manifest; the node identity itself is
                # what the UNL lists.
                peer.validations.trusted_nodes.add(validator.node_id)
        return validator

    def gossip_manifest(self, manifest, reachable=None, policy="uncapped"):
        """Deterministic round-based gossip. Each round every informed
        peer informs one uninformed peer. Returns (rounds, ms, informed).
        """
        peers = self.peers if reachable is None else reachable
        informed = set()
        # The publisher informs one peer in round 0.
        rounds = 0
        remaining = list(peers)
        first = remaining.pop(0)
        first.receive_manifest(manifest, policy)
        informed.add(first.peer_id)
        while remaining:
            rounds += 1
            self.time_ms += GOSSIP_ROUND_MS
            newly = []
            for peer in list(peers):
                if peer.peer_id in informed and remaining:
                    target = remaining.pop(0)
                    target.receive_manifest(manifest, policy)
                    newly.append(target.peer_id)
            informed.update(newly)
            if not newly:
                break
        return rounds, rounds * GOSSIP_ROUND_MS, len(informed)

    def ledger_hash(self, ledger_seq):
        return hashlib.sha256(
            ("ledger-%d" % ledger_seq).encode()).hexdigest()

    def run_ledgers(self, from_ledger, to_ledger, issuers=None,
                    deliver_to=None):
        """Run ledger closes from_ledger..to_ledger inclusive. Each up
        validator issues one validation per ledger; peers accept or
        reject per ValidationStore rules. One event row is logged per
        validator per ledger with the aggregate peer outcomes.
        Returns {validator_name: {outcome: count}} totals."""
        totals = {}
        for seq in range(from_ledger, to_ledger + 1):
            self.ledger = seq
            self.time_ms = seq * LEDGER_MS
            for v in (issuers if issuers is not None else self.validators):
                if not v.up:
                    self.log(seq, v.name, "validation_skipped",
                             "validator down at ledger %d" % seq,
                             "missed")
                    totals.setdefault(v.name, {}).setdefault(
                        "missed", 0)
                    totals[v.name]["missed"] += 1
                    continue
                val = Validation(
                    node_id=v.node_id, master_id=v.master.key_id,
                    signing_key_id=v.signing.key_id, ledger_seq=seq,
                    ledger_hash=self.ledger_hash(seq),
                    sign_time_ms=self.time_ms, signature=b"")
                val.signature = v.signing.sign(val.signing_payload())
                peers = self.peers if deliver_to is None else deliver_to
                outcomes = {}
                for peer in peers:
                    o = peer.validations.add(val, self.time_ms)
                    outcomes[o] = outcomes.get(o, 0) + 1
                for outcome, count in sorted(outcomes.items()):
                    totals.setdefault(v.name, {}).setdefault(outcome, 0)
                    totals[v.name][outcome] += count
                self.log(
                    seq, v.name, "validation_issued",
                    "ledger %d signed with %s; peer outcomes %s" % (
                        seq, v.signing.key_id,
                        ", ".join("%s=%d" % (k, outcomes[k])
                                  for k in sorted(outcomes))),
                    "accepted=%d/%d" % (
                        outcomes.get("accepted", 0), len(peers)))
        return totals


def issue_validation(network, validator, ledger_seq, cookie=0,
                     ledger_hash=None, sign_time_ms=None, peers=None):
    """Issue one validation from a validator for a ledger and deliver
    it to the given peers (all peers by default). Returns the
    per-outcome peer counts."""
    if ledger_hash is None:
        ledger_hash = network.ledger_hash(ledger_seq)
    if sign_time_ms is None:
        sign_time_ms = ledger_seq * LEDGER_MS
    val = Validation(
        node_id=validator.node_id, master_id=validator.master.key_id,
        signing_key_id=validator.signing.key_id,
        ledger_seq=ledger_seq, ledger_hash=ledger_hash,
        sign_time_ms=sign_time_ms, signature=b"", cookie=cookie)
    val.signature = validator.signing.sign(val.signing_payload())
    outcomes = {}
    for peer in (network.peers if peers is None else peers):
        o = peer.validations.add(val, sign_time_ms)
        outcomes[o] = outcomes.get(o, 0) + 1
    return outcomes


def deliver_validation_to(network, val, peers, now_ms):
    outcomes = {}
    for peer in peers:
        o = peer.validations.add(val, now_ms)
        outcomes[o] = outcomes.get(o, 0) + 1
    return outcomes
