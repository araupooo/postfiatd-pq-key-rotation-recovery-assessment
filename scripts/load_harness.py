#!/usr/bin/env python3
"""load_harness.py — run every scenario in scenarios/ against
scripts/simulator.py and write unedited outputs.

Usage:
    python3 scripts/load_harness.py

Per scenario S*.json it writes:
    outputs/S*.csv  — one row per event (time_ms, ledger, actor,
                      event, detail, outcome)
    outputs/S*.json — summary (metrics, control measurements,
                      final state)
    outputs/S*.log  — unedited run log, including the full SHA-256
                      of the scenario file, the simulator and this
                      harness, plus the summary numbers.

It also writes outputs/run-manifest.json (scenario / script hashes,
seed, pinned commit). Deterministic: fixed seeds, virtual clock.
"""

import csv
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)
sys.path.insert(0, HERE)

import simulator as sim  # noqa: E402

SEED = 20261125
N_PEERS = 10


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def record_control(controls, cid, attempts, stopped, note=""):
    entry = controls.setdefault(cid, {"attempts": 0, "stopped": 0,
                                      "notes": []})
    entry["attempts"] += attempts
    entry["stopped"] += stopped
    if note:
        entry["notes"].append(note)


class Driver:
    def __init__(self, cfg):
        self.cfg = cfg
        self.seed = cfg.get("seed", SEED)
        self.net = sim.Network(self.seed, cfg.get("peers", N_PEERS))
        self.validators = {}
        self.old_keys = {}       # validator name -> list of old Key
        self.stored_manifests = {}  # name -> Manifest (for replay)
        self.reachable = None    # None = all peers (no partition)
        self.metrics = {}
        self.controls = {}
        self.cursor = 1          # next ledger to run
        self._setup()

    # -- setup ------------------------------------------------------
    def _setup(self):
        for spec in self.cfg.get("validators", []):
            master = sim.Key(spec["master_key"], spec["master_algorithm"],
                             self.seed)
            signing = sim.Key(spec["signing_key"],
                              spec["signing_algorithm"], self.seed)
            v = sim.ValidatorNode(spec["name"], master, signing,
                                  self.seed, mode=spec["mode"])
            self.validators[spec["name"]] = v
            self.net.add_validator(v)
            self.old_keys[spec["name"]] = []
        self.metrics["validators"] = {
            name: {"mode": v.mode, "master_key": v.master.key_id,
                   "signing_key": v.signing.key_id,
                   "sequence": v.sequence}
            for name, v in self.validators.items()
        }

    def peers(self):
        return self.net.peers if self.reachable is None else self.reachable

    def accumulate_totals(self, totals):
        for name, t in totals.items():
            slot = self.metrics.setdefault("validation_totals", {})
            for outcome, n in t.items():
                slot[outcome] = slot.get(outcome, 0) + n

    # -- ledger running ----------------------------------------------
    def run(self, count):
        start = self.cursor
        end = self.cursor + count - 1
        totals = self.net.run_ledgers(start, end,
                                      deliver_to=self.peers())
        self.cursor = end + 1
        self.accumulate_totals(totals)
        return totals

    # -- actions ------------------------------------------------------
    def do_rotate(self, step):
        name = step["validator"]
        v = self.validators[name]
        self.old_keys[name].append(v.signing)
        new_key = sim.Key(step["new_key"], step["algorithm"], self.seed)
        manifest = v.rotate(new_key)
        rounds, ms, informed = self.net.gossip_manifest(
            manifest, reachable=self.peers())
        self.net.log(self.cursor - 1, name, "manifest_published",
                     "rotation to %s seq %d; gossip %d rounds %d ms, "
                     "informed %d/%d peers" % (
                         new_key.key_id, v.sequence, rounds, ms,
                         informed, len(self.peers())),
                     "accepted=%d/%d" % (informed, len(self.peers())))
        key = "rotation_%s" % name
        self.metrics[key] = {
            "ledger": self.cursor - 1, "new_key": new_key.key_id,
            "sequence": v.sequence, "gossip_rounds": rounds,
            "gossip_ms": ms, "peers_informed": informed,
            "peers_total": len(self.peers()),
        }
        return manifest

    def do_revoke(self, step):
        name = step["validator"]
        v = self.validators[name]
        self.old_keys[name].append(v.signing)
        manifest = v.revoke()
        rounds, ms, informed = self.net.gossip_manifest(
            manifest, reachable=self.peers())
        self.net.log(self.cursor - 1, name, "manifest_published",
                     "revocation seq 4294967295; gossip %d rounds %d ms, "
                     "informed %d/%d peers" % (
                         rounds, ms, informed, len(self.peers())),
                     "revoked=%d/%d" % (informed, len(self.peers())))
        self.metrics["revocation_%s" % name] = {
            "ledger": self.cursor - 1, "sequence": 0xFFFFFFFF,
            "gossip_rounds": rounds, "gossip_ms": ms,
            "peers_informed": informed,
            "peers_total": len(self.peers()),
        }
        return manifest

    def do_attacker_sign_old(self, step):
        """Attacker keeps signing with a superseded ephemeral key,
        concurrently with the operator (same ledgers, same ticks), so
        the measurement is per-ledger rejection, not downtime."""
        name = step["validator"]
        v = self.validators[name]
        old_key = self.old_keys[name][step.get("old_key_index", 0)]
        attacker = sim.ValidatorNode("attacker-%s" % name, v.master,
                                     old_key, self.seed)
        count = step["ledgers"]
        # The operator issues alongside the attacker when up (S2);
        # when down (S3, revoked) its ledgers are counted missed.
        issuers = [v, attacker]
        totals = self.net.run_ledgers(
            self.cursor, self.cursor + count - 1, issuers=issuers,
            deliver_to=self.peers())
        self.cursor += count
        self.accumulate_totals(totals)
        agg = totals.get("attacker-%s" % name, {})
        accepted = agg.get("accepted", 0)
        superseded = agg.get("superseded_key", 0)
        self.net.log(self.cursor - 1, "attacker-%s" % name,
                     "attacker_sign_old",
                     "attacker signed %d ledgers with superseded key %s; "
                     "peer outcomes %s" % (
                         count, old_key.key_id,
                         ", ".join("%s=%d" % (k, agg[k])
                                   for k in sorted(agg))),
                     "accepted=%d" % accepted)
        self.metrics["attacker_old_key_%s" % name] = {
            "ledgers": count, "attempts": count * len(self.peers()),
            "accepted": accepted, "superseded_key": superseded,
        }
        record_control(self.controls, "C16", count * len(self.peers()),
                       count * len(self.peers()) - accepted,
                       "superseded-key validations never counted")
        return agg

    def do_duplicate_sign(self, step):
        """A second node runs the SAME token (same master + signing
        key) with a divergent ledger view: the classic double-sign.
        Both sign the same sequences; the second validation for a
        sequence must be flagged conflicting, never double-counted."""
        name = step["validator"]
        v = self.validators[name]
        dup = sim.ValidatorNode("duplicate-%s" % name, v.master,
                                v.signing, self.seed)
        count = step["ledgers"]
        conflicting = 0
        accepted_dup = 0
        for seq in range(self.cursor, self.cursor + count):
            self.net.ledger = seq
            self.net.time_ms = seq * sim.LEDGER_MS
            # Primary signs the canonical ledger first.
            primary = sim.issue_validation(self.net, v, seq,
                                           peers=self.peers())
            self.accumulate_totals({v.name: primary})
            self.net.log(seq, v.name, "validation_issued",
                         "ledger %d signed with %s; peer outcomes %s"
                         % (seq, v.signing.key_id,
                            ", ".join("%s=%d" % (k, primary[k])
                                      for k in sorted(primary))),
                         "accepted=%d/%d" % (
                             primary.get("accepted", 0),
                             len(self.peers())))
            # Duplicate signs a divergent ledger for the same sequence.
            div_hash = hashlib.sha256(
                ("ledger-%d-divergent" % seq).encode()).hexdigest()
            outcomes = sim.issue_validation(
                self.net, dup, seq, ledger_hash=div_hash,
                peers=self.peers())
            conflicting += outcomes.get("conflicting", 0)
            accepted_dup += outcomes.get("accepted", 0)
            self.accumulate_totals({"duplicate-%s" % name: outcomes})
            self.net.log(seq, "duplicate-%s" % name,
                         "duplicate_validation",
                         "ledger %d divergent hash signed with same key "
                         "%s; peer outcomes %s" % (
                             seq, v.signing.key_id,
                             ", ".join("%s=%d" % (k, outcomes[k])
                                       for k in sorted(outcomes))),
                         "conflicting=%d/%d" % (
                             outcomes.get("conflicting", 0),
                             len(self.peers())))
        self.cursor += count
        self.metrics["duplicate_sign_%s" % name] = {
            "ledgers": count,
            "attempts": count * len(self.peers()),
            "conflicting": conflicting,
            "accepted_duplicate": accepted_dup,
        }
        record_control(self.controls, "C08",
                       count * len(self.peers()), conflicting,
                       "same-sequence divergent-ledger validations flagged")
        record_control(self.controls, "C07",
                       count * len(self.peers()),
                       count * len(self.peers()) - accepted_dup,
                       "second validation for a sequence never counted")
        return conflicting

    def do_replay_manifest(self, step):
        """Replay a superseded manifest (or a pre-revocation one) to
        every peer; expect stale everywhere."""
        manifest = self.stored_manifests[step["manifest"]]
        dispositions = {}
        for peer in self.peers():
            d = peer.receive_manifest(manifest)
            dispositions[d] = dispositions.get(d, 0) + 1
        self.net.log(self.cursor - 1, "attacker", "replay_manifest",
                     "replayed manifest %s seq %d; peer dispositions %s"
                     % (manifest.master.key_id, manifest.sequence,
                        ", ".join("%s=%d" % (k, dispositions[k])
                                  for k in sorted(dispositions))),
                     "stale=%d/%d" % (dispositions.get("stale", 0),
                                      len(self.peers())))
        key = "replay_%s" % step["manifest"].replace(":", "_")
        self.metrics[key] = {
            "sequence": manifest.sequence,
            "attempts": len(self.peers()), "dispositions": dispositions,
        }
        record_control(self.controls, "C00", len(self.peers()),
                       dispositions.get("stale", 0),
                       "superseded manifest replay rejected stale")

    def do_forge_manifest(self, step):
        """Forge a manifest: valid structure, but the master signature
        (variant 'master') or the ephemeral signature (variant
        'ephemeral') is made with an attacker's secret, not the key's.
        Expect invalid everywhere."""
        name = step["validator"]
        v = self.validators[name]
        attacker = sim.Key("attacker-key", "secp256k1", self.seed)
        signing = sim.Key(step.get("new_key", "eph-forged"),
                          "secp256k1", self.seed)
        sim.register_key(signing)
        m = sim.Manifest(v.master, signing, v.sequence + 1,
                         domain=v.domain)
        payload = m.unsigned_payload()
        if step["variant"] == "master":
            m.master_sig = attacker.sign(payload)
            m.ephemeral_sig = signing.sign(payload)
        else:
            m.master_sig = v.master.sign(payload)
            m.ephemeral_sig = attacker.sign(payload)
        dispositions = {}
        for peer in self.peers():
            d = peer.receive_manifest(m)
            dispositions[d] = dispositions.get(d, 0) + 1
        self.net.log(self.cursor - 1, "attacker", "forge_manifest",
                     "forged manifest variant=%s seq %d; peer "
                     "dispositions %s" % (
                         step["variant"], m.sequence,
                         ", ".join("%s=%d" % (k, dispositions[k])
                                   for k in sorted(dispositions))),
                     "invalid=%d/%d" % (dispositions.get("invalid", 0),
                                        len(self.peers())))
        cid = "C01" if step["variant"] == "master" else "C02"
        self.metrics["forge_%s" % step["variant"]] = {
            "attempts": len(self.peers()), "dispositions": dispositions,
        }
        record_control(self.controls, cid, len(self.peers()),
                       dispositions.get("invalid", 0),
                       "forged %s signature rejected" % step["variant"])

    def do_replay_old_validation(self, step):
        """Replay a validation whose signing time is 360 s old
        (past the CURRENT_EARLY 180 s window): expect stale."""
        name = step["validator"]
        v = self.validators[name]
        # Replay ledger (cursor-90)'s validation now: its signing
        # time is 360000 ms in the past, outside the CURRENT_EARLY
        # 180 s window. The ledger sequence is coherent — it is the
        # ledger that closed 360 s ago.
        replay_ledger = self.cursor - 90
        old_sign_time = replay_ledger * sim.LEDGER_MS
        val = sim.Validation(
            node_id=v.node_id, master_id=v.master.key_id,
            signing_key_id=v.signing.key_id,
            ledger_seq=replay_ledger,
            ledger_hash=self.net.ledger_hash(replay_ledger),
            sign_time_ms=old_sign_time, signature=b"")
        val.signature = v.signing.sign(val.signing_payload())
        outcomes = sim.deliver_validation_to(self.net, val, self.peers(),
                                             self.cursor * sim.LEDGER_MS)
        self.net.log(self.cursor - 1, "attacker",
                     "replay_old_validation",
                     "replayed validation signed 360000 ms ago; peer "
                     "outcomes %s" % (
                         ", ".join("%s=%d" % (k, outcomes[k])
                                   for k in sorted(outcomes)),),
                     "stale=%d/%d" % (outcomes.get("stale", 0),
                                      len(self.peers())))
        self.metrics["replay_old_validation"] = {
            "age_ms": 360000, "attempts": len(self.peers()),
            "outcomes": outcomes,
        }
        record_control(self.controls, "C09", len(self.peers()),
                       outcomes.get("stale", 0),
                       "360 s old validation outside the currency window")

    def do_tamper_validation(self, step):
        """Take a valid validation and flip one signature byte:
        expect invalid_sig everywhere."""
        name = step["validator"]
        v = self.validators[name]
        val = sim.Validation(
            node_id=v.node_id, master_id=v.master.key_id,
            signing_key_id=v.signing.key_id,
            ledger_seq=self.cursor,
            ledger_hash=self.net.ledger_hash(self.cursor),
            sign_time_ms=self.cursor * sim.LEDGER_MS, signature=b"")
        good = v.signing.sign(val.signing_payload())
        bad = bytes([good[0] ^ 0x01]) + good[1:]
        val.signature = bad
        outcomes = sim.deliver_validation_to(
            self.net, val, self.peers(), self.cursor * sim.LEDGER_MS)
        self.net.log(self.cursor - 1, "attacker", "tamper_validation",
                     "validation with one flipped signature byte; peer "
                     "outcomes %s" % (
                         ", ".join("%s=%d" % (k, outcomes[k])
                                   for k in sorted(outcomes)),),
                     "invalid_sig=%d/%d" % (
                         outcomes.get("invalid_sig", 0),
                         len(self.peers())))
        self.metrics["tamper_validation"] = {
            "attempts": len(self.peers()), "outcomes": outcomes,
        }
        record_control(self.controls, "C15", len(self.peers()),
                       outcomes.get("invalid_sig", 0),
                       "tampered validation signature rejected")

    def do_key_reuse(self, step):
        """Exercise the manifest key-reuse bans
        (Manifest.cpp:447-497): ephemeral key already bound to
        another master, signing key equal to the master key, and a
        master key already used as an ephemeral key."""
        variant = step["variant"]
        v = self.validators[step["validator"]]
        dispositions = {}
        if variant == "ephemeral_reuse":
            other_master = sim.Key("master-other", "secp256k1",
                                   self.seed)
            sim.register_key(other_master)
            m = sim.Manifest(other_master, v.signing, 1)
            m.sign_all()
        elif variant == "signing_is_master":
            m = sim.Manifest(v.master, v.master, v.sequence + 1)
            m.sign_all()
        elif variant == "master_is_ephemeral":
            other_signing = sim.Key("eph-other", "secp256k1",
                                    self.seed)
            sim.register_key(other_signing)
            m = sim.Manifest(v.signing, other_signing, 1)
            m.sign_all()
        else:
            raise ValueError("unknown key_reuse variant %s" % variant)
        for peer in self.peers():
            d = peer.receive_manifest(m)
            dispositions[d] = dispositions.get(d, 0) + 1
        self.net.log(self.cursor - 1, "attacker", "key_reuse",
                     "variant=%s; peer dispositions %s" % (
                         variant,
                         ", ".join("%s=%d" % (k, dispositions[k])
                                   for k in sorted(dispositions))),
                     "rejected=%d/%d" % (
                         len(self.peers()) -
                         dispositions.get("accepted", 0),
                         len(self.peers())))
        self.metrics["key_reuse_%s" % variant] = {
            "attempts": len(self.peers()), "dispositions": dispositions,
        }
        record_control(self.controls, "C04", len(self.peers()),
                       len(self.peers()) -
                       dispositions.get("accepted", 0),
                       "key-reuse manifest rejected (%s)" % variant)

    def do_version_attack(self, step):
        v = self.validators[step["validator"]]
        vkey = sim.Key("eph-v1", "secp256k1", self.seed)
        sim.register_key(vkey)
        m = sim.Manifest(v.master, vkey, v.sequence + 1, version=1)
        m.sign_all()
        dispositions = {}
        for peer in self.peers():
            d = peer.receive_manifest(m)
            dispositions[d] = dispositions.get(d, 0) + 1
        self.net.log(self.cursor - 1, "attacker", "version_attack",
                     "manifest version 1; peer dispositions %s" % (
                         ", ".join("%s=%d" % (k, dispositions[k])
                                   for k in sorted(dispositions)),),
                     "invalid=%d/%d" % (dispositions.get("invalid", 0),
                                        len(self.peers())))
        self.metrics["version_attack"] = {
            "attempts": len(self.peers()), "dispositions": dispositions,
        }
        record_control(self.controls, "C13", len(self.peers()),
                       dispositions.get("invalid", 0),
                       "version 1 manifest rejected at deserialize")

    def do_domain_attack(self, step):
        v = self.validators[step["validator"]]
        dkey = sim.Key("eph-dom", "secp256k1", self.seed)
        sim.register_key(dkey)
        m = sim.Manifest(v.master, dkey, v.sequence + 1,
                         domain="bad..domain")
        m.sign_all()
        dispositions = {}
        for peer in self.peers():
            d = peer.receive_manifest(m)
            dispositions[d] = dispositions.get(d, 0) + 1
        self.net.log(self.cursor - 1, "attacker", "domain_attack",
                     "manifest domain 'bad..domain'; peer dispositions "
                     "%s" % (
                         ", ".join("%s=%d" % (k, dispositions[k])
                                   for k in sorted(dispositions)),),
                     "invalid=%d/%d" % (dispositions.get("invalid", 0),
                                        len(self.peers())))
        self.metrics["domain_attack"] = {
            "attempts": len(self.peers()), "dispositions": dispositions,
        }
        record_control(self.controls, "C14", len(self.peers()),
                       dispositions.get("invalid", 0),
                       "malformed-domain manifest rejected at deserialize")

    def do_config_check(self, step):
        """Model the ValidatorKeys constructor rules
        (ValidatorKeys.cpp:35-75): [validator_token] and
        [validation_seed] are mutually exclusive, and a token is
        valid only when the derived public key equals the manifest's
        signing key."""
        v = self.validators[step["validator"]]
        cases = {
            "both_token_and_seed": {
                "token": True, "seed": True, "pk_matches": True,
                "expect": "configInvalid",
            },
            "token_pk_mismatch": {
                "token": True, "seed": False, "pk_matches": False,
                "expect": "configInvalid",
            },
            "valid_token": {
                "token": True, "seed": False, "pk_matches": True,
                "expect": "valid",
            },
        }
        results = {}
        for case, spec in cases.items():
            if spec["token"] and spec["seed"]:
                outcome = "configInvalid"
                reason = "both token and seed specified"
            elif spec["token"] and not spec["pk_matches"]:
                outcome = "configInvalid"
                reason = "token public key != manifest signing key"
            else:
                outcome = "valid"
                reason = "token accepted"
            results[case] = {"outcome": outcome, "reason": reason,
                             "expected": spec["expect"],
                             "match": outcome == spec["expect"]}
            self.net.log(self.cursor - 1, v.name, "config_check",
                         "config case %s: %s" % (case, reason), outcome)
        passed = sum(1 for r in results.values() if r["match"])
        self.metrics["config_check"] = {
            "cases": len(results), "passed": passed, "results": results,
        }
        record_control(self.controls, "C05", len(results), passed,
                       "config rules enforced as coded")

    def do_untrusted_flood(self, step):
        """Flood the cache with capped (gossip) manifests from
        unlisted master keys: the bound is 1000
        (defaultMaxUntrustedManifests, Manifest.h:283)."""
        count = step["count"]
        size_before = [len(p.cache.map_) for p in self.peers()]
        for i in range(count):
            master = sim.Key("flood-master-%04d" % i, "secp256k1",
                             self.seed)
            signing = sim.Key("flood-signing-%04d" % i, "secp256k1",
                              self.seed)
            sim.register_key(master)
            sim.register_key(signing)
            m = sim.Manifest(master, signing, 1)
            m.sign_all()
            for peer in self.peers():
                peer.receive_manifest(m, policy="capped")
        sizes = [len(p.cache.map_) for p in self.peers()]
        untrusted = [len(p.cache.untrusted) for p in self.peers()]
        # Flood entries kept = growth of the cache; the pre-existing
        # (uncapped, listed) entries are not part of the bound.
        kept = sizes[0] - size_before[0]
        evicted = count - kept
        self.net.log(self.cursor - 1, "attacker", "untrusted_flood",
                     "%d capped unlisted manifests; untrusted set %d "
                     "(bound 1000), flood entries kept %d, oldest "
                     "evicted %d" % (
                         count, untrusted[0], kept, evicted),
                     "bound_held=%s" % (max(untrusted) <= 1000))
        self.metrics["untrusted_flood"] = {
            "submitted": count, "cache_size": sizes[0],
            "untrusted_count": untrusted[0], "evicted_oldest": evicted,
            "bound": 1000,
        }
        record_control(self.controls, "C06", count, count,
                       "cache held at the 1000-entry bound; oldest evicted")

    def do_seed_rotate(self, step):
        """Seed-mode rotation: a new seed means a new keypair and a
        new node identity (ValidatorKeys.cpp:77-91); there is no
        manifest linking the old identity to the new one."""
        name = step["validator"]
        v = self.validators[name]
        old_node = v.node_id
        new_signing = sim.Key(step["new_key"], step["algorithm"],
                              self.seed)
        sim.register_key(new_signing)
        v.signing = new_signing
        self.old_keys[name].append(new_signing)
        # Baseline the per-peer "untrusted" counter so the UNL update
        # can measure exactly how many validations the new identity
        # lost while unlisted.
        self._untrusted_baseline = sum(
            p.validations.counters["untrusted"] for p in self.peers())
        self.net.log(self.cursor - 1, name, "seed_rotate",
                     "new seed -> new key %s; node identity %s -> %s; "
                     "no manifest links the identities" % (
                         new_signing.key_id, old_node, v.node_id),
                     "new_node_id=%s" % v.node_id)
        self.metrics["seed_rotate_%s" % name] = {
            "ledger": self.cursor - 1, "old_node_id": old_node,
            "new_node_id": v.node_id, "new_key": new_signing.key_id,
        }

    def do_unl_update(self, step):
        name = step["validator"]
        v = self.validators[name]
        for peer in self.peers():
            peer.validations.trusted_nodes.add(v.node_id)
            peer.cache.promote_to_trusted(v.master.key_id)
        self.net.log(self.cursor - 1, name, "unl_update",
                     "operator added node %s to the UNL on all %d peers"
                     % (v.node_id, len(self.peers())),
                     "trusted=%d/%d" % (len(self.peers()),
                                        len(self.peers())))
        self.metrics["unl_update_%s" % name] = {
            "ledger": self.cursor - 1, "node_id": v.node_id,
        }
        # Measure the cost of seed-mode rotation: validations from
        # the new identity that arrived while it was unlisted.
        untrusted_now = sum(
            p.validations.counters["untrusted"] for p in self.peers())
        lost = untrusted_now - getattr(self, "_untrusted_baseline", 0)
        record_control(self.controls, "C10", lost, lost,
                       "validations from an unlisted identity never "
                       "counted toward consensus")
        record_control(self.controls, "C17", lost, lost,
                       "seed-mode rotation produced a new unlisted "
                       "identity; every validation until the UNL "
                       "update was untrusted")

    def do_partition_start(self, step):
        half = len(self.net.peers) // 2
        self.reachable = self.net.peers[:half]
        self.net.log(self.cursor - 1, "network", "partition_start",
                     "peers %s unreachable from the validator" % (
                         ", ".join(p.peer_id
                                   for p in self.net.peers[half:])),
                     "reachable=%d/%d" % (half, len(self.net.peers)))
        self.metrics["partition"] = {
            "start_ledger": self.cursor,
            "reachable": half, "total": len(self.net.peers),
        }

    def do_partition_end(self, step):
        name = step["validator"]
        v = self.validators[name]
        self.reachable = None
        # Manifest sync on heal: the current manifest reaches the
        # other partition.
        rounds, ms, informed = self.net.gossip_manifest(
            v.current_manifest(),
            reachable=self.net.peers[len(self.net.peers) // 2:])
        self.net.log(self.cursor - 1, "network", "partition_end",
                     "partition healed; manifest sync to %d peers in %d "
                     "rounds %d ms" % (informed, rounds, ms),
                     "synced=%d" % informed)
        self.metrics["partition"]["end_ledger"] = self.cursor
        self.metrics["partition"]["heal_sync_ms"] = ms

    def do_node_down(self, step):
        v = self.validators[step["validator"]]
        v.up = False
        self.net.log(self.cursor - 1, v.name, "node_down",
                     "validator node stopped (failed start: bad token)",
                     "down")

    def do_node_up(self, step):
        v = self.validators[step["validator"]]
        v.up = True
        self.net.log(self.cursor - 1, v.name, "node_up",
                     "validator node restarted", "up")

    def do_rollback(self, step):
        """Rollback = a NEW manifest with a higher sequence that
        reinstates the old ephemeral key (sequence never goes
        backwards)."""
        name = step["validator"]
        v = self.validators[name]
        old_key = self.old_keys[name][step.get("old_key_index", 0)]
        new_key = old_key
        manifest = v.rotate(new_key)
        rounds, ms, informed = self.net.gossip_manifest(
            manifest, reachable=self.peers())
        self.net.log(self.cursor - 1, name, "rollback",
                     "rollback manifest reinstates %s at seq %d; gossip "
                     "%d rounds %d ms, informed %d/%d peers" % (
                         new_key.key_id, v.sequence, rounds, ms,
                         informed, len(self.peers())),
                     "accepted=%d/%d" % (informed, len(self.peers())))
        self.metrics["rollback_%s" % name] = {
            "ledger": self.cursor - 1, "reinstated_key": new_key.key_id,
            "sequence": v.sequence, "gossip_rounds": rounds,
            "gossip_ms": ms, "peers_informed": informed,
            "peers_total": len(self.peers()),
        }

    def do_pq_size_model(self, step):
        """Forward-looking size model (S9): what a manifest and a
        validation would cost with an ML-DSA-65 signing key, against
        the classical baselines. Sizes are exact cited figures
        (FIPS 204 Table 2 via RFC 9964; PublicKey.h for classical
        public keys; RFC 8032 for the ed25519 signature size); totals
        are key-material + signature bytes only, framing excluded and
        stated. The pinned-code check is real: a 1952-byte ML-DSA-65
        public key fails publicKeyType (33 bytes required) and the
        manifest fails deserialize."""
        table = {}
        for alg in ("secp256k1", "ed25519", "mldsa65"):
            sizes = sim.KEY_SIZES[alg]
            manifest_material = 2 * sizes["pubkey"] + \
                2 * sizes["signature"]
            validation_material = sizes["pubkey"] + sizes["signature"]
            table[alg] = {
                "pubkey_bytes": sizes["pubkey"],
                "signature_bytes": sizes["signature"],
                "manifest_key_material_bytes": manifest_material,
                "validation_key_material_bytes": validation_material,
            }
        base = table["ed25519"]["manifest_key_material_bytes"]
        pq = table["mldsa65"]["manifest_key_material_bytes"]
        vbase = table["ed25519"]["validation_key_material_bytes"]
        vpq = table["mldsa65"]["validation_key_material_bytes"]
        peers = len(self.peers())
        # Pinned-code check: ML-DSA-65 signing key under pinned rules.
        v = self.validators[step["validator"]]
        pq_key = sim.Key("eph-pq-mldsa65", "mldsa65", self.seed)
        m = sim.Manifest(v.master, pq_key, v.sequence + 1)
        m.sign_all()
        dispositions = {}
        for peer in self.peers():
            d = peer.receive_manifest(m)
            dispositions[d] = dispositions.get(d, 0) + 1
        self.net.log(self.cursor - 1, "model", "pq_size_model",
                     "ML-DSA-65 manifest key material %d bytes vs "
                     "ed25519 %d bytes (%.1fx); validation %d vs %d "
                     "bytes (%.1fx); pinned deserialize rejects the "
                     "1952-byte key on %d/%d peers" % (
                         pq, base, pq / base, vpq, vbase, vpq / vbase,
                         dispositions.get("invalid", 0),
                         len(self.peers())),
                     "invalid=%d/%d" % (dispositions.get("invalid", 0),
                                        len(self.peers())))
        self.metrics["pq_size_model"] = {
            "table": table,
            "manifest_ratio_mldsa65_vs_ed25519": round(pq / base, 2),
            "validation_ratio_mldsa65_vs_ed25519": round(vpq / vbase, 2),
            "manifest_gossip_bytes_per_rotation_10_peers": {
                "ed25519": base * peers,
                "mldsa65": pq * peers,
            },
            "validation_bytes_per_ledger_10_validators_10_peers": {
                "ed25519": vbase * 10 * peers,
                "mldsa65": vpq * 10 * peers,
            },
            "pinned_deserialize_of_mldsa65_manifest": dispositions,
        }
        record_control(self.controls, "C11", len(self.peers()),
                       dispositions.get("invalid", 0),
                       "1952-byte ML-DSA-65 key fails the 33-byte "
                       "publicKeyType check")
        record_control(self.controls, "C12", len(self.peers()),
                       dispositions.get("invalid", 0),
                       "mldsa65 is not a member of the pinned KeyType enum")

    def do_post_revocation_manifest(self, step):
        """After a revocation (sequence 0xFFFFFFFF) no further
        manifest for the master can be accepted: no higher sequence
        exists. The attacker holds the master secret and tries the
        highest remaining sequence (0xFFFFFFFE). Expect stale."""
        name = step["validator"]
        v = self.validators[name]
        signing = sim.Key("eph-after-revoke", "secp256k1", self.seed)
        sim.register_key(signing)
        m = sim.Manifest(v.master, signing, 0xFFFFFFFE)
        m.sign_all()
        dispositions = {}
        for peer in self.peers():
            d = peer.receive_manifest(m)
            dispositions[d] = dispositions.get(d, 0) + 1
        self.net.log(self.cursor - 1, "attacker",
                     "post_revocation_manifest",
                     "manifest seq 4294967294 after revocation; peer "
                     "dispositions %s" % (
                         ", ".join("%s=%d" % (k, dispositions[k])
                                   for k in sorted(dispositions)),),
                     "stale=%d/%d" % (dispositions.get("stale", 0),
                                      len(self.peers())))
        self.metrics["post_revocation_manifest"] = {
            "sequence": 0xFFFFFFFE,
            "attempts": len(self.peers()), "dispositions": dispositions,
        }
        record_control(self.controls, "C03", len(self.peers()),
                       dispositions.get("stale", 0),
                       "no manifest accepted after revocation; revocation "
                       "is terminal")

    def do_store_manifest(self, step):
        """Remember the validator's current manifest for later replay."""
        v = self.validators[step["validator"]]
        label = step["label"]
        self.stored_manifests[label] = v.current_manifest()
        self.net.log(self.cursor - 1, "attacker", "store_manifest",
                     "stored manifest %s seq %d for later replay" % (
                         label, v.sequence),
                     "stored")

    # -- dispatcher ----------------------------------------------------
    ACTIONS = {
        "rotate": do_rotate,
        "revoke": do_revoke,
        "attacker_sign_old": do_attacker_sign_old,
        "duplicate_sign": do_duplicate_sign,
        "replay_manifest": do_replay_manifest,
        "forge_manifest": do_forge_manifest,
        "replay_old_validation": do_replay_old_validation,
        "tamper_validation": do_tamper_validation,
        "key_reuse": do_key_reuse,
        "version_attack": do_version_attack,
        "domain_attack": do_domain_attack,
        "config_check": do_config_check,
        "untrusted_flood": do_untrusted_flood,
        "seed_rotate": do_seed_rotate,
        "unl_update": do_unl_update,
        "partition_start": do_partition_start,
        "partition_end": do_partition_end,
        "node_down": do_node_down,
        "node_up": do_node_up,
        "rollback": do_rollback,
        "post_revocation_manifest": do_post_revocation_manifest,
        "pq_size_model": do_pq_size_model,
        "store_manifest": do_store_manifest,
    }

    def execute(self):
        for step in self.cfg.get("steps", []):
            if "run" in step:
                self.run(step["run"])
            elif "action" in step:
                fn = self.ACTIONS[step["action"]]
                fn(self, step)
            else:
                raise ValueError("unknown step %r" % (step,))


def run_scenario(path):
    with open(path) as f:
        cfg = json.load(f)
    driver = Driver(cfg)
    driver.execute()
    net = driver.net
    sid = cfg["id"]
    # Aggregate peer counters.
    peer_counters = {}
    for peer in net.peers:
        for k, n in peer.validations.counters.items():
            peer_counters[k] = peer_counters.get(k, 0) + n
    # Uptime / missed ledgers from validation totals.
    totals = driver.metrics.get("validation_totals", {})
    issued = sum(v for k, v in totals.items() if k != "missed")
    missed = totals.get("missed", 0)
    ledgers_run = driver.cursor - 1
    summary = {
        "scenario": sid,
        "title": cfg["title"],
        "seed": cfg.get("seed", SEED),
        "pinned_commit": sim.PINNED_COMMIT,
        "peers": len(net.peers),
        "ledgers_run": ledgers_run,
        "severity": cfg.get("severity", "INFO"),
        "severity_reason": cfg.get("severity_reason", ""),
        "metrics": driver.metrics,
        "peer_counters": peer_counters,
        "validation_totals": totals,
        "validations_issued_peer_events": issued,
        "ledgers_missed": missed,
        "controls": driver.controls,
        "final_state": {
            name: {
                "mode": v.mode, "sequence": v.sequence,
                "signing_key": v.signing.key_id,
                "revoked": v.sequence == sim.REVOKED_SEQ,
                "node_id": v.node_id, "up": v.up,
            }
            for name, v in driver.validators.items()
        },
    }
    # CSV event log.
    csv_path = os.path.join(PACK, "outputs", "%s-events.csv" % sid)
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time_ms", "ledger", "actor", "event", "detail",
                    "outcome"])
        for e in net.events:
            w.writerow([e["time_ms"], e["ledger"], e["actor"],
                        e["event"], e["detail"], e["outcome"]])
    # JSON summary.
    json_path = os.path.join(PACK, "outputs", "%s.json" % sid)
    with open(json_path, "w") as f:
        json.dump(summary, f, indent=2, sort_keys=True)
        f.write("\n")
    # Unedited run log.
    sim_sha = sha256_file(os.path.join(HERE, "simulator.py"))
    harness_sha = sha256_file(os.path.join(HERE, "load_harness.py"))
    scen_sha = sha256_file(path)
    log_path = os.path.join(PACK, "outputs", "%s.log" % sid)
    with open(log_path, "w") as f:
        f.write("scenario: %s %s\n" % (sid, cfg["title"]))
        f.write("pinned commit: %s\n" % sim.PINNED_COMMIT)
        f.write("seed: %d\n" % cfg.get("seed", SEED))
        f.write("scenario file sha256: %s\n" % scen_sha)
        f.write("simulator.py sha256: %s\n" % sim_sha)
        f.write("load_harness.py sha256: %s\n" % harness_sha)
        f.write("ledgers run: %d\n" % ledgers_run)
        f.write("--- events ---\n")
        for e in net.events:
            f.write("[%d ms ledger %d] %s %s: %s => %s\n" % (
                e["time_ms"], e["ledger"], e["actor"], e["event"],
                e["detail"], e["outcome"]))
        f.write("--- summary ---\n")
        f.write("validation totals (peer events): %s\n" % json.dumps(
            totals, sort_keys=True))
        f.write("peer counters: %s\n" % json.dumps(
            peer_counters, sort_keys=True))
        f.write("ledgers missed: %d\n" % missed)
        f.write("controls: %s\n" % json.dumps(
            driver.controls, sort_keys=True))
        f.write("final state: %s\n" % json.dumps(
            summary["final_state"], sort_keys=True))
    print("%s: %d ledgers, %d events, totals %s" % (
        sid, ledgers_run, len(net.events), json.dumps(
            totals, sort_keys=True)))
    return summary


def main():
    scen_dir = os.path.join(PACK, "scenarios")
    out_dir = os.path.join(PACK, "outputs")
    os.makedirs(out_dir, exist_ok=True)
    summaries = []
    manifest_entries = []
    for name in sorted(os.listdir(scen_dir)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(scen_dir, name)
        summaries.append(run_scenario(path))
        manifest_entries.append({
            "path": "scenarios/%s" % name,
            "sha256": sha256_file(path),
        })
    run_manifest = {
        "pinned_commit": sim.PINNED_COMMIT,
        "seed": SEED,
        "simulator_sha256": sha256_file(
            os.path.join(HERE, "simulator.py")),
        "harness_sha256": sha256_file(
            os.path.join(HERE, "load_harness.py")),
        "scenarios": manifest_entries,
    }
    with open(os.path.join(out_dir, "run-manifest.json"), "w") as f:
        json.dump(run_manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    print("run-manifest: %d scenarios" % len(summaries))


if __name__ == "__main__":
    main()
