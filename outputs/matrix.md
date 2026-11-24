# Scenario matrix

Severity counts: 0 CRITICAL, 2 HIGH, 2 MEDIUM, 5 LOW, 2 INFO.

| Scenario | Title | Severity | Headline |
|---|---|---|---|
| S10 | Rotation during a network partition | HIGH | during the 10-ledger partition, validations accepted by 5/10 peers (quorum 8 not met); acceptance resumed 10/10 after the heal |
| S8 | Seed-mode rotation is an identity change | HIGH | seed-mode rotation: new identity trusted 0/30 ledgers before the UNL update, 90/120 ledgers trusted overall |
| S4 | Duplicated token: same key signs divergent ledgers | MEDIUM | conflicting validations flagged 100/100; duplicate validations counted 0 (never double-counted) |
| S9 | Post-quantum size model and the key-type gap | MEDIUM | ML-DSA-65 manifest key material 10522 bytes vs ed25519 194 bytes (54.2x); validation 5261 vs 97 bytes (54.2x); pinned code rejects the 1952-byte key on 10/10 peers |
| S2 | Emergency rotation after suspected ephemeral-key compromise | LOW | attacker validations accepted after rotation 0/590; operator missed 1 ledger (handover); uptime 99.17% |
| S3 | Master-key compromise: revocation and terminal sequence | LOW | validations accepted after revocation 0/600; post-revocation manifest attempts rejected stale 10/10; revocation terminal |
| S5 | Rollback after a failed rotation | LOW | missed 10/120 ledgers during the failed rotation; rollback reinstating the old key accepted on 10/10 peers; validations resumed |
| S6 | Replay and forgery resistance | LOW | replayed manifest stale 10/10; forged master signature invalid 10/10; forged ephemeral signature invalid 10/10; 360 s old validation stale 10/10; tampered validation signature invalid 10/10 |
| S7 | Key-reuse bans, malformed manifests, config rules, cache flood | LOW | key-reuse/version/domain attacks rejected 10/10 each; config rules 3/3 as coded; untrusted flood held at 1000/1000 untrusted entries (5 oldest evicted) |
| S0 | Baseline steady-state validation issuance | INFO | 120/120 validations accepted, 0 missed, uptime 100.00% |
| S1 | Scheduled rotation with a pre-staged new key | INFO | 0 missed ledgers; rotation propagated to 10/10 peers in 2000 ms (4 gossip rounds); old-key validations rejected after rotation |

Severity is a judgment on whether the attacker's or failure's goal was achieved; see docs/methodology.md for the rubric. Every headline number is read from the committed per-scenario summary JSON.
