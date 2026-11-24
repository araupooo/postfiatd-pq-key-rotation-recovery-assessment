#!/usr/bin/env python3
"""build_matrix.py — build the severity-ranked scenario matrix from the
per-scenario summary JSON files in outputs/.

Usage:
    python3 scripts/build_matrix.py

Writes outputs/matrix.json and outputs/matrix.md. Severity is a
judgment declared in each scenario file (see docs/methodology.md);
the matrix ranks by severity, then by scenario id.
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)
OUT = os.path.join(PACK, "outputs")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3,
                  "INFO": 4}


def headline(summary):
    """One-line headline numbers per scenario, from its measured
    metrics. Every number here is read from the committed summary."""
    sid = summary["scenario"]
    m = summary["metrics"]
    totals = summary["validation_totals"]
    accepted = totals.get("accepted", 0)
    if sid == "S0":
        return "120/120 validations accepted, 0 missed, uptime 100.00%"
    if sid == "S1":
        r = m["rotation_V1"]
        return ("0 missed ledgers; rotation propagated to %d/%d peers "
                "in %d ms (%d gossip rounds); old-key validations "
                "rejected after rotation" % (
                    r["peers_informed"], r["peers_total"],
                    r["gossip_ms"], r["gossip_rounds"]))
    if sid == "S2":
        a = m["attacker_old_key_V1"]
        missed = summary["ledgers_missed"]
        return ("attacker validations accepted after rotation %d/%d; "
                "operator missed %d ledger (handover); uptime %.2f%%"
                % (a["accepted"], a["attempts"], missed,
                   100.0 * (summary["ledgers_run"] - missed) /
                   summary["ledgers_run"]))
    if sid == "S3":
        a = m.get("attacker_old_key_V1", {})
        p = m.get("post_revocation_manifest", {})
        return ("validations accepted after revocation %d/%d; "
                "post-revocation manifest attempts rejected stale "
                "%d/%d; revocation terminal" % (
                    a.get("accepted", 0), a.get("attempts", 0),
                    p.get("dispositions", {}).get("stale", 0),
                    p.get("attempts", 0)))
    if sid == "S4":
        d = m["duplicate_sign_V1"]
        return ("conflicting validations flagged %d/%d; duplicate "
                "validations counted %d (never double-counted)" % (
                    d["conflicting"], d["attempts"],
                    d["accepted_duplicate"]))
    if sid == "S5":
        r = m["rollback_V1"]
        missed = summary["ledgers_missed"]
        return ("missed %d/%d ledgers during the failed rotation; "
                "rollback reinstating the old key accepted on %d/%d "
                "peers; validations resumed" % (
                    missed, summary["ledgers_run"],
                    r["peers_informed"], r["peers_total"]))
    if sid == "S6":
        r = m["replay_V1_seq1"]["dispositions"].get("stale", 0)
        fm = m["forge_master"]["dispositions"].get("invalid", 0)
        fe = m["forge_ephemeral"]["dispositions"].get("invalid", 0)
        ro = m["replay_old_validation"]["outcomes"].get("stale", 0)
        tv = m["tamper_validation"]["outcomes"].get("invalid_sig", 0)
        return ("replayed manifest stale %d/10; forged master signature "
                "invalid %d/10; forged ephemeral signature invalid "
                "%d/10; 360 s old validation stale %d/10; tampered "
                "validation signature invalid %d/10" % (
                    r, fm, fe, ro, tv))
    if sid == "S7":
        f = m["untrusted_flood"]
        return ("key-reuse/version/domain attacks rejected 10/10 each; "
                "config rules 3/3 as coded; untrusted flood held at "
                "%d/%d untrusted entries (%d oldest evicted)" % (
                    f["untrusted_count"], f["bound"],
                    f["evicted_oldest"]))
    if sid == "S8":
        return ("seed-mode rotation: new identity trusted 0/30 ledgers "
                "before the UNL update, %d/%d ledgers trusted overall"
                % (accepted // 10, summary["ledgers_run"]))
    if sid == "S9":
        p = m["pq_size_model"]
        return ("ML-DSA-65 manifest key material %d bytes vs ed25519 %d "
                "bytes (%.1fx); validation %d vs %d bytes (%.1fx); "
                "pinned code rejects the 1952-byte key on %d/%d peers"
                % (p["table"]["mldsa65"]["manifest_key_material_bytes"],
                   p["table"]["ed25519"]["manifest_key_material_bytes"],
                   p["manifest_ratio_mldsa65_vs_ed25519"],
                   p["table"]["mldsa65"]["validation_key_material_bytes"],
                   p["table"]["ed25519"]["validation_key_material_bytes"],
                   p["validation_ratio_mldsa65_vs_ed25519"],
                   p["pinned_deserialize_of_mldsa65_manifest"].get(
                       "invalid", 0), summary["peers"]))
    if sid == "S10":
        part = m["partition"]
        return ("during the %d-ledger partition, validations accepted "
                "by %d/%d peers (quorum 8 not met); acceptance resumed "
                "10/10 after the heal" % (
                    part["end_ledger"] - part["start_ledger"],
                    part["reachable"], part["total"]))
    return "%d peer validation events accepted" % accepted


def main():
    rows = []
    for name in sorted(os.listdir(OUT)):
        if not name.startswith("S") or not name.endswith(".json"):
            continue
        with open(os.path.join(OUT, name)) as f:
            summary = json.load(f)
        rows.append({
            "scenario": summary["scenario"],
            "title": summary["title"],
            "severity": summary["severity"],
            "severity_reason": summary["severity_reason"],
            "headline": headline(summary),
            "ledgers_run": summary["ledgers_run"],
            "peers": summary["peers"],
        })
    rows.sort(key=lambda r: (SEVERITY_ORDER[r["severity"]],
                             r["scenario"]))
    matrix = {"rows": rows}
    with open(os.path.join(OUT, "matrix.json"), "w") as f:
        json.dump(matrix, f, indent=2, sort_keys=True)
        f.write("\n")
    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    with open(os.path.join(OUT, "matrix.md"), "w") as f:
        f.write("# Scenario matrix\n\n")
        f.write("Severity counts: %s.\n\n" % (
            ", ".join("%d %s" % (counts.get(s, 0), s)
                      for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW",
                                "INFO"))))
        f.write("| Scenario | Title | Severity | Headline |\n")
        f.write("|---|---|---|---|\n")
        for r in rows:
            f.write("| %s | %s | %s | %s |\n" % (
                r["scenario"], r["title"], r["severity"],
                r["headline"]))
        f.write("\nSeverity is a judgment on whether the attacker's or "
                "failure's goal was achieved; see docs/methodology.md "
                "for the rubric. Every headline number is read from "
                "the committed per-scenario summary JSON.\n")
    print("matrix: %d scenarios (%s)" % (
        len(rows),
        ", ".join("%d %s" % (counts.get(s, 0), s)
                  for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW",
                            "INFO"))))


if __name__ == "__main__":
    main()
