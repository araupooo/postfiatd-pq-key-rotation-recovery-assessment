#!/usr/bin/env python3
"""measure_controls.py — aggregate per-control effectiveness from the
per-scenario summary JSON files in outputs/.

Usage:
    python3 scripts/measure_controls.py

Writes outputs/control-measurements.json and
outputs/control-measurements.md. Effectiveness is the share of attack
attempts a control stopped, counted from the committed scenario
outputs. A control no scenario exercised is UNMEASURED, never
assigned a number.
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)
OUT = os.path.join(PACK, "outputs")

PINNED = "0085a1ff885d6a446369cf73a4430f75af22be55"

# Control inventory: id, name, pinned-code citation, scenarios that
# exercise it. Line numbers are from the local checkout at the pinned
# commit, verified blob-by-blob against the GitHub API tree.
CONTROLS = [
    ("C00", "Manifest sequence monotonicity (stale rejection)",
     "src/xrpld/app/misc/detail/Manifest.cpp:411-425", ["S6"]),
    ("C01", "Master-signature verification on manifests",
     "src/xrpld/app/misc/detail/Manifest.cpp:198-214", ["S6"]),
    ("C02", "Ephemeral-signature verification on manifests",
     "src/xrpld/app/misc/detail/Manifest.cpp:198-214", ["S6"]),
    ("C03", "Revocation is terminal (sequence 0xFFFFFFFF)",
     "src/xrpld/app/misc/detail/Manifest.cpp:226-241,438-444", ["S3"]),
    ("C04", "Key-reuse bans (master/ephemeral cross-use)",
     "src/xrpld/app/misc/detail/Manifest.cpp:447-497", ["S7"]),
    ("C05", "Validator token / seed config rules",
     "src/xrpld/app/misc/detail/ValidatorKeys.cpp:35-75", ["S7"]),
    ("C06", "Untrusted manifest cache bound (1000 entries)",
     "src/xrpld/app/misc/Manifest.h:283", ["S7"]),
    ("C07", "SeqEnforcer: monotonic validation sequence per node",
     "src/xrpld/consensus/Validations.h:92-135", ["S4"]),
    ("C08", "Conflicting-validation detection (double-sign)",
     "src/xrpld/consensus/Validations.h:623-700", ["S4"]),
    ("C09", "Validation currency windows",
     "src/xrpld/consensus/Validations.h:46-89,149-166", ["S6"]),
    ("C10", "UNL trust gating (node identity must be listed)",
     "src/xrpld/app/misc/detail/ValidatorList.cpp:220-231", ["S8"]),
    ("C11", "Fixed 33-byte public-key buffer",
     "include/xrpl/protocol/PublicKey.h:65", ["S9"]),
    ("C12", "Key-type allowlist (secp256k1, ed25519 only)",
     "include/xrpl/protocol/KeyType.h:28-31; "
     "src/libxrpl/protocol/PublicKey.cpp:223-236", ["S9"]),
    ("C13", "Manifest version gate (only version 0)",
     "src/xrpld/app/misc/detail/Manifest.cpp:91-93", ["S7"]),
    ("C14", "Manifest domain format check",
     "src/xrpld/app/misc/detail/Manifest.cpp:103-111", ["S7"]),
    ("C15", "Validation signature verification (STValidation)",
     "src/libxrpl/protocol/STValidation.cpp:123-150", ["S6"]),
    ("C16", "Manifest key-currency (superseded key never counts)",
     "src/xrpld/app/misc/Manifest.h:357; "
     "src/xrpld/app/misc/detail/Manifest.cpp:567-590",
     ["S1", "S2", "S3"]),
    ("C17", "Seed mode has no rotation mechanism (negative control)",
     "src/xrpld/app/misc/detail/ValidatorKeys.cpp:77-91", ["S8"]),
]


def main():
    measured = {}
    for name in sorted(os.listdir(OUT)):
        if not name.startswith("S") or not name.endswith(".json"):
            continue
        with open(os.path.join(OUT, name)) as f:
            summary = json.load(f)
        for cid, data in summary.get("controls", {}).items():
            entry = measured.setdefault(cid, {"attempts": 0,
                                              "stopped": 0,
                                              "scenarios": [],
                                              "notes": []})
            entry["attempts"] += data.get("attempts", 0)
            entry["stopped"] += data.get("stopped", 0)
            entry["scenarios"].append(summary["scenario"])
            entry["notes"].extend(data.get("notes", []))
    rows = []
    for cid, name, citation, scenarios in CONTROLS:
        data = measured.get(cid)
        if data is None or data["attempts"] == 0:
            rows.append({
                "control": cid, "name": name, "citation": citation,
                "scenarios": scenarios, "attempts": 0, "stopped": 0,
                "effectiveness_pct": None, "status": "UNMEASURED",
                "notes": ["no scenario exercised this control"],
            })
        else:
            eff = 100.0 * data["stopped"] / data["attempts"]
            rows.append({
                "control": cid, "name": name, "citation": citation,
                "scenarios": sorted(set(data["scenarios"])),
                "attempts": data["attempts"],
                "stopped": data["stopped"],
                "effectiveness_pct": round(eff, 2),
                "status": "MEASURED",
                "notes": sorted(set(data["notes"])),
            })
    result = {"pinned_commit": PINNED, "controls": rows}
    with open(os.path.join(OUT, "control-measurements.json"),
              "w") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")
    with open(os.path.join(OUT, "control-measurements.md"), "w") as f:
        f.write("# Control measurements\n\n")
        f.write("| Control | Effectiveness | Attempts | Stopped | "
                "Status | Scenarios |\n")
        f.write("|---|---|---|---|---|---|\n")
        for r in rows:
            eff = ("%.2f%%" % r["effectiveness_pct"]
                   if r["effectiveness_pct"] is not None else "n/a")
            f.write("| %s %s | %s | %d | %d | %s | %s |\n" % (
                r["control"], r["name"], eff, r["attempts"],
                r["stopped"], r["status"],
                ", ".join(r["scenarios"])))
        f.write("\n")
        for r in rows:
            f.write("## %s %s\n\n" % (r["control"], r["name"]))
            f.write("Citation: `%s` at pinned commit %s.\n\n" % (
                r["citation"], PINNED))
            for note in r["notes"]:
                f.write("- %s\n" % note)
            f.write("\n")
    n_measured = sum(1 for r in rows if r["status"] == "MEASURED")
    print("controls: %d measured, %d unmeasured" % (
        n_measured, len(rows) - n_measured))


if __name__ == "__main__":
    main()
