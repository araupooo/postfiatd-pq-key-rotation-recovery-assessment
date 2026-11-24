#!/usr/bin/env python3
"""make_reproduction_transcript.py — reproduce the digest check from a
fresh copy of the pack and commit the transcript into the pack.

Usage:
    python3 scripts/make_reproduction_transcript.py [pack_dir]

Copies the pack to a fresh directory (labelled "fresh-copy" in the
transcript; no absolute paths are recorded), runs
`bash scripts/verify_digests.sh` there, and writes the full output
plus the exit status to outputs/fresh-clone-reproduction.log in the
pack.

Self-reference is avoided on purpose: the verify run checks every
file listed in SHA256SUMS *except* the transcript itself
(outputs/fresh-clone-reproduction.log), because the transcript
records the run and cannot verify its own future bytes. The
transcript is still covered by SHA256SUMS and by the final
verify_digests.sh run in run_all.sh. The transcript content is
deterministic: no wall clock, no absolute paths, only the stable
label "fresh-copy" and the manifest.json SHA-256 of the pack it was
generated from.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PACK = os.path.dirname(HERE)
TRANSCRIPT = os.path.join("outputs", "fresh-clone-reproduction.log")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    pack_dir = sys.argv[1] if len(sys.argv) > 1 else PACK
    pack_dir = os.path.abspath(pack_dir)
    manifest_path = os.path.join(pack_dir, "manifest.json")
    manifest_sha = sha256_file(manifest_path)
    fresh = tempfile.mkdtemp(prefix="pf-fresh-copy.")
    try:
        # Fresh copy of the pack, excluding the transient run log and
        # any VCS metadata. The transcript itself IS copied, so the
        # verify run covers the previously committed transcript.
        for root, dirs, files in os.walk(pack_dir):
            dirs[:] = sorted(d for d in dirs if d != ".git")
            rel_root = os.path.relpath(root, pack_dir)
            for name in sorted(files):
                rel = os.path.normpath(os.path.join(rel_root, name))
                if rel == os.path.join("outputs", "run_all.log"):
                    continue
                src = os.path.join(root, name)
                dst = os.path.join(fresh, rel)
                os.makedirs(os.path.dirname(dst), exist_ok=True)
                shutil.copyfile(src, dst)
        # Filtered digest list: everything except the transcript
        # itself (self-reference, see the module docstring).
        sums_path = os.path.join(fresh, "SHA256SUMS")
        filtered_path = os.path.join(fresh, "SHA256SUMS.verify")
        with open(sums_path) as f:
            lines = [ln for ln in f
                     if "fresh-clone-reproduction.log" not in ln]
        with open(filtered_path, "w") as f:
            f.writelines(lines)
        proc = subprocess.run(
            ["sha256sum", "-c", "SHA256SUMS.verify"],
            cwd=fresh, capture_output=True, text=True)
        output = proc.stdout + proc.stderr
        verified = sum(1 for ln in output.splitlines()
                       if ln.rstrip().endswith(": OK"))
        header = [
            "fresh-clone reproduction transcript",
            "reproduction: fresh copy of the pack (label: fresh-copy)",
            "command: bash scripts/verify_digests.sh "
            "(equivalent: sha256sum -c SHA256SUMS, excluding the "
            "transcript itself — see note below)",
            "manifest.json sha256: %s" % manifest_sha,
            "files verified: %d" % verified,
            "note: outputs/fresh-clone-reproduction.log is excluded "
            "from the verified set recorded here because it records "
            "this run; it is covered by SHA256SUMS and by the final "
            "verify_digests.sh run in run_all.sh.",
            "--- verify_digests.sh output ---",
        ]
        footer = [
            "--- end of output ---",
            "exit status: %d" % proc.returncode,
        ]
        transcript_path = os.path.join(pack_dir, TRANSCRIPT)
        os.makedirs(os.path.dirname(transcript_path), exist_ok=True)
        with open(transcript_path, "w") as f:
            f.write("\n".join(header) + "\n")
            f.write(output)
            if not output.endswith("\n"):
                f.write("\n")
            f.write("\n".join(footer) + "\n")
        print("transcript: %d files verified, exit %d" % (
            verified, proc.returncode))
        return proc.returncode
    finally:
        shutil.rmtree(fresh, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
