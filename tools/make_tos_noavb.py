"""Build a "no-AVB" trustos image.

Takes the stock sml + trustos of one slot, patches the AVB verdict inside TOS and
wraps the result so the signature still verifies (CVE-2022-38691). Writes
`tos-noavb-bsp-bypassed_<slot>.bin`, which goes into the `trustos` partition.

    python make_tos_noavb.py --slot b --dump dump --out images \
        --spd-dump tools/spd_dump.exe

Inputs: dump/sml_b and dump/trustos_b (read them from the tablet with
`session.ps1 -Action read`, or take sml-sign.bin / tos-sign.bin from the factory
pac with `extract_pac.py`).

The patch itself is done by spd_dump's proven C implementation (`dis_avb_ex`), run
in offline tool mode. Every property of the result is then re-checked here before
the file is saved.
"""
import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TRUSTOS_PART_SIZE = 6 * 1024 * 1024
DHTB = 0x200


def sha(b):
    return hashlib.sha256(b).hexdigest()


def dhtb_header(d):
    if d[:4] != b"DHTB":
        raise SystemExit("not a DHTB image: %r" % d[:4])
    return dict(
        mImgSize=struct.unpack_from("<I", d, 0x30)[0],
        mPayloadHash=d[8:40],
        mFirmwareSize=struct.unpack_from("<I", d, 0x3C)[0],
    )


def simghdr(d):
    """SIMGHDR sits right after the payload it describes."""
    h = dhtb_header(d)
    off = DHTB + h["mImgSize"]
    if d[off:off + 8] != b"SIMGHDR\x00":
        raise SystemExit("no SIMGHDR at 0x%x" % off)
    q = struct.unpack_from("<8Q", d, off + 8)
    return dict(off=off, payload_size=q[1], payload_offset=q[2],
                cert_size=q[3], cert_offset=q[4])


def run_c_tool(exe, sml_src, tos_src, work):
    shutil.copyfile(sml_src, os.path.join(work, "sml.bin"))
    shutil.copyfile(tos_src, os.path.join(work, "trustos.bin"))
    proc = subprocess.run(
        [exe, "-t", "dis_avb_ex", "sml.bin", "trustos.bin"],
        cwd=work, input="exit\n", capture_output=True, text=True, errors="replace",
    )
    out = (proc.stdout or "") + (proc.stderr or "")
    if not os.path.exists(os.path.join(work, "tos-noavb-bsp-bypassed")):
        print(out)
        raise SystemExit("dis_avb_ex produced no image")
    if "patch mov at" not in out:
        print(out)
        raise SystemExit("patch site not found: image layout is not what this tool expects")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--slot", default="b", choices=["a", "b"])
    ap.add_argument("--dump", default=os.path.join(ROOT, "dump"),
                    help="folder with sml_<slot> and trustos_<slot>")
    ap.add_argument("--out", default=os.path.join(ROOT, "images"))
    ap.add_argument("--spd-dump", default=os.path.join(ROOT, "tools", "spd_dump.exe"),
                    help="path to spd_dump.exe (offline tool mode)")
    args = ap.parse_args()

    sml_src = os.path.join(args.dump, "sml_" + args.slot)
    tos_src = os.path.join(args.dump, "trustos_" + args.slot)
    for p in (sml_src, tos_src, args.spd_dump):
        if not os.path.exists(p):
            raise SystemExit("missing: " + p)

    work = os.path.join(ROOT, "out", "_tosbuild")
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    try:
        log = run_c_tool(args.spd_dump, sml_src, tos_src, work)
        for line in log.strip().splitlines():
            if line.startswith(("avb marker", "detected mov", "patch mov", "chsize")):
                print("  " + line)

        sml = open(sml_src, "rb").read()
        tos = open(tos_src, "rb").read()
        patched = open(os.path.join(work, "tos-noavb"), "rb").read()
        merged = open(os.path.join(work, "tos-noavb-bsp-bypassed"), "rb").read()

        sml_h, tos_h = dhtb_header(sml), dhtb_header(tos)
        merged_h = dhtb_header(merged)
        merged_s = simghdr(merged)

        diffs = [i for i in range(0, min(len(tos), len(patched)), 4)
                 if tos[i:i + 4] != patched[i:i + 4]]
        patch_pos = diffs[0] if diffs else -1

        checks = []
        checks.append(("TOS: exactly one instruction changed", len(diffs) == 1, hex(patch_pos)))
        checks.append(("TOS: patch is mov w0,#0 (0x52800000)",
                       patched[patch_pos:patch_pos + 4] == b"\x00\x00\x80\x52", ""))
        checks.append(("TOS: size unchanged", len(tos) == len(patched), str(len(patched))))
        checks.append(("merged: mImgSize = tos + sml",
                       merged_h["mImgSize"] == tos_h["mImgSize"] + sml_h["mImgSize"],
                       hex(merged_h["mImgSize"])))
        checks.append(("merged: TOS payload = patched TOS",
                       merged[DHTB:DHTB + tos_h["mImgSize"]]
                       == patched[DHTB:DHTB + tos_h["mImgSize"]], ""))
        checks.append(("merged: SML payload = stock",
                       merged[DHTB + tos_h["mImgSize"]:DHTB + tos_h["mImgSize"] + sml_h["mImgSize"]]
                       == sml[DHTB:DHTB + sml_h["mImgSize"]], ""))
        checks.append(("merged: SIMGHDR points at the SML region",
                       merged_s["payload_offset"] == DHTB + tos_h["mImgSize"]
                       and merged_s["payload_size"] == sml_h["mImgSize"],
                       "offset=0x%x size=0x%x" % (merged_s["payload_offset"], merged_s["payload_size"])))
        signed = merged[merged_s["payload_offset"]:merged_s["payload_offset"] + merged_s["payload_size"]]
        checks.append(("merged: signed region hash = stock SML hash",
                       sha(signed) == sml_h["mPayloadHash"].hex(), sha(signed)[:16]))
        checks.append(("merged: fits trustos partition (6 MiB)",
                       len(merged) <= TRUSTOS_PART_SIZE,
                       "%d bytes, %d free" % (len(merged), TRUSTOS_PART_SIZE - len(merged))))
        checks.append(("merged: patched instruction in place",
                       merged[patch_pos:patch_pos + 4] == b"\x00\x00\x80\x52", hex(patch_pos)))

        width = max(len(c[0]) for c in checks)
        ok = True
        for name, good, extra in checks:
            ok &= bool(good)
            print("  [%s] %-*s  %s" % ("OK " if good else "FAIL", width, name, extra))
        if not ok:
            raise SystemExit("checks failed - image NOT saved")

        os.makedirs(args.out, exist_ok=True)
        dst = os.path.join(args.out, "tos-noavb-bsp-bypassed_%s.bin" % args.slot)
        with open(dst, "wb") as f:
            f.write(merged)
        print()
        print("done:", dst)
        print("  size     : %d bytes (0x%x)" % (len(merged), len(merged)))
        print("  sha256   :", sha(merged))
        return 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
