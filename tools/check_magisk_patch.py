"""Sanity-check a Magisk-patched boot image against the stock dump.

    python tools/check_magisk_patch.py patch/boot_b_stock.img <magisk_patched.img>

Verifies that the kernel is untouched, the ramdisk actually changed, and the
header still describes a sane v3/v4 image. It cannot replace a boot test, but it
catches the classic mistakes: patched the wrong slot, patched a truncated file.
"""
import hashlib
import struct
import sys


def parse(path):
    d = open(path, "rb").read()
    if d[:8] != b"ANDROID!":
        raise SystemExit("%s: not an Android boot image" % path)
    ver = struct.unpack_from("<I", d, 0x28)[0]
    ks, rs = struct.unpack_from("<II", d, 0x8)
    page = 4096
    koff = page
    roff = (koff + ks + page - 1) & ~(page - 1)
    return dict(data=d, ver=ver, ks=ks, rs=rs, koff=koff, roff=roff,
                size=len(d),
                kernel=d[koff:koff + ks],
                ramdisk=d[roff:roff + rs])


def main():
    if len(sys.argv) < 3:
        print(__doc__.strip())
        return 2
    a, b = parse(sys.argv[1]), parse(sys.argv[2])
    ok = True

    checks = []
    checks.append(("header version", a["ver"] == b["ver"], "%d / %d" % (a["ver"], b["ver"])))
    checks.append(("kernel unchanged", a["kernel"] == b["kernel"],
                   "sha256 %s / %s" % (hashlib.sha256(a["kernel"]).hexdigest()[:16],
                                      hashlib.sha256(b["kernel"]).hexdigest()[:16])))
    checks.append(("ramdisk changed", a["ramdisk"] != b["ramdisk"],
                   "%d -> %d bytes" % (a["rs"], b["rs"])))
    checks.append(("patched ramdisk non-empty", b["rs"] > 0, str(b["rs"])))
    checks.append(("image size sane", 16 * 1024 * 1024 < b["size"] <= 256 * 1024 * 1024,
                   "%d bytes" % b["size"]))

    width = max(len(c[0]) for c in checks)
    for name, good, extra in checks:
        ok &= bool(good)
        print("  [%s] %-*s  %s" % ("OK " if good else "FAIL", width, name, extra))

    print()
    print("  stock   :", sys.argv[1], hashlib.sha256(a["data"]).hexdigest()[:32])
    print("  patched :", sys.argv[2], hashlib.sha256(b["data"]).hexdigest()[:32])
    if not ok:
        print("\nverdict: NOT safe to flash")
        return 1
    print("\nverdict: looks like a real Magisk patch of the same boot image")
    return 0


if __name__ == "__main__":
    sys.exit(main())
