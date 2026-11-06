"""Compare a partition read-back with the image we wrote to it.

    python tools/verify_tos_write.py patch/tos-noavb-bsp-bypassed_b.bin run/trustos

The image is normally shorter than the partition, so only the prefix is compared;
the tail is reported so a stale/zero tail is not mistaken for corruption.
"""
import hashlib
import sys


def main():
    if len(sys.argv) < 3:
        print(__doc__.strip())
        return 2
    want = open(sys.argv[1], "rb").read()
    got = open(sys.argv[2], "rb").read()

    n = min(len(want), len(got))
    if got[:n] != want[:n]:
        first = next(i for i in range(n) if got[i] != want[i])
        print("MISMATCH at 0x%x: wrote %02x, read %02x"
              % (first, want[first], got[first]))
        return 1

    print("OK: first %d bytes identical (0x%x)" % (n, n))
    print("  wrote sha256:", hashlib.sha256(want).hexdigest())
    print("  read  sha256:", hashlib.sha256(got[:n]).hexdigest())
    if len(got) > n:
        tail = got[n:]
        print("  tail: %d bytes (0x%x), nonzero %d"
              % (len(tail), n, sum(1 for b in tail if b)))
        print("  -> tail is untouched partition data, expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
