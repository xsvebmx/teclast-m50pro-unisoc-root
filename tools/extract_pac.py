"""Extract files from a Unisoc factory .pac (2.x), optionally straight out of
the .rar download without unpacking it first.

    python extract_pac.py --pac Firmware.pac --out images --names FDL FDL2
    python extract_pac.py --rar "M50 Pro(M4P1)_..._SZ.rar" --out images --names FDL FDL2
    python extract_pac.py --pac Firmware.pac --list

PAC layout as found on this firmware: UTF-16 header "BP_R1.0.0", a table at
0x850 with 0xA14-byte entries (name, file name), and per entry:
    +0x600  file size
    +0x60C  absolute offset of the file inside the pac

Files are stored in ascending offset order, so the streaming (.rar) path reads
them in one pass without unpacking the 3.7 GB pac first.
"""
import argparse
import hashlib
import os
import re
import struct
import subprocess
import sys

BASE = 0x850
STRIDE = 0xA14
SEVEN_DEFAULT = r"C:\Program Files\7-Zip\7z.exe"


class Reader:
    """Buffered reader over a pipe: keeps everything read so far."""

    def __init__(self, stream, chunk=0x10000):
        self.stream = stream
        self.chunk = chunk
        self.buf = b""

    def ensure(self, n):
        while len(self.buf) < n:
            data = self.stream.read(max(self.chunk, n - len(self.buf)))
            if not data:
                return False
            self.buf += data
        return True

    def read_at(self, offset, size):
        end = offset + size
        if size > 256 * 1024 * 1024:
            sys.exit("refusing to buffer %d bytes from a pipe; use --pac" % size)
        if not self.ensure(end if offset >= len(self.buf) else offset + 1):
            sys.exit("unexpected end of stream")
        while len(self.buf) < end:
            data = self.stream.read(max(self.chunk, end - len(self.buf)))
            if not data:
                sys.exit("unexpected end of stream")
            self.buf += data
        return self.buf[offset:end]


def wstr(buf, off, maxlen=0x100):
    raw = buf[off:off + maxlen]
    out = []
    for i in range(0, len(raw) - 1, 2):
        c = raw[i] | (raw[i + 1] << 8)
        if c == 0:
            break
        if 32 <= c < 127:
            out.append(chr(c))
        else:
            return None
    return "".join(out)


def parse_table(reader):
    if not reader.ensure(0x40) or reader.buf[:8] != b"B\x00P\x00_\x00R\x00":
        sys.exit("not a Unisoc PAC file (magic mismatch)")
    rows = []
    off = BASE
    while reader.ensure(off + STRIDE):
        name = wstr(reader.buf, off)
        fname = wstr(reader.buf, off + 0x200)
        if not name or not re.fullmatch(r"[A-Za-z0-9_]+", name):
            break
        size = struct.unpack_from("<I", reader.buf, off + 0x600)[0]
        foff = struct.unpack_from("<I", reader.buf, off + 0x60C)[0]
        rows.append(dict(name=name.upper(), file=fname or "", size=size, offset=foff))
        off += STRIDE
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--pac", help="path to Firmware.pac")
    src.add_argument("--rar", help="path to the factory .rar (streamed through 7-Zip)")
    ap.add_argument("--member", default=r"Firmware\Firmware.pac", help="path inside the rar")
    ap.add_argument("--seven", help="path to 7z.exe")
    ap.add_argument("--out", default="images")
    ap.add_argument("--names", nargs="*", default=["FDL", "FDL2"],
                    help="partition names, e.g. FDL FDL2 TRUSTOS SML BOOT")
    ap.add_argument("--list", action="store_true", help="only print the table")
    args = ap.parse_args()

    if args.pac:
        stream = open(args.pac, "rb")
        proc = None
        seekable = True
    else:
        seven = args.seven or SEVEN_DEFAULT
        proc = subprocess.Popen([seven, "x", "-so", args.rar, args.member],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        stream = proc.stdout
        seekable = False

    try:
        reader = Reader(stream)
        rows = parse_table(reader)
        if args.list:
            for r in rows:
                print("%-24s %-32s %10d  0x%x" % (r["name"], r["file"], r["size"], r["offset"]))
            return 0

        wanted_names = {n.upper() for n in args.names}
        wanted = [r for r in rows if r["name"] in wanted_names]
        missing = wanted_names - {r["name"] for r in rows}
        if missing:
            print("not found in pac: " + ", ".join(sorted(missing)), file=sys.stderr)
        if not wanted:
            return 1

        os.makedirs(args.out, exist_ok=True)
        wanted.sort(key=lambda r: r["offset"])

        for r in wanted:
            if seekable:
                stream.seek(r["offset"])
                data = stream.read(r["size"])
            else:
                data = reader.read_at(r["offset"], r["size"])
            dst = os.path.join(args.out, r["file"] or (r["name"].lower() + ".bin"))
            with open(dst, "wb") as f:
                f.write(data)
            print("%-12s -> %-30s %9d bytes  sha256 %s" %
                  (r["name"], dst, len(data), hashlib.sha256(data).hexdigest()[:16]))
        return 0
    finally:
        if proc:
            try:
                stream.close()
            except Exception:
                pass
            proc.kill()
            proc.wait()
        else:
            stream.close()


if __name__ == "__main__":
    sys.exit(main())
