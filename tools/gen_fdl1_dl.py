"""Port of TomKing062's gen_fdl1-dl.c: trim a DHTB-signed image to its real
size and NOP out the signature-verification branch, producing fdl1-dl.bin."""
import struct
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else 'm50pro/fdl/fdl1.bin'
DST = sys.argv[2] if len(sys.argv) > 2 else 'm50pro/fdl/fdl1-dl.bin'

mem = bytearray(open(SRC, 'rb').read())
size = len(mem)

if struct.unpack_from('<I', mem, 0)[0] != 0x42544844:
    sys.exit('not a SPRD trusted firmware (DHTB)')

base = struct.unpack_from('<I', mem, 0x30)[0]
if base == 0:
    sys.exit('broken DHTB image')

if base + 0x260 >= size:
    print('no trimming needed, size stays 0x%x' % size)
    open(DST, 'wb').write(mem)
    sys.exit(0)


def u32(off):
    return struct.unpack_from('<I', mem, off)[0]


chosen = None
for f1, f2 in ((0x50, 0x58), (0x30, 0x38), (0x20, 0x28)):
    a, b = u32(base + 0x200 + f1), u32(base + 0x200 + f2)
    if a and b:
        chosen = a + b
        print('size from +0x%x/+0x%x: 0x%x' % (f1, f2, chosen))
        break
if chosen is None:
    chosen = base + 0x200
    print('size fallback: 0x%x' % chosen)

size = chosen
mem = mem[:size]
print('trimmed: 0x%x -> 0x%x' % (len(open(SRC, 'rb').read()), size))

patched = 0
off = 0x200
while off < base + 0x200:
    if u32(off) == 0x34000040:
        if (u32(off - 4) >> 8) == 0x940000 and u32(off + 4) == 0x14000000:
            struct.pack_into('<I', mem, off - 4, 0xD503201F)
            struct.pack_into('<I', mem, off, 0xD503201F)
            struct.pack_into('<I', mem, off + 4, 0xD503201F)
            patched += 1
            off += 4
    off += 4

open(DST, 'wb').write(mem)
print('patched branches:', patched)
print('wrote %s (%d bytes)' % (DST, len(mem)))
