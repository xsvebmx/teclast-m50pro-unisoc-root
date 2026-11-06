"""Offline replica of spd_dump's dis_avb() scanner.

Finds the site dis_avb() would patch in a trustos image, prints it and
disassembles the surrounding function. Read-only: touches no device and
writes no files.

    python tools/probe_dis_avb.py dump/trustos_a [--dis]
"""
import os
import struct
import sys

DHTB = 0x200


def find_bytes(mem, pat):
    return mem.find(pat)


def is_prologue(insn):
    if (insn & 0xFFC07FFF) == 0xA9807BFD:   # stp x29, x30, [sp, #-imm]!
        return True
    if (insn & 0xFFC003FF) == 0xD10003FF:   # sub sp, sp, #imm
        return True
    return False


def find_marker_ref(mem, marker_off):
    target = marker_off - DHTB
    page = [0] * 32
    valid = [False] * 32
    for i in range(DHTB, len(mem) - 4, 4):
        insn = struct.unpack_from("<I", mem, i)[0]
        if (insn & 0x9F000000) == 0x90000000:  # ADRP
            rd = insn & 31
            imm = ((insn >> 5) & 0x7FFFF) << 2 | ((insn >> 29) & 3)
            if imm & (1 << 20):
                imm -= 1 << 21
            page[rd] = ((i - DHTB) & ~0xFFF) + (imm << 12)
            valid[rd] = True
        elif (insn & 0xFF800000) == 0x91000000:  # ADD imm, 64-bit
            rn = (insn >> 5) & 31
            imm12 = (insn >> 10) & 0xFFF
            if insn & (1 << 22):
                imm12 <<= 12
            if valid[rn] and page[rn] + imm12 == target:
                return i
    return None


def find_func_start(mem, ref):
    lo = DHTB
    i = ref
    while i >= DHTB + 4:
        if struct.unpack_from("<I", mem, i - 4)[0] == 0xD65F03C0:  # ret
            lo = i
            break
        i -= 4
    for i in range(lo, ref, 4):
        if is_prologue(struct.unpack_from("<I", mem, i)[0]):
            return i
    return lo


def find_func_end(mem, start):
    seen_ret = False
    for i in range(start + 4, len(mem) - 4, 4):
        insn = struct.unpack_from("<I", mem, i)[0]
        if insn == 0xD65F03C0:
            seen_ret = True
        elif seen_ret and is_prologue(insn):
            return i
    return len(mem)


def scan(mem):
    marker = find_bytes(mem, b"### enter avb_slot_verify. ###")
    if marker < 0:
        marker = find_bytes(mem, b"enter avb_slot_verify")
    if marker < 0:
        return None, "marker string not found"
    ref = find_marker_ref(mem, marker)
    if ref is None:
        return None, "marker has no adrp/add xref"
    lo = find_func_start(mem, ref)
    hi = find_func_end(mem, lo)
    patch_pos = 0
    start_pos = 0
    for i in range(lo, min(hi, len(mem) - 32), 4):
        cur = struct.unpack_from("<I", mem, i)[0]
        if cur == 0xD65F03C0 or (cur & 0xFF00FFFF) == 0xA8007BFD:
            start_pos = 0
        elif (cur & 0xFF00FFFF) == 0xA9007BFD:
            start_pos = i
        elif start_pos:
            ldp = 0
            for m in range(0, 20, 4):
                if mem[i + m + 3] == 0xA9:
                    ldp += 1
                else:
                    break
            if ldp != 5:
                continue
            rets = sum(1 for m in (24, 28) if struct.unpack_from("<I", mem, i + m)[0] == 0xD65F03C0)
            if not rets:
                continue
            if struct.unpack_from("<H", mem, i - 4)[0] == 0x3E0 and mem[i - 7] == 0x3:
                c1 = c2 = 0
                for m in range(start_pos, i, 4):
                    hi16 = struct.unpack_from("<I", mem, m)[0] >> 16
                    if hi16 == 0x9400:
                        c1 += 1
                    elif hi16 == 0xB400:
                        c2 += 1
                if c1 and c2 and c1 + c2 > 2:
                    patch_pos = i - 4
    info = dict(marker=marker, ref=ref, func=(lo, hi), patch=patch_pos)
    return info, None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else r"dump/trustos_a"
    mem = open(path, "rb").read()
    info, err = scan(mem)
    if err:
        print("FAIL:", err)
        return 1
    print("image      :", path, hex(len(mem)))
    print("marker str : 0x%x" % info["marker"])
    print("xref instr : 0x%x" % info["ref"])
    print("function   : 0x%x - 0x%x" % info["func"])
    if not info["patch"]:
        print("patch site : NOT FOUND -> dis_avb would skip saving")
        return 2
    p = info["patch"]
    cur = struct.unpack_from("<I", mem, p)[0]
    print("patch site : 0x%x  current=0x%08x  new=0x52800000 (mov w0,#0)" % (p, cur))
    if "--dis" in sys.argv:
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pylibs"))
            from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        except Exception as exc:
            print("capstone unavailable:", exc)
            return 0
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = False
        print("\n--- function head (offset 0x%x) ---" % info["func"][0])
        for ins in md.disasm(mem[info["func"][0]:info["func"][0] + 96], info["func"][0]):
            print("0x%x: %-8s %s" % (ins.address, ins.mnemonic, ins.op_str))
        print("\n--- around patch (0x%x) ---" % (p - 48))
        for ins in md.disasm(mem[p - 48:p + 48], p - 48):
            mark = "  <== patched" if ins.address == p else ""
            print("0x%x: %-8s %s%s" % (ins.address, ins.mnemonic, ins.op_str, mark))
    return 0


if __name__ == "__main__":
    sys.exit(main())
