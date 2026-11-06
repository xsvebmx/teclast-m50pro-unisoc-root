# Technical notes: root on the Teclast M50 Pro (T616 / UMS9230)

Companion to `README.en.md`: why it works this way, which addresses and formats are
involved. All commands were run on the device.

---

## 1. Device

| | |
|---|---|
| Model | Teclast M50 Pro, revision M4P1, EEA region |
| Firmware | V1.02_20231114, Android 13, security patch 2023-09-05 |
| SoC | Unisoc T616, platform UMS9230 (`ro.boot.hardware=ums9230_1h10`) |
| Storage | eMMC, A/B + dynamic partitions, active slot **b** |
| Kernel | 5.4.210, arm64-v8a |
| Bootloader | locked (`ro.boot.flash.locked=1`, `verifiedbootstate=green`) |

---

## 2. Why not through an unlock

`fastboot flashing unlock` is not implemented here (`unknown cmd`), and
`fastboot oem unlock` answers `Unlock bootloader fail.` — LK requires the identifier
token to be signed with the vendor's private key.

The unlock blob LK writes into `miscdata` at `0x2000` is encrypted with the HUK in
the secure world. Neither Android nor the normal bootloader path can reach it, and
the BSL commands `e_bl` (`0x71`) and `e_efuse_read` (`0x78`) are not implemented in
this LK build — they answer `0xFE unsupported`.

So unlocking is closed, and root is installed around it via a BootROM bug.

---

## 3. [CVE-2022-38694](https://nvd.nist.gov/vuln/detail/CVE-2022-38694): code execution in the BootROM

The mask-ROM BootROM runs unsigned code if a ROP payload is placed before loading
FDL. Addresses for ums9230:

| what | address |
|---|---|
| payload (`custom_exec_no_verify_65015f08.bin`) | `0x65015f08` |
| FDL1 | `0x65000800` |
| FDL2 | `0x9efffe00` |

ums312/ums512 use `0x5500`; with that address the BootROM answers
`0x8A DOWN_SIZE_ERROR`.

FDL1 must be patched — its signature check is removed by `gen_fdl1_dl.py` (a port of
`gen_fdl1-dl.c` from TomKing062's repository). FDL2 is LK itself (the same image as
`uboot`); once it runs, `r`/`w`/`e` are available for partitions.

After that session any partition can be read and written, which replaces `fastboot`.

---

## 4. [CVE-2022-38691](https://nvd.nist.gov/vuln/detail/CVE-2022-38691): patching `trustos`

TOS contains a function that prints `### enter avb_slot_verify. ###` and returns the
verification verdict. On `trustos_b`:

| | |
|---|---|
| marker string | `0xa9068` |
| xref (adrp/add) | `0x727b8` |
| function | `0x72734 – 0x72de0` |
| patch site | `0x72890`, `mov w0, w20` → `mov w0, #0` (`0x52800000`) |
| single `ret` | `0x728ac` |

There is exactly one `ret`, and every branch funnels through that `mov`, so the patch
masks the verdict on all paths while the body still fills the partition descriptors.

Modifying the image breaks its signature, so the result is repackaged:

1. DHTB header taken from `sml`;
2. the patched TOS payload;
3. the untouched `sml` payload;
4. `SIMGHDR` offsets shifted (`payload_offset` `0x200` → `0x4cd200`, `cert_offset`
   adjusted).

The verifier hashes the SML region, whose sha256 still matches the signed
`mPayloadHash` (`8c876a29…`), so the signature verifies while the patched TOS runs.

Result: 5 156 744 bytes (`0x4ea8f0`) versus stock `0x4cd000` — 128 KB larger, still
inside the 6 MiB partition.

Build: `tools/make_tos_noavb.py` (runs `spd_dump -t dis_avb_ex` and checks the output).

---

## 5. Patching `boot` and Magisk

`boot_b` is a plain `ANDROID!` v4 image: 38.3 MB kernel, 1.47 MB LZ4-legacy ramdisk,
`AVB0`-vbmeta right after the image, `AVBf` footer at the end of the partition.
`init_boot` is empty (zeros), so `boot` is patched, not `init_boot`.

After Magisk: kernel untouched (`sha256 51abed55…`), ramdisk 1 471 131 → 1 165 874
bytes (xz), with `init` = magiskinit, `overlay.d/sbin/`, `.backup/.magisk`,
`PREINITDEVICE=cache`.

Check: `tools/check_magisk_patch.py` (kernel identical, ramdisk changed, sane size).

---

## 6. Write order and verification

Every write is followed by a read-back and a byte comparison — a wrong byte in the
boot chain means the tablet does not start.

Order that worked:

1. `trustos` → reboot → Android boots, so SPL/SML accepted the image;
2. `boot` → reboot → `su -c id` → `uid=0`.

Flags stay stock after root: `flash.locked=1`, `verifiedbootstate=green`,
`vbmeta.device_state=locked`, `veritymode=enforcing`. Only the verdict is masked.

---

## 7. Rollback

```
w trustos trustos_b
w boot boot_b
```

Files come from the dump or from the factory `.pac`. Full recovery is flashing the
PAC with ResearchDownload in BootROM mode, which works regardless of bootloader
state (verified on a tablet that would not boot at all).

---

## 8. After root (short)

- **Magisk 31.1** — modules and `su`; `su` for `adb shell` is granted in the app.
- **Zygisk** is enabled in the DB: `magisk --sqlite "REPLACE INTO settings
  (key,value) VALUES('zygisk',1)"`, then reboot. Verify with `libzygisk.so` present
  in `/proc/<zygote>/maps`.
- **DenyList** — `magisk --denylist add <pkg>`; verify with
  `tools/check_denylist.sh <pkg>`.
- **Play Integrity** — PlayIntegrityFork v19; GMS and Play Store must stay out of
  DenyList.

---

## 9. Limits

- `trustos` and `boot` are the boot chain: a mistake means no boot; recover from the
  dump or the PAC.
- The TOS image is 128 KB larger than stock. If a given SPL copies `mImgSize` into a
  fixed region it can fail; on this device it works.
- AVB is bypassed, but dm-verity for `system`/`vendor` still runs: modified system
  partitions will not verify without editing fstab in the ramdisk.
- 5G is impossible on T616: LTE-only modem, no NR RF front end.
