#!/system/bin/sh
# Report whether Magisk mounts are visible inside the target app's mount namespace.
PKG="${1:-com.idamob.tinkoff.android}"
p=$(pidof "$PKG")
if [ -z "$p" ]; then
    echo "process for $PKG not running"
    exit 1
fi
p=${p%% *}
echo "pkg      : $PKG"
echo "pid      : $p"
n=$(grep -ci magisk /proc/$p/mounts 2>/dev/null)
echo "app ns   : ${n:-0} magisk mounts"
grep -i magisk /proc/$p/mounts 2>/dev/null | head -5
echo "root ns  : $(grep -ci magisk /proc/self/mounts) magisk mounts"
echo "--- magisk dirs visible to app ---"
ls -d /proc/$p/root/debug_ramdisk 2>/dev/null || echo "no /debug_ramdisk in app view"
ls /proc/$p/root/system/bin/su 2>/dev/null || echo "no su in app view"
