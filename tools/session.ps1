# One CVE session against the tablet: read partitions, or write trustos / boot.
#
#   .\session.ps1 -Action read
#   .\session.ps1 -Action write-tos
#   .\session.ps1 -Action write-boot -Boot .\out\magisk_patched.img
#
# The tablet must be in download mode first: powered off, hold Vol-, plug USB,
# keep holding ~10 s. If the port does not appear, unplug, hold Power 30 s, retry.
#
# Every write is followed by a read-back and a byte comparison. Do not skip it.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('read', 'write-tos', 'write-boot')]
    [string]$Action,

    [string]$OutDir = '.\out',
    [string]$Images = '..\images',
    [string]$SpdDump = 'spd_dump.exe',
    [string]$Boot,
    [string]$Python = 'python',
    [int]$Wait = 180
)

$ErrorActionPreference = 'Stop'
$OutDir = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $OutDir))
$Images = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $Images))

# spd_dump: as given, then next to this script, then on PATH
if (-not [IO.Path]::IsPathRooted($SpdDump)) {
    $candidates = @(
        (Join-Path $PSScriptRoot $SpdDump),
        (Join-Path (Split-Path $PSScriptRoot) $SpdDump),
        $SpdDump
    )
    $found = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
} else {
    $found = $SpdDump
}
if (-not $found) { throw "spd_dump.exe not found; put it in $PSScriptRoot or pass -SpdDump <path>" }
$SpdDump = [IO.Path]::GetFullPath($found)
if (-not (Test-Path (Join-Path $Images 'fdl1-dl.bin'))) { throw "images not found in $Images" }
New-Item -ItemType Directory -Force $OutDir | Out-Null

$common = @(
    '--wait', "$Wait", '--verbose', '1',
    'exec_addr', '0x65015f08',
    'fdl', (Join-Path $Images 'fdl1-dl.bin'), '0x65000800',
    'fdl', (Join-Path $Images 'fdl2.bin'), '0x9efffe00',
    'exec', 'path', $OutDir
)

function Invoke-Session([string[]]$Commands) {
    Push-Location $OutDir
    try {
        & $SpdDump @common @Commands
    } finally {
        Pop-Location
    }
}

switch ($Action) {
    'read' {
        Write-Host '== reading sml, trustos and boot =='
        Invoke-Session @('r', 'sml', 'r', 'trustos', 'r', 'boot', 'reset')

        # rename to the names make_tos_noavb.py expects (--dump <OutDir>)
        $map = @{ 'sml' = 'sml_b'; 'trustos' = 'trustos_b'; 'boot' = 'boot_b' }
        foreach ($k in $map.Keys) {
            $src = Join-Path $OutDir $k
            if (Test-Path $src) { Move-Item $src (Join-Path $OutDir $map[$k]) -Force }
        }
        Write-Host ''
        Write-Host "Read-back is in $OutDir (sml_b, trustos_b, boot_b)."
        Write-Host 'Check the stock hashes in hashes.txt; a mismatch means different firmware,'
        Write-Host 'in which case rebuild the image from these files instead of using someone else''s.'
    }

    'write-tos' {
        $img = Join-Path $Images 'tos-noavb-bsp-bypassed_b.bin'
        $copy = Join-Path $OutDir 'tos.bin'
        Copy-Item $img $copy -Force
        Write-Host "== writing trustos ($([Math]::Round((Get-Item $copy).Length / 1MB, 2)) MB) =="
        Invoke-Session @('w', 'trustos', 'tos.bin', 'r', 'trustos', 'reset')

        Write-Host ''
        Write-Host '== verifying read-back =='
        & $Python (Join-Path $PSScriptRoot 'verify_tos_write.py') $img (Join-Path $OutDir 'trustos')
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'MISMATCH: do not reboot. Re-run the write, or restore the stock image.'
            exit 1
        }
        Write-Host 'OK. The tablet has been reset; if Android boots, the image was accepted.'
    }

    'write-boot' {
        if (-not $Boot) { throw 'pass -Boot <path to magisk_patched.img>' }
        $Boot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $Boot))
        if (-not (Test-Path $Boot)) { throw "boot image not found: $Boot" }
        $copy = Join-Path $OutDir 'boot.img'
        Copy-Item $Boot $copy -Force
        Write-Host "== writing boot ($([Math]::Round((Get-Item $copy).Length / 1MB, 2)) MB) =="
        Invoke-Session @('w', 'boot', 'boot.img', 'r', 'boot', 'reset')

        Write-Host ''
        Write-Host '== verifying read-back =='
        & $Python (Join-Path $PSScriptRoot 'verify_tos_write.py') $Boot (Join-Path $OutDir 'boot')
        if ($LASTEXITCODE -ne 0) {
            Write-Host 'MISMATCH: restore the stock boot partition before rebooting.'
            exit 1
        }
        Write-Host 'OK. Check root after boot: adb shell su -c id'
    }
}
