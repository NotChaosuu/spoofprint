<#
.SYNOPSIS
  Capture real browser TLS + HTTP/2 fingerprints against the spoofprint collector.

.DESCRIPTION
  Builds the collector, then for each installed browser: starts a private
  collector instance writing to testdata/captures/<browser>/, launches that
  browser headless (isolated temp profile) pointed at the collector, waits for
  the ClientHello + first request to be captured, then tears everything down.

  Chromium browsers (Chrome/Edge/Brave) get a full TLS + HTTP/2 capture because
  --ignore-certificate-errors lets the handshake complete. Firefox distrusts the
  self-signed cert, so it yields a TLS-only capture (still enough to verify its
  JA4 prefix, GREASE, MLKEM and ALPS state).

  SAFETY: every browser runs with its own --user-data-dir / -profile temp dir, so
  it is a separate process tree from any browser you already have open. Teardown
  only kills the exact PID tree this script launched plus processes whose command
  line references this script's temp profile — it never kills browsers by name.

.PARAMETER Port
  Localhost port for the collector (default 8443).

.PARAMETER WaitSeconds
  How long to let each browser talk to the collector before teardown (default 6).
#>
param(
  [int]$Port = 8443,
  [int]$WaitSeconds = 6
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$exe  = Join-Path $repo "spoofprint-collector.exe"

Write-Host "building collector..."
Push-Location $repo
try {
  & go build -o $exe ./cmd/collector
  if ($LASTEXITCODE -ne 0) { throw "go build failed" }
} finally {
  Pop-Location
}

$browsers = [ordered]@{
  chrome  = "C:\Program Files\Google\Chrome\Application\chrome.exe"
  edge    = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
  brave   = "C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
  firefox = "C:\Program Files\Mozilla Firefox\firefox.exe"
}

$capRoot = Join-Path $repo "testdata\captures"
# localhost (not an IP literal) so browsers send SNI — that yields the t13d... JA4
# a real deployment behind a hostname sees, matching the profile prefixes.
$url = "https://localhost:$Port/"

foreach ($name in $browsers.Keys) {
  $bexe = $browsers[$name]
  if (-not (Test-Path $bexe)) { Write-Host "$name : not installed, skipping"; continue }

  $dump = Join-Path $capRoot $name
  New-Item -ItemType Directory -Force -Path $dump | Out-Null
  Get-ChildItem $dump -Filter *.json -ErrorAction SilentlyContinue | Remove-Item -Force
  $log = Join-Path $dump "collector.log"

  # NOTE: paths here contain spaces, and Start-Process array-joins ArgumentList
  # without quoting — so build a single command-line string and quote every path.
  $colArgs = "-addr :$Port -dump `"$dump`""
  $col = Start-Process -FilePath $exe -ArgumentList $colArgs `
           -PassThru -WindowStyle Hidden -RedirectStandardError $log
  Start-Sleep -Milliseconds 800

  $tmpProfile = Join-Path $env:TEMP "sp-cap-$name"
  Remove-Item -Recurse -Force $tmpProfile -ErrorAction SilentlyContinue
  if ($name -eq "firefox") {
    $bargs = "-headless -no-remote -new-instance -profile `"$tmpProfile`" `"$url`""
  } else {
    $bargs = "--headless=new --disable-gpu --ignore-certificate-errors " +
             "--no-first-run --no-default-browser-check " +
             "--user-data-dir=`"$tmpProfile`" --dump-dom `"$url`""
  }

  $b = Start-Process -FilePath $bexe -ArgumentList $bargs -PassThru -WindowStyle Hidden
  if (-not $b.WaitForExit($WaitSeconds * 1000)) {
    & taskkill /PID $b.Id /T /F *> $null
  }

  # Targeted cleanup: kill only processes launched with THIS script's temp
  # profile (handles Firefox's launcher fork without touching the user's own).
  $leaf = Split-Path $bexe -Leaf
  Get-CimInstance Win32_Process -Filter "Name='$leaf'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like "*sp-cap-$name*" } |
    ForEach-Object { & taskkill /PID $_.ProcessId /T /F *> $null }

  Start-Sleep -Milliseconds 400
  & taskkill /PID $col.Id /T /F *> $null
  Start-Sleep -Milliseconds 300

  $n = @(Get-ChildItem $dump -Filter *.json -ErrorAction SilentlyContinue).Count
  $ver = (Get-Item $bexe).VersionInfo.ProductVersion
  Write-Host "$name $ver -> $n capture(s) in testdata\captures\$name"
  Remove-Item -Recurse -Force $tmpProfile -ErrorAction SilentlyContinue
}

Write-Host ""
Write-Host "done. captures under $capRoot"
