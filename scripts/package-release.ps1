# Package dist binaries into per-platform archives for a GitHub release.
# Usage: scripts/package-release.ps1
# Requires: dist/ already populated by build.sh
param(
  [string]$Version = (Get-Content "$PSScriptRoot\..\VERSION" -Raw).Trim()
)
$ErrorActionPreference = "Stop"
$root = Resolve-Path "$PSScriptRoot\.."
$dist = Join-Path $root "dist"
$out  = Join-Path $root "release-assets"
if (Test-Path $out) { Remove-Item -Recurse -Force $out }
New-Item -ItemType Directory -Path $out | Out-Null

$binaries = Get-ChildItem $dist -File | Where-Object { $_.Name -match '^(aritun|aritund)-' }
if (-not $binaries) { throw "no binaries in dist/" }

foreach ($b in $binaries) {
  # Map dist binary name → release-asset name so the GitHub release page is
  # unambiguous: aritun-client-… = client, aritun-server-… = server.
  $assetBase = if ($b.BaseName -like "aritund-*") {
    "aritun-server-" + $b.BaseName.Substring("aritund-".Length)
  } elseif ($b.BaseName -like "aritun-*") {
    "aritun-client-" + $b.BaseName.Substring("aritun-".Length)
  } else {
    $b.BaseName
  }

  if ($b.Name -like "*.exe") {
    # Windows: zip
    $zipName = "$assetBase.zip"
    Compress-Archive -Path $b.FullName -DestinationPath (Join-Path $out $zipName) -Force
    Write-Host "  + $zipName"
  } else {
    # Unix: tar.gz
    $tarName = "$assetBase.tar.gz"
    $tmp = Join-Path $out $b.Name
    Copy-Item $b.FullName $tmp -Force
    tar -czf (Join-Path $out $tarName) -C $out $b.Name
    Remove-Item $tmp -Force
    Write-Host "  + $tarName"
  }
}

Write-Host ""
Write-Host "release assets ready in release-assets/ for v$Version"
Get-ChildItem $out | ForEach-Object { "  {0}  {1:N0} bytes" -f $_.Name, $_.Length }
