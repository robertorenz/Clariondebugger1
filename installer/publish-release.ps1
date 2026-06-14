<#
  One-shot release: build the artifacts and cut the GitHub release.
    1. builds the self-contained installer + portable zip (build-release.ps1)
    2. pushes the current commit so the tag points at a published commit
    3. creates (or updates, with --clobber) the GitHub release vX.Y.Z and uploads both assets

  Usage:
    powershell installer\publish-release.ps1 -Version 1.1.0
    powershell installer\publish-release.ps1 -Version 1.1.0 -NotesFile notes.md
#>
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$Notes,
    [string]$NotesFile
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent $here
$tag  = "v$Version"

# --- preflight: gh must be authenticated ---
gh auth status 1>$null 2>$null
if ($LASTEXITCODE -ne 0) { throw "gh CLI is not authenticated. Run: gh auth login" }

# --- 1. build artifacts ---
& (Join-Path $here "build-release.ps1") -Version $Version

$output = Join-Path $here "output"
$setup  = Join-Path $output "ClarionDebuggerSetup-$Version.exe"
$zip    = Join-Path $output "ClarionDebugger-$Version-portable-win-x86.zip"
if (-not (Test-Path $setup)) { throw "installer not found: $setup" }
if (-not (Test-Path $zip))   { throw "portable zip not found: $zip" }

# --- 2. release notes ---
if     ($NotesFile -and (Test-Path $NotesFile)) { $noteText = Get-Content $NotesFile -Raw }
elseif ($Notes)                                 { $noteText = $Notes }
else {
    $noteText = @"
Clarion Debugger $Version

Download:
- ClarionDebuggerSetup-$Version.exe - installer (per-user, no admin)
- ClarionDebugger-$Version-portable-win-x86.zip - portable single .exe (unzip & run)

Self-contained (.NET 8 runtime bundled - nothing to install). 32-bit, runs on 64-bit Windows.
See the README for the full feature list.
"@
}
$notesPath = Join-Path $output "release-notes-$Version.txt"
Set-Content -Path $notesPath -Value $noteText -Encoding UTF8

# --- 3. push HEAD so the tag is on a published commit ---
Write-Host "==> pushing current commit..."
git -C $root push 2>&1 | Out-Null

# --- 4. create or update the release ---
gh release view $tag 1>$null 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "==> release $tag exists - uploading assets (clobber)..."
    gh release upload $tag $setup $zip --clobber
    gh release edit $tag --notes-file $notesPath | Out-Null
}
else {
    Write-Host "==> creating release $tag..."
    gh release create $tag $setup $zip --title "Clarion Debugger $Version" --notes-file $notesPath
}

Write-Host "`n==> done:"
gh release view $tag --json url --jq .url
