# Backward-compatible launcher — canonical path: scanners/water/powershell/WUP-WUP.ps1
$Canonical = Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) 'scanners' 'water' 'powershell' 'WUP-WUP.ps1'
if (-not (Test-Path $Canonical)) { throw "Canonical scanner not found: $Canonical" }
. $Canonical
