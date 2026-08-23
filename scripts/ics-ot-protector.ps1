#Requires -Version 5.1
<#
.SYNOPSIS
    Unified launcher for ICS OT Protector sector scanners.

.EXAMPLE
    .\scripts\ics-ot-protector.ps1 -Sector water

.EXAMPLE
    .\scripts\ics-ot-protector.ps1 -Sector energy-grid -Subnet 192.168.10.0/24

.EXAMPLE
    pwsh .\scripts\ics-ot-protector.ps1 -Sector rail -Subnets 10.10.20.0/24

.EXAMPLE
    bash ./scripts/ics-ot-protector.sh scan --sector energy-grid --subnets 192.168.10.0/24
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory, HelpMessage = 'Sector scanner to run: water, energy-grid, bas, or rail')]
    [ValidateSet('water', 'energy-grid', 'bas', 'rail')]
    [string]$Sector,

    [Parameter(ValueFromRemainingArguments = $true)]
    [object[]]$RemainingArgs
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot

$Scanner = switch ($Sector) {
    'water'       { Join-Path $Root 'scanners' 'water' 'powershell' 'WUP-WUP.ps1' }
    'energy-grid' { Join-Path $Root 'scanners' 'energy-grid' 'powershell' 'EGP.ps1' }
    'bas'         { Join-Path $Root 'scanners' 'bas' 'powershell' 'BAS-Guardian.ps1' }
    'rail'        { Join-Path $Root 'scanners' 'rail' 'powershell' 'ROP.ps1' }
}

if (-not (Test-Path -LiteralPath $Scanner)) {
    throw "Scanner not found for sector '$Sector': $Scanner"
}

& $Scanner @RemainingArgs
