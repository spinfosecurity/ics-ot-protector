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
    pwsh .\scripts\ics-ot-protector.ps1 -Scan -ScanSector energy-grid -Subnets 192.168.10.0/24 -CveOnly

.EXAMPLE
    pwsh .\scripts\ics-ot-protector.ps1 -Scan -ScanSector water -Subnets 10.0.0.0/17 -Force
#>
[CmdletBinding(DefaultParameterSetName = 'Sector')]
param(
    [Parameter(ParameterSetName = 'Sector', Mandatory, HelpMessage = 'Sector scanner to run: water, energy-grid, bas, or rail')]
    [ValidateSet('water', 'energy-grid', 'bas', 'rail')]
    [string]$Sector,

    [Parameter(ParameterSetName = 'Scan', Mandatory)]
    [switch]$Scan,

    [Parameter(ParameterSetName = 'Scan', Mandatory)]
    [ValidateSet('water', 'energy-grid', 'bas', 'rail')]
    [string]$ScanSector,

    [Parameter(ParameterSetName = 'Scan', Mandatory)]
    [string[]]$Subnets,

    [Parameter(ParameterSetName = 'Scan')]
    [ValidateRange(1, 512)]
    [int]$Threads = 64,

    [Parameter(ParameterSetName = 'Scan')]
    [ValidateRange(100, 10000)]
    [int]$TimeoutMs = 1500,

    [Parameter(ParameterSetName = 'Scan')]
    [string]$OutputDir = './reports',

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$CveOnly,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$EotHotOnly,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$Force,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$NoCsv,

    [Parameter(ParameterSetName = 'Scan')]
    [string]$Config,

    [Parameter(ParameterSetName = 'Scan')]
    [switch]$Quiet,

    [Parameter(ParameterSetName = 'Sector', ValueFromRemainingArguments = $true)]
    [object[]]$RemainingArgs
)

$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot

if ($Scan) {
    $runner = Join-Path $Root 'scanners' '_shared' 'Run-SectorScan.ps1'
    if (-not (Test-Path -LiteralPath $runner)) {
        throw "Scan runner not found: $runner"
    }
    & $runner -Sector $ScanSector -Subnets $Subnets -Threads $Threads -TimeoutMs $TimeoutMs `
        -OutputDir $OutputDir -CveOnly:$CveOnly -EotHotOnly:$EotHotOnly -Force:$Force -NoCsv:$NoCsv `
        -Config $Config -Quiet:$Quiet
    return
}

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
