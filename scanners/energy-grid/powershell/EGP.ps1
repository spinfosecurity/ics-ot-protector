<#
.SYNOPSIS
    Energy Grid Protector (EGP) - OT/SCADA Cybersecurity Scanner for Power Grid Networks

.DESCRIPTION
    Scans power grid, transmission, and substation OT/SCADA subnets for:
      - Named vendor CVEs (Hitachi Energy, ABB, B&R)
      - Hitachi Energy RTU500 series vulnerability exposure
      - Remote-access protocol exposure (RDP, VNC, SSH, Telnet, FTP, HTTP/HTTPS)
      - ICS protocol exposure (DNP3, Modbus, IEC 60870-5-104, IEC 61850, EtherNet/IP)
    Produces severity-tagged (CRITICAL/HIGH/MEDIUM) console output and a timestamped
    report saved to the reports/ directory.

    Reference: CISA Alert AA26-097A | FBI PSA 2026-08-01
    Use only on networks you own or have explicit written authorization to scan.

.PARAMETER Subnet
    Target /24 CIDR subnet (e.g., 192.168.10.0/24). Must be a valid /24 notation.

.PARAMETER TimeoutMs
    TCP connection timeout in milliseconds. Default: 500. Range: 100-5000.

.PARAMETER CveOnly
    Switch. When specified, skips remote-access and ICS protocol checks and
    performs only named CVE port checks (fast-scan mode).

.PARAMETER OutputDir
    Directory for saving the report. Default: .\reports

.EXAMPLE
    .\EGP.ps1 -Subnet 10.10.20.0/24
    Full scan of 10.10.20.0/24 with default 500ms timeout.

.EXAMPLE
    .\EGP.ps1 -Subnet 192.168.100.0/24 -TimeoutMs 1000 -CveOnly
    Fast CVE-only scan of 192.168.100.0/24 with 1000ms timeout.

.EXAMPLE
    .\EGP.ps1 -Subnet 172.16.5.0/24 -OutputDir C:\Reports\EGP
    Full scan saving report to C:\Reports\EGP

.NOTES
    Author  : spinfosecurity
    Version : 1.0.0
    License : MIT
    Project : https://github.com/spinfosecurity/ics-ot-protector/tree/main/scanners/energy-grid
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = 'Target /24 CIDR subnet, e.g. 192.168.1.0/24')]
    [ValidatePattern('^(\d{1,3}\.){3}\d{1,3}/24$')]
    [string]$Subnet,

    [Parameter(Mandatory = $false)]
    [ValidateRange(100, 5000)]
    [int]$TimeoutMs = 500,

    [Parameter(Mandatory = $false)]
    [switch]$CveOnly,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = '.\reports'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'Import-SectorConfig.ps1')
Initialize-EnergyGridConfig -Config (Import-SectorConfig -Sector 'energy-grid')

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
function Show-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Energy Grid Protector (EGP) v1.0.0" -ForegroundColor Cyan
    Write-Host "  OT/SCADA Cybersecurity Scanner - Power Grid Edition" -ForegroundColor Cyan
    Write-Host "  github.com/spinfosecurity/ics-ot-protector" -ForegroundColor Cyan
    Write-Host "  Ref: CISA AA26-097A | FBI PSA 2026-08-01" -ForegroundColor DarkCyan
    Write-Host "  USE ONLY ON NETWORKS YOU ARE AUTHORIZED TO SCAN" -ForegroundColor Yellow
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host ""
}

# ---------------------------------------------------------------------------
# Severity color helper
# ---------------------------------------------------------------------------
function Get-SeverityColor([string]$Severity) {
    switch ($Severity) {
        'CRITICAL' { return 'Red' }
        'HIGH'     { return 'DarkRed' }
        'MEDIUM'   { return 'Yellow' }
        default    { return 'Gray' }
    }
}

# ---------------------------------------------------------------------------
# TCP port test
# ---------------------------------------------------------------------------
function Test-TcpPort {
    [OutputType([bool])]
    param (
        [string]$IpAddress,
        [int]$Port,
        [int]$TimeoutMilliseconds
    )
    try {
        $client = [System.Net.Sockets.TcpClient]::new()
        $task   = $client.ConnectAsync($IpAddress, $Port)
        if ($task.Wait($TimeoutMilliseconds)) {
            $client.Close()
            return $true
        }
        $client.Close()
        return $false
    } catch {
        return $false
    }
}

# ---------------------------------------------------------------------------
# CVE / port definitions loaded from config/sectors/energy-grid.yaml
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Parse /24 subnet into list of host IPs
# ---------------------------------------------------------------------------
function Get-SubnetHosts([string]$CidrSubnet) {
    $baseIp = $CidrSubnet -replace '/24$', ''
    $octets = $baseIp -split '\.'
    if ($octets.Count -ne 4) {
        throw "Invalid subnet format: $CidrSubnet"
    }
    foreach ($o in $octets) {
        if ([int]$o -lt 0 -or [int]$o -gt 255) {
            throw "Octet out of range in subnet: $CidrSubnet"
        }
    }
    $prefix = "$($octets[0]).$($octets[1]).$($octets[2])"
    return (1..254) | ForEach-Object { "$prefix.$_" }
}

# ---------------------------------------------------------------------------
# Write finding to report and console
# ---------------------------------------------------------------------------
function Write-Finding {
    param (
        [string]$ReportPath,
        [string]$IpAddress,
        [int]$Port,
        [string]$FindingLabel,
        [string]$Severity,
        [string]$Description,
        [string]$Remediation
    )
    $timestamp = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    $line = "[$timestamp] [$Severity] $IpAddress`:$Port - $FindingLabel | $Description | REMEDIATION: $Remediation"
    $color = Get-SeverityColor $Severity

    Write-Host "  [$Severity] " -ForegroundColor $color -NoNewline
    Write-Host "$IpAddress`:$Port" -ForegroundColor White -NoNewline
    Write-Host " - $FindingLabel" -ForegroundColor $color
    Write-Host "    $Description" -ForegroundColor Gray

    Add-Content -Path $ReportPath -Value $line
}

# ---------------------------------------------------------------------------
# MAIN (skipped when $EGP_TEST_MODE is set before dot-sourcing)
# ---------------------------------------------------------------------------
if ($EGP_TEST_MODE -or $global:EGP_TEST_MODE) { return }

Show-Banner

# Validate and prepare output directory
if (-not (Test-Path $OutputDir)) {
    try {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    } catch {
        Write-Error "Cannot create output directory '$OutputDir': $_"
        exit 1
    }
}

$timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$reportFile  = Join-Path $OutputDir "EGP_Report_${timestamp}.txt"
$modeLabel   = if ($CveOnly) { 'CVE-ONLY (fast-scan)' } else { 'FULL SCAN' }

# Initialize report file
@"
Energy Grid Protector (EGP) v1.0.0
Scan Mode    : $modeLabel
Target Subnet: $Subnet
Timeout      : ${TimeoutMs}ms
Scan Started : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Reference    : CISA Alert AA26-097A | FBI PSA 2026-08-01
Repository   : https://github.com/spinfosecurity/ics-ot-protector
=======================================================================
"@ | Set-Content -Path $reportFile

Write-Host "[*] Mode       : $modeLabel" -ForegroundColor Cyan
Write-Host "[*] Target     : $Subnet" -ForegroundColor Cyan
Write-Host "[*] Timeout    : ${TimeoutMs}ms per port" -ForegroundColor Cyan
Write-Host "[*] Report     : $reportFile" -ForegroundColor Cyan
Write-Host ""

try {
    $hosts = Get-SubnetHosts -CidrSubnet $Subnet
} catch {
    Write-Error "Subnet parsing failed: $_"
    exit 1
}

$totalHosts   = $hosts.Count
$findings     = 0
$hostsScanned = 0

foreach ($ip in $hosts) {
    $hostsScanned++
    $pct = [math]::Round(($hostsScanned / $totalHosts) * 100, 1)
    Write-Progress -Activity "EGP Scanning $Subnet" `
        -Status "[$hostsScanned/$totalHosts] Scanning $ip ($pct%)" `
        -PercentComplete $pct

    # --- CVE Checks ---
    foreach ($cveId in $CveChecks.Keys) {
        $cve = $CveChecks[$cveId]
        foreach ($port in $cve.Ports) {
            if (Test-TcpPort -IpAddress $ip -Port $port -TimeoutMilliseconds $TimeoutMs) {
                Write-Finding -ReportPath $reportFile `
                    -IpAddress $ip -Port $port `
                    -FindingLabel $cveId `
                    -Severity $cve.Severity `
                    -Description $cve.Description `
                    -Remediation $cve.Remediation
                $findings++
            }
        }
    }

    if (-not $CveOnly) {
        # --- Remote Access Checks ---
        foreach ($port in $RemoteAccessPorts.Keys) {
            if (Test-TcpPort -IpAddress $ip -Port $port -TimeoutMilliseconds $TimeoutMs) {
                $ra = $RemoteAccessPorts[$port]
                Write-Finding -ReportPath $reportFile `
                    -IpAddress $ip -Port $port `
                    -FindingLabel "REMOTE-ACCESS:$($ra.Name)" `
                    -Severity $ra.Severity `
                    -Description $ra.Description `
                    -Remediation 'See docs/CISA-Reference.md for hardening guidance'
                $findings++
            }
        }

        # --- ICS Protocol Checks ---
        foreach ($port in $IcsPorts.Keys) {
            if (Test-TcpPort -IpAddress $ip -Port $port -TimeoutMilliseconds $TimeoutMs) {
                $ics = $IcsPorts[$port]
                Write-Finding -ReportPath $reportFile `
                    -IpAddress $ip -Port $port `
                    -FindingLabel "ICS-PROTOCOL:$($ics.Name)" `
                    -Severity $ics.Severity `
                    -Description $ics.Description `
                    -Remediation 'See docs/Threat-Intelligence.md for ICS protocol hardening'
                $findings++
            }
        }
    }
}

Write-Progress -Activity "EGP Scanning $Subnet" -Completed

# Summary
$summary = @"

=======================================================================
SCAN COMPLETE
Hosts Scanned : $hostsScanned
Findings      : $findings
Scan Ended    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Report Saved  : $reportFile

REMEDIATION RESOURCES:
  CISA Alert AA26-097A  : https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a
  FBI PSA 2026-08-01    : https://www.fbi.gov/
  CISA ICS Advisories   : https://www.cisa.gov/news-events/ics-advisories
  Report Vulnerabilities: https://www.cisa.gov/report
=======================================================================
"@

$summary | Add-Content -Path $reportFile

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  SCAN COMPLETE" -ForegroundColor Green
Write-Host "  Hosts Scanned : $hostsScanned" -ForegroundColor White
Write-Host "  Findings      : $findings" -ForegroundColor $(if ($findings -gt 0) { 'Red' } else { 'Green' })
Write-Host "  Report Saved  : $reportFile" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
if ($findings -gt 0) {
    Write-Host "[!] ACTION REQUIRED: Review findings and apply remediations." -ForegroundColor Red
    Write-Host "    See docs/CISA-Reference.md and docs/Threat-Intelligence.md" -ForegroundColor Yellow
}
