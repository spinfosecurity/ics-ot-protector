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
    Project : https://github.com/spinfosecurity/Energy-Grid-Protector
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

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
function Show-Banner {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  Energy Grid Protector (EGP) v1.0.0" -ForegroundColor Cyan
    Write-Host "  OT/SCADA Cybersecurity Scanner - Power Grid Edition" -ForegroundColor Cyan
    Write-Host "  github.com/spinfosecurity/Energy-Grid-Protector" -ForegroundColor Cyan
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
# CVE definitions
# ---------------------------------------------------------------------------
$CveChecks = [ordered]@{
    'CVE-2026-42945' = @{
        Description = 'Hitachi Energy e-mesh EMS (v4.1.6, v4.4.2, v4.7.0) - Interoperability/standardization layer flaw in substation EMS. Unauthenticated network access may lead to service disruption or unauthorized control.'
        Ports       = @(80, 443, 8080, 8443)
        Severity    = 'CRITICAL'
        Remediation = 'Apply Hitachi Energy patch immediately. Isolate EMS management interfaces behind VPN/firewall. See CISA ICS Advisory and docs/CISA-Reference.md'
    }
    'CVE-2025-1445' = @{
        Description = 'Hitachi Energy / ABB / B&R shared hardware vulnerability - Improper input validation, out-of-bounds write, memory buffer restriction failure. Affects ABB ACS880 drives with IEC 61131-3 license.'
        Ports       = @(102, 2404, 44818, 2222)
        Severity    = 'CRITICAL'
        Remediation = 'Update firmware per vendor advisories. Restrict network access to drives. Apply IEC 62443 network segmentation. See docs/CISA-Reference.md'
    }
    'CVE-2025-13162' = @{
        Description = 'ABB Advant Master Online Builder / 800xA - Uncontrolled search path element enabling arbitrary code execution via unrestricted DLL directory hijacking.'
        Ports       = @(135, 445, 8080)
        Severity    = 'HIGH'
        Remediation = 'Apply ABB Security Advisory patch. Restrict write permissions on DLL search paths. Use application allowlisting. See docs/CISA-Reference.md'
    }
    'RTU500-MULTI-CVE' = @{
        Description = 'Hitachi Energy RTU500 Series - Multiple disclosed vulnerabilities including authentication bypass, denial of service, and improper certificate validation across RTU500 product line.'
        Ports       = @(20000, 2404, 102, 443)
        Severity    = 'HIGH'
        Remediation = 'Upgrade RTU500 firmware to latest patched version. Enforce certificate validation. Restrict DNP3/IEC104 access to known master stations. See docs/Threat-Intelligence.md'
    }
}

# ---------------------------------------------------------------------------
# Remote-access port definitions
# ---------------------------------------------------------------------------
$RemoteAccessPorts = [ordered]@{
    3389  = @{ Name = 'RDP';    Severity = 'HIGH';   Description = 'Remote Desktop Protocol exposed on OT network. CISA AA26-097A and FBI PSA 2026-08-01 document active exploitation. Remove or restrict immediately.' }
    5900  = @{ Name = 'VNC';   Severity = 'CRITICAL'; Description = 'VNC port 5900 exposed. FBI PSA 2026-08-01 warns of active VNC exploitation against ICS environments. Disable or place behind VPN.' }
    5901  = @{ Name = 'VNC-1'; Severity = 'CRITICAL'; Description = 'VNC port 5901 exposed. FBI PSA 2026-08-01 warns of active VNC exploitation against ICS environments. Disable or place behind VPN.' }
    22    = @{ Name = 'SSH';    Severity = 'MEDIUM';  Description = 'SSH port open on OT host. Ensure key-based auth only, disable password auth, restrict to jump host access.' }
    23    = @{ Name = 'Telnet'; Severity = 'CRITICAL'; Description = 'Telnet transmits credentials in cleartext. Immediate removal required on all OT/SCADA assets per CISA guidance.' }
    21    = @{ Name = 'FTP';    Severity = 'HIGH';    Description = 'FTP transmits data and credentials in cleartext. Replace with SFTP or SCP. Active ICS malware campaigns use FTP for lateral movement.' }
    80    = @{ Name = 'HTTP';   Severity = 'MEDIUM';  Description = 'Unencrypted HTTP web interface exposed. Migrate to HTTPS. Restrict web management to operations VLAN only.' }
    443   = @{ Name = 'HTTPS';  Severity = 'MEDIUM';  Description = 'HTTPS web interface exposed. Verify certificate validity, disable legacy TLS versions, restrict to authorized clients.' }
}

# ---------------------------------------------------------------------------
# ICS protocol port definitions
# ---------------------------------------------------------------------------
$IcsPorts = [ordered]@{
    20000 = @{ Name = 'DNP3';          Severity = 'HIGH';   Description = 'DNP3 (IEEE 1815) exposed. Lacks authentication in many implementations. CISA AA26-097A: Iranian actors probing DNP3 on grid assets.' }
    502   = @{ Name = 'Modbus';        Severity = 'HIGH';   Description = 'Modbus TCP exposed. No native authentication or encryption. Restrict to known master station IPs via ACL.' }
    102   = @{ Name = 'IEC-61850/S7';  Severity = 'HIGH';   Description = 'IEC 61850 MMS / Siemens S7 port exposed. Verify device identity and restrict to authorized engineering workstations.' }
    2404  = @{ Name = 'IEC-60870-5-104'; Severity = 'HIGH'; Description = 'IEC 60870-5-104 (IEC104) exposed. Used for SCADA control. Restrict to designated control center IP ranges.' }
    44818 = @{ Name = 'EtherNet/IP';   Severity = 'MEDIUM'; Description = 'EtherNet/IP (CIP) exposed. Verify this is intentional. Restrict to PLC management VLAN and engineering stations.' }
    2222  = @{ Name = 'EtherNet/IP-IO'; Severity = 'MEDIUM'; Description = 'EtherNet/IP implicit I/O port exposed. Should not be reachable from non-OT VLANs. Review network segmentation.' }
}

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
# MAIN
# ---------------------------------------------------------------------------
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
Repository   : https://github.com/spinfosecurity/Energy-Grid-Protector
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
