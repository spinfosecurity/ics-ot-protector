<#
.SYNOPSIS
    WUP WUP - Water Utility Protector
    
.DESCRIPTION
    Interactive threat detector for water/wastewater utilities.
    "WUP WUP" - Emergency response for critical infrastructure protection.
    
    Updated August 2026 with latest CISA ICS advisories and threat intelligence.
    
    WHAT THIS DOES:
    ✓ Scans OT subnets for internet-exposed PLCs, HMIs, and remote access
    ✓ Detects RDP (3389), VNC (5900), SSH (22) - primary attack vectors
    ✓ Identifies EtherNet/IP (44818, 2222), Modbus (502), S7 (102) exposure
    ✓ Prioritizes findings by severity (CRITICAL vs HIGH)
    ✓ Provides CISA-aligned remediation guidance
    ✓ Generates simple text report (optional)
    
    WHAT THIS DOES NOT DO:
    ✗ Does NOT test credentials or attempt authentication
    ✗ Does NOT modify system configurations
    ✗ Does NOT scan IT networks (OT/SCADA focus only)
    ✗ Does NOT replace professional penetration testing
    ✗ Does NOT detect active malware or intrusions
    ✗ Does NOT work over IPv6 (IPv4 only)
    ✗ Does NOT scan non-/24 subnets
    
    TECHNICAL LIMITATIONS:
    - TCP port scan only (no UDP, no banner grabbing)
    - Single-threaded (~2-5 minutes per subnet)
    - May produce false negatives behind aggressive firewalls
    - Requires local network access
    
    AUTHORIZED USE ONLY:
    Defensive security assessment by authorized personnel only.
    Only scan networks you own or have explicit written permission to test.
    
.NOTES
    Version: 3.2.0 (Enhanced UI/UX with Report Export)
    Name: WUP WUP - Water Utility Protector
    Last Updated: 2026-08-02
    Reference: CISA Alert AA26-097A (2026-07-30), FBI PSA 2026-08-01
    
.LINK
    https://www.cisa.gov/news-events/alerts/2026/07/30/cisa-urges-water-and-wastewater-systems-sector-protect-operational
#>

# ============================================================================
# CONFIGURATION
# ============================================================================

$ScriptInfo = @{
    Name = "WUP WUP"
    FullName = "Water Utility Protector"
    Version = "3.2.0"
    Tagline = "WUP WUP - Emergency Response for Water Security"
    Reference = "CISA Alert AA26-097A (2026-07-30)"
}

$CriticalOTPorts = @{
    44818 = "EtherNet/IP (CIP) - Rockwell/Allen-Bradley [TARGETED]"
    2222 = "EtherNet/IP Alternate - CISA-flagged"
    502 = "Modbus TCP - Unauthenticated protocol"
    102 = "S7 Comm (Siemens SIMATIC)"
    20000 = "DNP3 - Water sector common"
    47808 = "BACnet/IP - Building/HVAC integration"
    20256 = "UniLogic (Unitronics Vision PLC)"
}

$RemoteAccessPorts = @{
    3389 = "RDP (Remote Desktop) - #1 attack vector"
    5900 = "VNC (Virtual Network Computing) - Active exploitation"
    5901 = "VNC Alternate"
    22 = "SSH (Secure Shell) - CISA-flagged in water attacks"
    80 = "HTTP (Web HMI)"
    443 = "HTTPS (Web HMI)"
    8080 = "HTTP Alternate (Web HMI)"
    8443 = "HTTPS Alternate (Web HMI)"
}

$ThreatContext = @{
    "RDP" = "PRIMARY ATTACK VECTOR - 70% of water sector breaches (CISA 2026)"
    "VNC" = "Active exploitation by Iran-linked groups (FBI PSA 2026-08-01)"
    "SSH" = "CISA-flagged in July 2026 water sector attacks"
    "EtherNet/IP" = "Rockwell MicroLogix 1400 targeted (4,148 exposed globally)"
    "Modbus" = "Unauthenticated - easily manipulated (CVSS 9.3)"
    "S7" = "Siemens SIMATIC S7-1200 (4,117 exposed globally)"
    "Web HMI" = "Internet-exposed HMIs per CISA/EPA joint advisory"
    "DNP3" = "Water sector SCADA protocol - no encryption"
    "UniLogic" = "Unitronics Vision PLC - default password '1111'"
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Test-Port {
    param(
        [string]$IP,
        [int]$Port,
        [int]$Timeout = 2
    )
    
    $tcpClient = $null
    $result = $false
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($IP, $Port, $null, $null)
        $connectionSuccess = $asyncResult.AsyncWaitHandle.WaitOne($Timeout * 1000)
        
        if ($connectionSuccess) {
            try {
                $tcpClient.EndConnect($asyncResult)
                $result = $tcpClient.Connected
            } catch {
                $result = $false
            }
        } else {
            $result = $false
        }
    } catch {
        $result = $false
    } finally {
        if ($tcpClient) {
            try {
                if ($tcpClient.Connected) {
                    $tcpClient.Close()
                }
                $tcpClient.Dispose()
            } catch {
                # Ignore cleanup errors
            }
        }
    }
    
    return $result
}

function Get-NetworkPrefix {
    param([string]$Subnet)
    
    $baseIP = ($subnet -split '/')[0]
    $octets = $baseIP -split '\.'
    return "$($octets[0]).$($octets[1]).$($octets[2])"
}

function Show-Intro {
    Clear-Host
    
    Write-Host @"

███████╗██╗███╗   ██╗ █████╗ ████████╗██╗ ██████╗ █████╗ ██╗     ██╗    ██╗
██╔════╝██║████╗  ██║██╔══██╗╚══██╔══╝██║██╔════╝██╔══██╗██║     ██║    ██║
█████╗  ██║██╔██╗ ██║███████║   ██║   ██║██║     ███████║██║     ██║ █╗ ██║
██╔══╝  ██║██║╚██╗██║██╔══██║   ██║   ██║██║     ██╔══██║██║     ██║███╗██║
██║     ██║██║ ╚████║██║  ██║   ██║   ██║╚██████╗██║  ██║███████╗╚███╔███╔╝
╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ 
                                                                           
WATER UTILITY PROTECTOR
$($ScriptInfo.Tagline)

Version: $($ScriptInfo.Version) | Updated: August 2026
Reference: $($ScriptInfo.Reference)

"@ -ForegroundColor Cyan
    
    Write-Host @"
================================================================================

Enhanced with CISA Alert AA26-097A Intelligence (July 2026 Water Sector Attacks)

What This Does:
  ✓ Scans OT subnets for exposed PLCs, HMIs, and remote access points
  ✓ Detects RDP (3389), VNC (5900), SSH (22) - primary attack vectors
  ✓ Identifies EtherNet/IP (44818, 2222), Modbus (502), S7 (102) exposure
  ✓ Prioritizes findings by severity (CRITICAL vs HIGH)
  ✓ Provides CISA-aligned remediation guidance
  ✓ Generates simple text report (optional)

What This Does NOT Do:
  ✗ Does NOT test credentials or attempt authentication
  ✗ Does NOT modify system configurations
  ✗ Does NOT scan IT networks (OT/SCADA focus only)
  ✗ Does NOT replace professional penetration testing
  ✗ Does NOT detect active malware or intrusions
  ✗ Does NOT work over IPv6 (IPv4 only)
  ✗ Does NOT scan non-/24 subnets

Technical Limitations:
  • TCP port scan only (no UDP, no banner grabbing)
  • Single-threaded (~2-5 minutes per subnet)
  • May produce false negatives behind aggressive firewalls
  • Requires local network access

AUTHORIZED USE ONLY:
  This tool is for defensive security assessment by authorized personnel only.
  Only scan networks you own or have explicit written permission to test.
  Unauthorized scanning may violate federal and state laws.

================================================================================
"@ -ForegroundColor White
    
    Write-Host "`nPress any key to begin configuration or Ctrl+C to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

function Show-Header {
    param(
        [string]$Title,
        [string]$Subtitle
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor Cyan
    if ($Subtitle) {
        Write-Host "  $Subtitle" -ForegroundColor DarkGray
    }
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "`n" -NoNewline
}

function Ask-Subnets {
    Clear-Host
    Show-Header "Step 1: Configure Scan Targets"
    
    Write-Host "Which OT subnets would you like to scan?" -ForegroundColor White
    Write-Host "  • Enter up to 5 subnets in format: 192.168.10.0/24" -ForegroundColor DarkGray
    Write-Host "  • Press Enter after each subnet" -ForegroundColor DarkGray
    Write-Host "  • Press Enter on empty line to finish" -ForegroundColor DarkGray
    Write-Host "`n" -NoNewline
    
    $subnets = @()
    $subnetCount = 0
    
    do {
        $subnetCount++
        $subnet = Read-Host "  Subnet #$subnetCount"
        
        if ($subnet) {
            if ($subnet -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
                $prefixLength = [int]($subnet -split '/')[1]
                if ($prefixLength -eq 24) {
                    $subnets += $subnet
                    Write-Host "  ✓ Added: $subnet" -ForegroundColor Green
                } else {
                    Write-Host "  ✗ Only /24 subnets are supported" -ForegroundColor Red
                }
            } else {
                Write-Host "  ✗ Invalid format. Use: 192.168.10.0/24" -ForegroundColor Red
            }
        }
    } while ($subnet -and $subnetCount -lt 5)
    
    if ($subnets.Count -eq 0) {
        Write-Host "`n  [!] No subnets entered. Exiting..." -ForegroundColor Red
        Start-Sleep -Seconds 2
        exit
    }
    
    return $subnets
}

function Ask-Timeout {
    Clear-Host
    Show-Header "Step 2: Set Scan Timeout"
    
    Write-Host "Connection timeout per IP (in seconds):" -ForegroundColor White
    Write-Host "`n" -NoNewline
    Write-Host "  Recommended Settings:" -ForegroundColor Cyan
    Write-Host "  ┌────────────┬──────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │ 1 second   │ Fast but may miss slow devices          │" -ForegroundColor DarkGray
    Write-Host "  │ 2 seconds  │ Balanced (recommended for most networks) │" -ForegroundColor Green
    Write-Host "  │ 3-5 seconds│ Slower but more thorough                │" -ForegroundColor DarkGray
    Write-Host "  └────────────┴──────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host "`n" -NoNewline
    
    do {
        $timeoutInput = Read-Host "  Enter timeout (1-30 seconds, default: 2)"
        
        if ([string]::IsNullOrWhiteSpace($timeoutInput)) {
            $timeout = 2
        } elseif ($timeoutInput -match '^\d+$') {
            $timeout = [int]$timeoutInput
            if ($timeout -lt 1 -or $timeout -gt 30) {
                Write-Host "  ✗ Please enter a value between 1 and 30" -ForegroundColor Red
            }
        } else {
            Write-Host "  ✗ Invalid input. Enter a number between 1 and 30" -ForegroundColor Red
        }
    } while (-not $timeout)
    
    return $timeout
}

function Ask-ExportReport {
    Clear-Host
    Show-Header "Step 3: Export Options"
    
    Write-Host "Would you like to save a scan report to a text file?" -ForegroundColor White
    Write-Host "`n" -NoNewline
    Write-Host "  • Report includes all findings with timestamps" -ForegroundColor DarkGray
    Write-Host "  • Easy to share with IT team or management" -ForegroundColor DarkGray
    Write-Host "  • Saved to: C:\WaterUtilitySecurity\Reports\" -ForegroundColor DarkGray
    Write-Host "`n" -NoNewline
    
    $export = Read-Host "  Save report? (Y/N)"
    
    return ($export -match '^[Yy]')
}

function Confirm-Scan {
    param(
        [string[]]$Subnets,
        [int]$Timeout,
        [bool]$ExportReport
    )
    
    Clear-Host
    Show-Header "Step 4: Confirm Configuration"
    
    Write-Host "Configuration Summary:" -ForegroundColor White
    Write-Host "`n" -NoNewline
    Write-Host "  Subnets to scan:" -ForegroundColor Yellow
    foreach ($subnet in $subnets) {
        Write-Host "    • $subnet" -ForegroundColor White
    }
    Write-Host "`n" -NoNewline
    Write-Host "  Timeout: ${Timeout} seconds per IP" -ForegroundColor Yellow
    Write-Host "  Total IPs: $($Subnets.Count * 254)" -ForegroundColor Yellow
    Write-Host "  Estimated time: $([math]::Round($Subnets.Count * 2.5, 1)) minutes" -ForegroundColor Yellow
    Write-Host "  Report export: $(if ($ExportReport) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($ExportReport) { 'Green' } else { 'DarkGray' })
    Write-Host "`n" -NoNewline
    
    $confirm = Read-Host "  Start scan? (Y/N)"
    
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "`n  Scan cancelled." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        exit
    }
}

function Generate-Report {
    param(
        [string[]]$Subnets,
        [int]$Timeout,
        [array]$Findings,
        [int]$TotalScanned,
        [int]$CriticalCount,
        [int]$HighCount,
        [datetime]$StartTime,
        [datetime]$EndTime
    )
    
    try {
        $reportDir = "C:\WaterUtilitySecurity\Reports"
        if (!(Test-Path $reportDir)) {
            New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $reportFile = Join-Path $reportDir "WUPWUP_Report_$timestamp.txt"
        
        $report = @"
================================================================================
                    WUP WUP - WATER UTILITY PROTECTOR
                    Security Scan Report
================================================================================

Report Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Script Version: $($ScriptInfo.Version)
Reference: $($ScriptInfo.Reference)

================================================================================
SCAN CONFIGURATION
================================================================================

Subnets Scanned:
"@
        
        foreach ($subnet in $subnets) {
            $report += "`n  • $subnet"
        }
        
        $report += @"

Timeout: $Timeout seconds per IP
Total IPs Scanned: $TotalScanned
Scan Duration: $([math]::Round(($EndTime - $StartTime).TotalSeconds, 1)) seconds

================================================================================
FINDINGS SUMMARY
================================================================================

Total Findings: $($Findings.Count)
  • Critical: $CriticalCount
  • High: $HighCount

================================================================================
CRITICAL FINDINGS (Immediate Action Required)
================================================================================
"@
        
        $criticalFindings = $Findings | Where-Object { $_.Severity -eq 'CRITICAL' }
        if ($criticalFindings.Count -gt 0) {
            foreach ($finding in $criticalFindings) {
                $report += @"

[$($finding.IP):$($finding.Port)] - $($finding.Service)
  Type: $($finding.ThreatType)
  Context: $($finding.ThreatContext)
  Action: $($finding.Action)
"@
            }
        } else {
            $report += "`n  No critical findings."
        }
        
        $report += @"

================================================================================
HIGH-PRIORITY FINDINGS
================================================================================
"@
        
        $highFindings = $Findings | Where-Object { $_.Severity -eq 'HIGH' }
        if ($highFindings.Count -gt 0) {
            foreach ($finding in $highFindings) {
                $report += @"

[$($finding.IP):$($finding.Port)] - $($finding.Service)
  Type: $($finding.ThreatType)
  Action: $($finding.Action)
"@
            }
        } else {
            $report += "`n  No high-priority findings."
        }
        
        $report += @"

================================================================================
RECOMMENDED ACTIONS
================================================================================

1. Disconnect CRITICAL devices from internet IMMEDIATELY
2. Implement VPN for all remote access (RDP/VNC/SSH)
3. Change ALL default passwords on PLCs/HMIs
4. Restrict OT protocols to engineering VLAN only
5. Check for cellular modem exposure (CISA blind spot)
6. Document findings and report to CISA if compromised

Reference: CISA Alert AA26-097A (2026-07-30)
Report Incident: https://www.cisa.gov/report-cyber-incident
CISA Scanning: https://www.cisa.gov/cyber-hygiene-services

================================================================================
                            END OF REPORT
================================================================================
"@
        
        $report | Out-File -FilePath $reportFile -Encoding UTF8
        return $reportFile
        
    } catch {
        Write-Host "  [!] Failed to generate report: $_" -ForegroundColor Red
        return $null
    }
}

function Show-ScanProgress {
    param(
        [int]$Current,
        [int]$Total,
        [datetime]$StartTime
    )
    
    $elapsed = (Get-Date) - $StartTime
    $rate = [math]::Round($Current / $elapsed.TotalSeconds, 1)
    $percent = [math]::Round(($Current / $Total) * 100)
    
    $progressBar = "[" + ("█" * ([math]::Floor($percent / 5))) + ("░" * (20 - [math]::Floor($percent / 5))) + "]"
    
    Write-Host "  $progressBar $percent% ($Current/$Total IPs) - $rate IPs/sec" -ForegroundColor DarkGray
}

function Show-ScanHeader {
    param(
        [string]$Subnet,
        [datetime]$StartTime
    )
    
    Write-Host "`n" -NoNewline
    Write-Host "┌" -ForegroundColor Cyan -NoNewline
    Write-Host ("─" * 50) -ForegroundColor Cyan -NoNewline
    Write-Host "┐" -ForegroundColor Cyan
    Write-Host "│" -ForegroundColor Cyan -NoNewline
    Write-Host " SCAN: $Subnet" -ForegroundColor White -NoNewline
    Write-Host (" " * (49 - $Subnet.Length)) -NoNewline
    Write-Host "│" -ForegroundColor Cyan
    Write-Host "│" -ForegroundColor Cyan -NoNewline
    Write-Host " Started: $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor DarkGray -NoNewline
    Write-Host (" " * (30 - (Get-Date -Format 'HH:mm:ss').Length)) -NoNewline
    Write-Host "│" -ForegroundColor Cyan
    Write-Host "└" -ForegroundColor Cyan -NoNewline
    Write-Host ("─" * 50) -ForegroundColor Cyan -NoNewline
    Write-Host "┘" -ForegroundColor Cyan
}

function Show-ScanComplete {
    param(
        [datetime]$StartTime,
        [int]$FindingsCount
    )
    
    $elapsed = (Get-Date) - $StartTime
    $elapsedSeconds = [math]::Round($elapsed.TotalSeconds, 1)
    
    Write-Host "`n  " -NoNewline
    Write-Host "┌" -ForegroundColor Green -NoNewline
    Write-Host ("─" * 48) -ForegroundColor Green -NoNewline
    Write-Host "┐" -ForegroundColor Green
    Write-Host "  │" -ForegroundColor Green -NoNewline
    Write-Host " COMPLETE: $elapsedSeconds seconds, $FindingsCount findings" -ForegroundColor White -NoNewline
    Write-Host (" " * (47 - ($elapsedSeconds.ToString().Length + $FindingsCount.ToString().Length + 28))) -NoNewline
    Write-Host "│" -ForegroundColor Green
    Write-Host "  └" -ForegroundColor Green -NoNewline
    Write-Host ("─" * 48) -ForegroundColor Green -NoNewline
    Write-Host "┘" -ForegroundColor Green
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

try {
    Show-Intro
    
    # Interactive configuration
    $subnets = Ask-Subnets
    $timeout = Ask-Timeout
    $exportReport = Ask-ExportReport
    Confirm-Scan -Subnets $subnets -Timeout $timeout -ExportReport $exportReport
    
    # Start scanning
    Clear-Host
    Show-Header "WUP WUP - Starting Threat Detection" "Scanning for ACTIVE THREAT VECTORS"
    
    Write-Host "Subnets: $($subnets -join ', ')" -ForegroundColor White
    Write-Host "Timeout: ${timeout}s per IP" -ForegroundColor White
    Write-Host "Scan Type: TCP Port Scan (OT + Remote Access)" -ForegroundColor White
    Write-Host "`n" -NoNewline
    
    $findings = @()
    $totalScanned = 0
    $criticalCount = 0
    $highCount = 0
    $startTime = Get-Date
    
    foreach ($subnet in $subnets) {
        $networkPrefix = Get-NetworkPrefix -Subnet $subnet
        $subnetStartTime = Get-Date
        $subnetFindings = 0
        
        Show-ScanHeader -Subnet $subnet -StartTime $subnetStartTime
        
        for ($i = 1; $i -le 254; $i++) {
            $ip = "$networkPrefix.$i"
            $totalScanned++
            
            # Progress every 25 IPs
            if ($i % 25 -eq 0) {
                Show-ScanProgress -Current $i -Total 254 -StartTime $subnetStartTime
            }
            
            # Remote access ports
            foreach ($port in $RemoteAccessPorts.Keys) {
                $portOpen = Test-Port -IP $ip -Port $port -Timeout $timeout
                
                if ($portOpen) {
                    $service = $RemoteAccessPorts[$port]
                    $serviceName = ($service -split ' ')[0]
                    $threatInfo = $ThreatContext[$serviceName]
                    
                    if ($port -in @(3389, 5900, 5901, 22)) {
                        Write-Host "  [!!! CRITICAL !!!] $ip`:$port - $service" -ForegroundColor Red
                        Write-Host "      $threatInfo" -ForegroundColor Red
                        Write-Host "      Action: BLOCK IMMEDIATELY or restrict to VPN only" -ForegroundColor Yellow
                        
                        $findings += [PSCustomObject]@{
                            IP = $ip
                            Port = $port
                            Service = $service
                            Severity = "CRITICAL"
                            ThreatType = "Remote Access - Immediate Threat"
                            ThreatContext = $threatInfo
                            Action = "BLOCK IMMEDIATELY or restrict to VPN only"
                        }
                        $criticalCount++
                        $subnetFindings++
                    } else {
                        Write-Host "  [!! HIGH !!] $ip`:$port - $service" -ForegroundColor Yellow
                        Write-Host "      $threatInfo" -ForegroundColor Yellow
                        Write-Host "      Action: Restrict to engineering VLAN; implement MFA" -ForegroundColor DarkYellow
                        
                        $findings += [PSCustomObject]@{
                            IP = $ip
                            Port = $port
                            Service = $service
                            Severity = "HIGH"
                            ThreatType = "Web HMI Exposure"
                            ThreatContext = $threatInfo
                            Action = "Restrict to engineering VLAN; implement MFA"
                        }
                        $highCount++
                        $subnetFindings++
                    }
                }
            }
            
            # OT protocols
            foreach ($port in $CriticalOTPorts.Keys) {
                $portOpen = Test-Port -IP $ip -Port $port -Timeout $timeout
                
                if ($portOpen) {
                    $protocol = $CriticalOTPorts[$port]
                    Write-Host "  [!] $ip`:$port - $protocol" -ForegroundColor Magenta
                    
                    $findings += [PSCustomObject]@{
                        IP = $ip
                        Port = $port
                        Service = $protocol
                        Severity = "HIGH"
                        ThreatType = "OT Protocol Exposure"
                        Action = "Remove from internet; implement firewall rules"
                    }
                    $subnetFindings++
                }
            }
        }
        
        Show-ScanComplete -StartTime $subnetStartTime -FindingsCount $subnetFindings
    }
    
    # Final summary
    $endTime = Get-Date
    $totalElapsed = $endTime - $startTime
    $scanRate = [math]::Round($totalScanned / $totalElapsed.TotalSeconds, 1)
    
    Clear-Host
    Show-Header "WUP WUP - Scan Complete"
    
    Write-Host "SCAN STATISTICS:" -ForegroundColor White
    Write-Host "  ┌────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │ Total IPs Scanned:     $totalScanned" -ForegroundColor White
    Write-Host "  │ Total Ports Tested:    $($totalScanned * ($RemoteAccessPorts.Count + $CriticalOTPorts.Count))" -ForegroundColor White
    Write-Host "  │ Scan Duration:         $([math]::Round($totalElapsed.TotalSeconds, 1)) seconds" -ForegroundColor White
    Write-Host "  │ Average Rate:          $scanRate IPs/second" -ForegroundColor White
    Write-Host "  └────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host "`n" -NoNewline
    
    Write-Host "FINDINGS SUMMARY:" -ForegroundColor White
    Write-Host "  ┌────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │ Critical:  $criticalCount" -ForegroundColor $(if ($criticalCount -gt 0) { 'Red' } else { 'White' })
    Write-Host "  │ High:      $highCount" -ForegroundColor $(if ($highCount -gt 0) { 'Yellow' } else { 'White' })
    Write-Host "  │ Total:     $($findings.Count)" -ForegroundColor $(if ($findings.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  └────────────────────────────────────────────────┘" -ForegroundColor DarkGray
    Write-Host "`n" -NoNewline
    
    if ($findings.Count -gt 0) {
        Write-Host "[!] IMMEDIATE ACTIONS REQUIRED:" -ForegroundColor Red
        Write-Host "`n" -NoNewline
        Write-Host "  1. Disconnect CRITICAL devices from internet IMMEDIATELY" -ForegroundColor Yellow
        Write-Host "  2. Implement VPN for all remote access (RDP/VNC/SSH)" -ForegroundColor Yellow
        Write-Host "  3. Change ALL default passwords on PLCs/HMIs" -ForegroundColor Yellow
        Write-Host "  4. Restrict OT protocols to engineering VLAN only" -ForegroundColor Yellow
        Write-Host "  5. Check for cellular modem exposure (CISA blind spot)" -ForegroundColor Yellow
        Write-Host "  6. Document findings and report to CISA if compromised" -ForegroundColor Yellow
        Write-Host "`n" -NoNewline
        Write-Host "  Reference: CISA Alert AA26-097A (2026-07-30)" -ForegroundColor DarkGray
        Write-Host "  Report: https://www.cisa.gov/report-cyber-incident" -ForegroundColor DarkGray
        Write-Host "  CISA Scanning: https://www.cisa.gov/cyber-hygiene-services" -ForegroundColor DarkGray
    } else {
        Write-Host "[✓] No internet-exposed threats detected." -ForegroundColor Green
        Write-Host "  Continue monitoring and maintain security controls." -ForegroundColor DarkGray
    }
    
    # Export report if requested
    if ($exportReport -and $findings.Count -gt 0) {
        Write-Host "`n" -NoNewline
        Write-Host "Generating report..." -ForegroundColor Cyan
        $reportPath = Generate-Report -Subnets $subnets -Timeout $timeout -Findings $findings `
                                     -TotalScanned $totalScanned -CriticalCount $criticalCount `
                                     -HighCount $highCount -StartTime $startTime -EndTime $endTime
        
        if ($reportPath) {
            Write-Host "`n[✓] Report saved to: $reportPath" -ForegroundColor Green
            Write-Host "  Share this report with your IT team or management." -ForegroundColor DarkGray
        }
    }
    
    Write-Host "`n" -NoNewline
    Write-Host "Press any key to exit..." -ForegroundColor Yellow
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    
} catch {
    Write-Host "`n" -NoNewline
    Write-Host "[ERROR] WUP WUP terminated unexpectedly" -ForegroundColor Red
    Write-Host "  Error: $($_.Exception.Message)" -ForegroundColor DarkGray
    Write-Host "  Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor DarkGray
    Write-Host "`n" -NoNewline
    Start-Sleep -Seconds 3
}
