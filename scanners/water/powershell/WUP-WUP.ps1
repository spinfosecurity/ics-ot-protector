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
    ✓ Generates JSON scan report (optional)
    
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
    - Parallel per-host scanning (up to 50 concurrent runspaces)
    - May produce false negatives behind aggressive firewalls
    - Requires local network access
    
    AUTHORIZED USE ONLY:
    Defensive security assessment by authorized personnel only.
    Only scan networks you own or have explicit written permission to test.
    
.NOTES
    Version: 3.4.0
    Name: WUP WUP - Water Utility Protector
    Last Updated: 2026-08-19
    Reference: CISA Alert AA26-097A (2026-07-30), FBI PSA 2026-08-01
    
.LINK
    https://www.cisa.gov/news-events/alerts/2026/07/30/cisa-urges-water-and-wastewater-systems-sector-protect-operational
#>

# ============================================================================
# CONFIGURATION (loaded from config/sectors/water.yaml)
# ============================================================================

. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'Import-SectorConfig.ps1')
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'ScannerHelpers.ps1')
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'ScanEngine.ps1')
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'Export-ScanReport.ps1')
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'Preflight.ps1')
$script:SectorConfig = Import-SectorConfig -Sector 'water'
Initialize-WaterConfig -Config $script:SectorConfig

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
                Write-Verbose "TcpClient cleanup error: $($_.Exception.Message)"
            }
        }
    }
    
    return $result
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
  ✓ Generates JSON scan report (optional)

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
    
    while ($subnets.Count -lt 5) {
        $promptNum = $subnets.Count + 1
        $subnet = Read-Host "  Subnet #$promptNum"
        
        # Empty input = done
        if ([string]::IsNullOrWhiteSpace($subnet)) { break }
        
        if ($subnet -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
            $prefixLength = [int]($subnet -split '/')[1]
            if ($prefixLength -eq 24) {
                $subnets += $subnet
                Write-Host "  ✓ Added: $subnet" -ForegroundColor Green
            } else {
                Write-Host "  ✗ Only /24 subnets are supported. Try again." -ForegroundColor Red
            }
        } else {
            Write-Host "  ✗ Invalid format. Use: 192.168.10.0/24. Try again." -ForegroundColor Red
        }
    }
    
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
    
    $timeout = $null
    do {
        $timeoutInput = Read-Host "  Enter timeout (1-30 seconds, default: 2)"
        
        if ([string]::IsNullOrWhiteSpace($timeoutInput)) {
            $timeout = 2
        } elseif ($timeoutInput -match '^\d+$') {
            $timeoutVal = [int]$timeoutInput
            if ($timeoutVal -lt 1 -or $timeoutVal -gt 30) {
                Write-Host "  ✗ Please enter a value between 1 and 30" -ForegroundColor Red
            } else {
                $timeout = $timeoutVal
            }
        } else {
            Write-Host "  ✗ Invalid input. Enter a number between 1 and 30" -ForegroundColor Red
        }
    } while ($null -eq $timeout)
    
    return $timeout
}

function Ask-ExportReport {
    Clear-Host
    Show-Header "Step 3: Export Options"
    
    Write-Host "Would you like to save a JSON scan report?" -ForegroundColor White
    Write-Host "`n" -NoNewline
    Write-Host "  • Report includes all findings with timestamps" -ForegroundColor DarkGray
    Write-Host "  • Standard JSON format shared across all sector scanners" -ForegroundColor DarkGray
    Write-Host "  • Saved to: ~/WaterUtilitySecurity/Reports/" -ForegroundColor DarkGray
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
    $totalPorts = $RemoteAccessPorts.Count + $CriticalOTPorts.Count
    $estimatedSeconds = $Subnets.Count * 254 * $Timeout * $totalPorts / 60
    $estimatedMinutes = [math]::Round([math]::Max($estimatedSeconds / 60, 0.5), 1)
    Write-Host "  Timeout: ${Timeout} seconds per IP" -ForegroundColor Yellow
    Write-Host "  Total IPs: $($Subnets.Count * 254)" -ForegroundColor Yellow
    Write-Host "  Estimated time (worst case): ~$estimatedMinutes minutes" -ForegroundColor Yellow
    Write-Host "  Report export: $(if ($ExportReport) { 'Yes' } else { 'No' })" -ForegroundColor $(if ($ExportReport) { 'Green' } else { 'DarkGray' })
    Write-Host "`n" -NoNewline
    
    $confirm = Read-Host "  Start scan? (Y/N)"
    
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "`n  Scan cancelled." -ForegroundColor Yellow
        Start-Sleep -Seconds 2
        exit
    }

    $null = Confirm-ScanScope -Subnets $Subnets
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
        if ($null -eq $Findings) {
            $Findings = @()
        }

        $reportDir = Join-Path ([System.Environment]::GetFolderPath('UserProfile')) "WaterUtilitySecurity\Reports"
        if (!(Test-Path $reportDir)) {
            New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
        }

        $durationMs = [int][math]::Round(($EndTime - $StartTime).TotalMilliseconds, 0)
        $portCount = $RemoteAccessPorts.Count + $CriticalOTPorts.Count
        $result = Export-ScanReport -Findings $Findings -OutputDir $reportDir -Prefix 'WUP-results' -Metadata @{
            sector          = 'water'
            scanner         = 'WUP WUP'
            version         = $ScriptInfo.Version
            reference       = $ScriptInfo.Reference
            subnets         = ($Subnets -join ',')
            timeout_seconds = $Timeout
            total_scanned   = $TotalScanned
            critical_count  = $CriticalCount
            high_count      = $HighCount
            duration_seconds = [math]::Round(($EndTime - $StartTime).TotalSeconds, 1)
        } -HostsScanned $TotalScanned -PortsChecked $portCount -DurationMs $durationMs -ExportCsv

        return $result.ReportPath
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
    
    # Derive box width from content so long subnets never overflow
    $timeStr = Get-Date -Format 'HH:mm:ss'
    $scanLine  = " SCAN: $Subnet"
    $timeLine  = " Started: $timeStr"
    $innerWidth = [math]::Max(50, [math]::Max($scanLine.Length, $timeLine.Length) + 2)
    
    $scanPad = $innerWidth - $scanLine.Length - 1
    $timePad = $innerWidth - $timeLine.Length - 1
    
    Write-Host "`n" -NoNewline
    Write-Host "┌$('─' * $innerWidth)┐" -ForegroundColor Cyan
    Write-Host "│" -ForegroundColor Cyan -NoNewline
    Write-Host "$scanLine$(' ' * $scanPad)" -ForegroundColor White -NoNewline
    Write-Host "│" -ForegroundColor Cyan
    Write-Host "│" -ForegroundColor Cyan -NoNewline
    Write-Host "$timeLine$(' ' * $timePad)" -ForegroundColor DarkGray -NoNewline
    Write-Host "│" -ForegroundColor Cyan
    Write-Host "└$('─' * $innerWidth)┘" -ForegroundColor Cyan
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
    $completeLine = " COMPLETE: $elapsedSeconds seconds, $FindingsCount findings"
    $padWidth = [math]::Max(0, 47 - $completeLine.Length)
    Write-Host "  │" -ForegroundColor Green -NoNewline
    Write-Host $completeLine -ForegroundColor White -NoNewline
    Write-Host (" " * $padWidth) -NoNewline
    Write-Host "│" -ForegroundColor Green
    Write-Host "  └" -ForegroundColor Green -NoNewline
    Write-Host ("─" * 48) -ForegroundColor Green -NoNewline
    Write-Host "┘" -ForegroundColor Green
}

# ============================================================================
# MAIN EXECUTION
# Set $WUP_TEST_MODE = $true before dot-sourcing this file to load functions
# and configuration without triggering the interactive session.
# ============================================================================

if ($WUP_TEST_MODE) { return }

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
    $portCatalog = Get-WaterPortCatalogFromConfig -Config $script:SectorConfig
    $maxConcurrency = 50
    $timeoutMs = $timeout * 1000
    
    foreach ($subnet in $subnets) {
        $subnetStartTime = Get-Date
        $subnetFindings = 0
        $subnetCollected = [System.Collections.Generic.List[pscustomobject]]::new()
        
        Show-ScanHeader -Subnet $subnet -StartTime $subnetStartTime
        
        $targets = Get-SubnetHosts -CidrSubnet $subnet
        $null = Invoke-TcpPortScan -Targets $targets -PortCatalog $portCatalog -TimeoutMs $timeoutMs -Threads $maxConcurrency -OnFinding {
            param($Finding)
            $subnetCollected.Add($Finding)
        } -OnProgress {
            param($TargetHost, $Processed, $Total)
            Write-ScanEngineProgress -TargetHost $TargetHost -Processed $Processed -Total $Total -StartTime $startTime
        }

        foreach ($r in ($subnetCollected | Sort-Object Host, Port)) {
            if ($r.Severity -eq 'CRITICAL') {
                Write-Host "  [!!! CRITICAL !!!] $($r.Host):$($r.Port) - $($r.Service)" -ForegroundColor Red
                Write-Host "      $($r.Description)" -ForegroundColor Red
                Write-Host "      Action: $($r.Remediation)" -ForegroundColor Yellow
                $criticalCount++
            } else {
                $color = if ($r.Category -eq 'OT Protocol Exposure') { 'Magenta' } else { 'Yellow' }
                Write-Host "  [!! HIGH !!] $($r.Host):$($r.Port) - $($r.Service)" -ForegroundColor $color
                Write-Host "      $($r.Description)" -ForegroundColor $color
                Write-Host "      Action: $($r.Remediation)" -ForegroundColor DarkYellow
                $highCount++
            }
            $findings += $r
            $subnetFindings++
        }

        $totalScanned += $targets.Count
        Show-ScanComplete -StartTime $subnetStartTime -FindingsCount $subnetFindings
    }
    
    # Final summary
    $endTime = Get-Date
    $totalElapsed = $endTime - $startTime
    $scanRate = [math]::Round($totalScanned / $totalElapsed.TotalSeconds, 1)
    
    Clear-Host
    Show-Header "WUP WUP - Scan Complete"
    
    $totalPorts = $totalScanned * ($RemoteAccessPorts.Count + $CriticalOTPorts.Count)
    $boxWidth = 50
    function Format-BoxLine([string]$label, [string]$value) {
        $content = " $label $value"
        $pad = [math]::Max(0, $boxWidth - $content.Length - 1)
        return "│$content$(' ' * $pad)│"
    }
    Write-Host "SCAN STATISTICS:" -ForegroundColor White
    Write-Host "  ┌$('─' * $boxWidth)┐" -ForegroundColor DarkGray
    Write-Host "  $(Format-BoxLine 'Total IPs Scanned:    ' $totalScanned)" -ForegroundColor White
    Write-Host "  $(Format-BoxLine 'Total Ports Tested:   ' $totalPorts)" -ForegroundColor White
    Write-Host "  $(Format-BoxLine 'Scan Duration:        ' "$([math]::Round($totalElapsed.TotalSeconds, 1)) seconds")" -ForegroundColor White
    Write-Host "  $(Format-BoxLine 'Average Rate:         ' "$scanRate IPs/second")" -ForegroundColor White
    Write-Host "  └$('─' * $boxWidth)┘" -ForegroundColor DarkGray
    Write-Host "`n" -NoNewline
    
    Write-Host "FINDINGS SUMMARY:" -ForegroundColor White
    Write-Host "  ┌$('─' * $boxWidth)┐" -ForegroundColor DarkGray
    Write-Host "  $(Format-BoxLine 'Critical:  ' $criticalCount)" -ForegroundColor $(if ($criticalCount -gt 0) { 'Red' } else { 'White' })
    Write-Host "  $(Format-BoxLine 'High:      ' $highCount)" -ForegroundColor $(if ($highCount -gt 0) { 'Yellow' } else { 'White' })
    Write-Host "  $(Format-BoxLine 'Total:     ' $findings.Count)" -ForegroundColor $(if ($findings.Count -gt 0) { 'Red' } else { 'Green' })
    Write-Host "  └$('─' * $boxWidth)┘" -ForegroundColor DarkGray
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
    
    # Export report if requested (always generate when requested, even for clean scans)
    if ($exportReport) {
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
