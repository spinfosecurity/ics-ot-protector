# =============================================================================
# BAS Guardian - configuration loaded from config/sectors/bas.yaml
# =============================================================================

. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'Import-SectorConfig.ps1')
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'ScannerHelpers.ps1')
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'ScanEngine.ps1')
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'Export-ScanReport.ps1')
. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'Preflight.ps1')
$script:SectorConfig = Import-SectorConfig -Sector 'bas'
Initialize-BasConfig -Config $script:SectorConfig

function Show-Intro {
    Clear-Host
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host "                    BAS GUARDIAN v2.0" -ForegroundColor White
    Write-Host "                    $ScriptTagline" -ForegroundColor White
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Version: $ScriptVersion | Updated: August 2026" -ForegroundColor White
    Write-Host "Reference: $Reference" -ForegroundColor White
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "NEW in v2.0 - Vendor-Specific Intelligence:" -ForegroundColor Green
    Write-Host "  + Honeywell IQ4x (CVE-2026-3611, CVSS 10.0) - auth disabled by default"
    Write-Host "  + Johnson Controls C-CURE 9000/Victor (ICSA-26-204-01) - RCE risk"
    Write-Host "  + Siemens Desigo CC/SENTRON Powermanager - privilege escalation"
    Write-Host "  + Tridium Niagara Framework port exposure (candidate)"
    Write-Host ""
    Write-Host "What This Does:" -ForegroundColor White
    Write-Host "  + Scans building automation subnets for exposed BACnet devices"
    Write-Host "  + Detects RDP (3389), VNC (5900), SSH (22) on BMS workstations"
    Write-Host "  + Identifies BACnet/IP (47808), BACnet/SC (4800), LonWorks (1628) exposure"
    Write-Host "  + Identifies candidate vendor-specific BMS exposure by port (Honeywell, JCI, Siemens, Tridium)"
    Write-Host "  + Flags unauthenticated BACnet traffic vulnerable to CVE-2026-24060"
    Write-Host "  + Prioritizes findings by severity (CRITICAL vs HIGH)"
    Write-Host "  + Generates JSON scan report (optional)"
    Write-Host ""
    Write-Host "What This Does NOT Do:" -ForegroundColor White
    Write-Host "  - Does NOT test credentials or attempt authentication"
    Write-Host "  - Does NOT modify HVAC/BMS configurations"
    Write-Host "  - Does NOT replace professional penetration testing"
    Write-Host "  - Does NOT decrypt BACnet/SC traffic"
    Write-Host "  - Does NOT work over IPv6 (IPv4 only)"
    Write-Host "  - Does NOT scan non-/24 subnets"
    Write-Host ""
    Write-Host "AUTHORIZED USE ONLY:" -ForegroundColor Yellow
    Write-Host "  This tool is for defensive security assessment by authorized personnel only."
    Write-Host "  Only scan networks you own or have explicit written permission to test."
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Press Enter to begin configuration or Ctrl+C to exit..." -ForegroundColor Yellow
    Read-Host
}

function Test-Port {
    param($IP, $Port, $TimeoutMs)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $connect = $tcp.BeginConnect($IP, $Port, $null, $null)
        $success = $connect.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if ($success) {
            $tcp.EndConnect($connect)
            $tcp.Close()
            return $true
        }
        $tcp.Close()
        return $false
    } catch {
        return $false
    }
}

function Ask-Subnets {
    Clear-Host
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  Step 1: Configure Scan Targets" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Which building automation subnets would you like to scan?"
    Write-Host "  - Enter up to 5 subnets in format: 192.168.20.0/24"
    Write-Host "  - Press Enter on empty line to finish"
    Write-Host ""

    $script:Subnets = @()
    $count = 0

    while ($count -lt 5) {
        $count++
        $subnet = Read-Host "  Subnet #$count"
        if ([string]::IsNullOrWhiteSpace($subnet)) { break }

        if ($subnet -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') {
            $prefixLength = $subnet.Split('/')[1]
            if ($prefixLength -eq 24) {
                $script:Subnets += $subnet
                Write-Host "  Added: $subnet" -ForegroundColor Green
            } else {
                Write-Host "  Only /24 subnets are supported" -ForegroundColor Red
            }
        } else {
            Write-Host "  Invalid format. Use: 192.168.20.0/24" -ForegroundColor Red
        }
    }

    if ($script:Subnets.Count -eq 0) {
        Write-Host "`n  No subnets entered. Exiting..." -ForegroundColor Red
        exit
    }
}

function Ask-Timeout {
    Clear-Host
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  Step 2: Set Scan Timeout" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Connection timeout per IP (in milliseconds):"
    Write-Host "  500ms  = Fast, may miss slow devices"
    Write-Host "  1000ms = Balanced (recommended)"
    Write-Host "  2000ms = Slower but more thorough"
    Write-Host ""

    $timeoutInput = Read-Host "  Enter timeout in ms (100-5000, default 1000)"
    if ([string]::IsNullOrWhiteSpace($timeoutInput)) {
        $script:TimeoutMs = 1000
    } else {
        $script:TimeoutMs = [int]$timeoutInput
    }
}

function Ask-ExportReport {
    Clear-Host
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  Step 3: Export Options" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    $answer = Read-Host "  Save JSON report to file? (Y/N)"
    $script:ExportReport = ($answer -match '^[Yy]')
}

function Confirm-Scan {
    Clear-Host
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host "  Step 4: Confirm Configuration" -ForegroundColor Cyan
    Write-Host "============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Subnets to scan:"
    foreach ($s in $script:Subnets) { Write-Host "  - $s" }
    Write-Host ""
    Write-Host "Timeout: $($script:TimeoutMs)ms per IP"
    Write-Host "Total IPs: $($script:Subnets.Count * 254)"
    Write-Host "Report export: $(if ($script:ExportReport) {'Yes'} else {'No'})"
    Write-Host ""
    $confirm = Read-Host "Start scan? (Y/N)"
    if ($confirm -notmatch '^[Yy]') {
        Write-Host "Cancelled."
        exit
    }

    $previewCatalog = Get-BasPortCatalogFromConfig -Config $script:SectorConfig
    $scope = Confirm-ScanScope -Subnets $script:Subnets
    Write-PreflightSummary -Sector 'bas' -HostCount $scope.HostCount -PortCount $previewCatalog.Count `
        -Threads 50 -TimeoutMs $script:TimeoutMs
}

function Generate-Report {
    $reportDir = ".\reports"
    if (!(Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir | Out-Null }

    $durationMs = [int][math]::Round($script:ScanDuration * 1000, 0)
    $result = Export-ScanReport -Findings $script:Findings -OutputDir $reportDir -Prefix 'BAS-results' -Metadata @{
        sector           = 'bas'
        scanner          = 'BAS Guardian'
        version          = $ScriptVersion
        reference        = $Reference
        subnets          = ($script:Subnets -join ',')
        timeout_ms       = $script:TimeoutMs
        total_scanned    = $script:TotalScanned
        critical_count   = $script:CriticalCount
        high_count       = $script:HighCount
        duration_seconds = $script:ScanDuration
    } -HostsScanned $script:TotalScanned -PortsChecked $portCatalog.Count -DurationMs $durationMs -ExportCsv

    return $result.ReportPath
}

if ($BAS_TEST_MODE -or $global:BAS_TEST_MODE) { return }

Show-Intro
Ask-Subnets
Ask-Timeout
Ask-ExportReport
Confirm-Scan

Clear-Host
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  BAS Guardian v2.0 - Starting Threat Detection" -ForegroundColor Cyan
Write-Host "  Scanning for exposed building automation systems" -ForegroundColor DarkGray
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Subnets: $($script:Subnets -join ', ')"
Write-Host "Timeout: $($script:TimeoutMs)ms per IP"
Write-Host ""

$script:Findings = @()
$script:TotalScanned = 0
$script:CriticalCount = 0
$script:HighCount = 0
$startTime = Get-Date
$portCatalog = Get-BasPortCatalogFromConfig -Config $script:SectorConfig

foreach ($subnet in $script:Subnets) {
    Write-Host "`n[SCAN] $subnet" -ForegroundColor Cyan
    $subnetStart = Get-Date
    $subnetFindingsBefore = $script:Findings.Count

    $targets = Get-SubnetHosts -CidrSubnet $subnet
    $null = Invoke-TcpPortScan -Targets $targets -PortCatalog $portCatalog -TimeoutMs $script:TimeoutMs -Threads 50 -OnFinding {
        param($Finding)
        $script:Findings += $Finding

        if ($Finding.Service -like '*BMS Platform*') {
            $vendor = $Finding.Service -replace ' BMS Platform$', ''
            Write-Host "  [!!! VENDOR CRITICAL !!!] $($Finding.Host):$($Finding.Port) - $vendor" -ForegroundColor Red
            Write-Host "      $($Finding.Description)" -ForegroundColor Red
            $script:CriticalCount++
        } elseif ($Finding.Severity -eq 'CRITICAL') {
            Write-Host "  [CRITICAL] $($Finding.Host):$($Finding.Port) - $($Finding.Service)" -ForegroundColor Red
            Write-Host "      $($Finding.Description)" -ForegroundColor Red
            $script:CriticalCount++
        } elseif ($Finding.Service -match 'BACnet|LonWorks|Tridium') {
            Write-Host "  [BAS] $($Finding.Host):$($Finding.Port) - $($Finding.Service)" -ForegroundColor Magenta
            $script:HighCount++
        } else {
            Write-Host "  [HIGH] $($Finding.Host):$($Finding.Port) - $($Finding.Service)" -ForegroundColor Yellow
            if ($Finding.Port -eq 80) {
                Write-Host "      $($ThreatContext['Honeywell'])" -ForegroundColor Yellow
            } else {
                Write-Host "      $($Finding.Description)" -ForegroundColor Yellow
            }
            $script:HighCount++
        }
    } -OnProgress {
        param($TargetHost, $Processed, $Total)
        Write-ScanEngineProgress -TargetHost $TargetHost -Processed $Processed -Total $Total -StartTime $startTime
    }

    $script:TotalScanned += $targets.Count
    $subnetFindings = $script:Findings.Count - $subnetFindingsBefore
    $subnetDuration = [math]::Round(((Get-Date) - $subnetStart).TotalSeconds, 1)
    Write-Host "  [COMPLETE] $subnetFindings findings in ${subnetDuration}s" -ForegroundColor Green
}

$script:ScanDuration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)

Clear-Host
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  BAS Guardian v2.0 - Scan Complete" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Total IPs Scanned: $($script:TotalScanned)"
Write-Host "Scan Duration: $($script:ScanDuration)s"
Write-Host ""
Write-Host "Critical: $($script:CriticalCount)  |  High: $($script:HighCount)  |  Total: $($script:Findings.Count)" -ForegroundColor White

if ($script:Findings.Count -gt 0) {
    Write-Host ""
    Write-Host "IMMEDIATE ACTIONS REQUIRED:" -ForegroundColor Red
    Write-Host "1. Remove BACnet devices from direct internet exposure"
    Write-Host "2. Implement VPN for all remote BMS/HVAC access (RDP/VNC/SSH)"
    Write-Host "3. Segment BAS network from corporate IT network"
    Write-Host "4. If Honeywell IQ4x port reachable: verify web HMI auth is ENABLED (CVE-2026-3611 exposure candidate)"
    Write-Host "5. If Johnson Controls C-CURE 9000/Victor port reachable: patch immediately (ICSA-26-204-01)"
    Write-Host "6. If Siemens Desigo CC port reachable: apply patch, review privilege assignments"
    Write-Host "7. Patch bacnet-stack to 1.4.3+ and monitor CVE-2026-24060 advisories"
    Write-Host "8. Report suspicious activity to CISA: https://www.cisa.gov/report-cyber-incident"

    if ($script:ExportReport) {
        $reportFile = Generate-Report
        Write-Host ""
        Write-Host "Report saved to: $reportFile" -ForegroundColor Green
    }
} else {
    Write-Host ""
    Write-Host "No internet-exposed threats detected." -ForegroundColor Green
}

Write-Host ""
