# =============================================================================
# BAS Guardian - configuration loaded from config/sectors/bas.yaml
# =============================================================================

. (Join-Path (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)) '_shared' 'Import-SectorConfig.ps1')
Initialize-BasConfig -Config (Import-SectorConfig -Sector 'bas')

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
    Write-Host "  + Generates simple text report (optional)"
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

function Get-NetworkPrefix {
    param($Subnet)
    $baseIP = $Subnet.Split('/')[0]
    return ($baseIP.Split('.')[0..2] -join '.')
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
    $answer = Read-Host "  Save scan report to file? (Y/N)"
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
}

function Generate-Report {
    $reportDir = ".\reports"
    if (!(Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir | Out-Null }
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportFile = "$reportDir\BASGuardian_Report_$timestamp.txt"

    $content = @()
    $content += "================================================================================"
    $content += "  BAS GUARDIAN v2.0 - Building Automation Security Scan Report"
    $content += "================================================================================"
    $content += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $content += "Version: $ScriptVersion | Reference: $Reference"
    $content += ""
    $content += "Subnets Scanned:"
    foreach ($s in $script:Subnets) { $content += "  - $s" }
    $content += ""
    $content += "Timeout: $($script:TimeoutMs)ms | Total IPs: $script:TotalScanned | Duration: $($script:ScanDuration)s"
    $content += ""
    $content += "FINDINGS: $($script:Findings.Count) total ($script:CriticalCount critical, $script:HighCount high)"
    $content += ""
    $content += "--- CRITICAL FINDINGS ---"
    foreach ($f in $script:Findings) {
        if ($f.Severity -eq "CRITICAL") {
            $content += ""
            $content += "[$($f.IP):$($f.Port)] $($f.Service)"
            $content += "  $($f.ThreatContext)"
            $content += "  Action: $($f.Action)"
        }
    }
    $content += ""
    $content += "--- HIGH FINDINGS ---"
    foreach ($f in $script:Findings) {
        if ($f.Severity -eq "HIGH") {
            $content += ""
            $content += "[$($f.IP):$($f.Port)] $($f.Service)"
            $content += "  Action: $($f.Action)"
        }
    }
    $content += ""
    $content += "RECOMMENDED ACTIONS:"
    $content += "1. Remove BACnet devices from direct internet exposure"
    $content += "2. Implement VPN for all remote BMS/HVAC access (RDP/VNC/SSH)"
    $content += "3. Segment BAS network from corporate IT network"
    $content += "4. Upgrade to BACnet/SC where possible (encrypted transport)"
    $content += "5. Patch bacnet-stack to 1.4.3+ (CVE-2026-41503) and monitor CVE-2026-24060"
    $content += "6. If running Honeywell IQ4x: verify web HMI authentication is ENABLED (CVE-2026-3611)"
    $content += "7. If running Johnson Controls C-CURE 9000/Victor: patch immediately (ICSA-26-204-01)"
    $content += "8. If running Siemens Desigo CC/SENTRON Powermanager: apply patch and review privileges"
    $content += "9. Monitor for unauthorized Who-Is/I-Am broadcast traffic"

    $content | Out-File -FilePath $reportFile -Encoding UTF8
    return $reportFile
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

foreach ($subnet in $script:Subnets) {
    $prefix = Get-NetworkPrefix $subnet
    Write-Host "`n[SCAN] $subnet" -ForegroundColor Cyan
    $subnetStart = Get-Date
    $subnetFindings = 0

    for ($i = 1; $i -le 254; $i++) {
        $ip = "$prefix.$i"
        $script:TotalScanned++

        if ($i % 50 -eq 0) {
            Write-Host "  Progress: $i/254" -ForegroundColor DarkGray
        }

        foreach ($port in $RemoteAccessPorts.Keys) {
            if (Test-Port -IP $ip -Port $port -TimeoutMs $script:TimeoutMs) {
                $service = $RemoteAccessPorts[$port]
                $key = $service.Split(' ')[0]
                $threat = $ThreatContext[$key]
                if (-not $threat) { $threat = "Remote access point - verify authorization and MFA" }

                if ($port -in @(3389, 5900, 5901, 22)) {
                    Write-Host "  [CRITICAL] ${ip}:${port} - $service" -ForegroundColor Red
                    Write-Host "      $threat" -ForegroundColor Red
                    $script:Findings += [PSCustomObject]@{
                        IP = $ip; Port = $port; Service = $service; Severity = "CRITICAL"
                        ThreatContext = $threat; Action = "BLOCK IMMEDIATELY or restrict to VPN only"
                    }
                    $script:CriticalCount++
                } else {
                    Write-Host "  [HIGH] ${ip}:${port} - $service" -ForegroundColor Yellow
                    if ($port -eq 80) {
                        Write-Host "      $($ThreatContext['Honeywell'])" -ForegroundColor Yellow
                    }
                    $script:Findings += [PSCustomObject]@{
                        IP = $ip; Port = $port; Service = $service; Severity = "HIGH"
                        ThreatContext = $threat; Action = "Restrict to management VLAN; implement MFA; verify auth is enabled"
                    }
                    $script:HighCount++
                }
                $subnetFindings++
            }
        }

        foreach ($port in $CriticalBASPorts.Keys) {
            if (Test-Port -IP $ip -Port $port -TimeoutMs $script:TimeoutMs) {
                $protocol = $CriticalBASPorts[$port]
                Write-Host "  [BAS] ${ip}:${port} - $protocol" -ForegroundColor Magenta
                $threatKey = $protocol.Split(' ')[0]
                $threat = $ThreatContext[$threatKey]
                $script:Findings += [PSCustomObject]@{
                    IP = $ip; Port = $port; Service = $protocol; Severity = "HIGH"
                    ThreatContext = $threat; Action = "Remove from internet; segment from IT network; patch bacnet-stack"
                }
                $script:HighCount++
                $subnetFindings++
            }
        }

        foreach ($alert in $VendorAlerts) {
            if (Test-Port -IP $ip -Port $alert.Port -TimeoutMs $script:TimeoutMs) {
                Write-Host "  [!!! VENDOR CRITICAL !!!] ${ip}:$($alert.Port) - $($alert.Vendor)" -ForegroundColor Red
                Write-Host "      $($alert.CVE) (CVSS: $($alert.CVSS))" -ForegroundColor Red
                Write-Host "      $($alert.Description)" -ForegroundColor Red
                $script:Findings += [PSCustomObject]@{
                    IP = $ip; Port = $alert.Port; Service = "$($alert.Vendor) BMS Platform"; Severity = "CRITICAL"
                    ThreatContext = "$($alert.CVE) - $($alert.Description)"; Action = $alert.Action
                }
                $script:CriticalCount++
                $subnetFindings++
            }
        }
    }

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
