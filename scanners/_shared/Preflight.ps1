# Pre-flight dependency and scan-scope validation for PowerShell scanners.

$script:PreflightWarnHosts = 1024
$script:PreflightForceHosts = 4096

function Test-ScanDependencies {
    $missing = @()
    if (-not (Get-Command ConvertFrom-Json -ErrorAction SilentlyContinue)) {
        $missing += 'PowerShell JSON cmdlets'
    }
    if ($missing.Count -gt 0) {
        throw "Missing required dependencies: $($missing -join ', ')"
    }
    return $true
}

function Get-ScanScopeInfo {
    param(
        [Parameter(Mandatory)]
        [string[]]$Subnets
    )

    $validated = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $totalEstimate = 0

    foreach ($raw in $Subnets) {
        $subnet = $raw.Trim()
        if ([string]::IsNullOrWhiteSpace($subnet)) { continue }
        try {
            $ips = ConvertTo-IpRange -Cidr $subnet
        } catch {
            throw "Invalid CIDR notation: '$subnet'. $($_.Exception.Message)"
        }
        $prefix = [int]($subnet.Split('/')[1])
        if ($prefix -le 20) {
            [void]$warnings.Add("Large subnet $subnet (/$prefix, ~$($ips.Count) hosts)")
        }
        $totalEstimate += $ips.Count
        [void]$validated.Add($subnet)
    }

    if ($validated.Count -eq 0) {
        throw "No valid CIDR targets provided."
    }

    $uniqueHosts = @(Build-ScanTargets -Subnets $validated)

    return [pscustomobject]@{
        ValidatedSubnets = @($validated)
        HostCount        = $uniqueHosts.Count
        Warnings         = @($warnings)
    }
}

function Confirm-ScanScope {
    param(
        [Parameter(Mandatory)]
        [string[]]$Subnets,
        [switch]$Force
    )

    [void](Test-ScanDependencies)
    $scope = Get-ScanScopeInfo -Subnets $Subnets

    foreach ($subnet in $scope.ValidatedSubnets) {
        $prefix = [int]($subnet.Split('/')[1])
        if ($prefix -le 16 -and -not $Force) {
            throw "Subnet $subnet is too large (/$prefix). Re-run with -Force to acknowledge a wide scan."
        }
    }

    if ($scope.HostCount -gt $script:PreflightForceHosts -and -not $Force) {
        throw "Scan scope is $($scope.HostCount) unique hosts (limit $($script:PreflightForceHosts) without -Force)."
    }

    foreach ($warn in $scope.Warnings) {
        Write-Warning $warn
    }
    if ($scope.HostCount -gt $script:PreflightWarnHosts) {
        Write-Warning "Scan will probe $($scope.HostCount) unique hosts."
    }

    return $scope
}

function Write-PreflightSummary {
    param(
        [string]$Sector,
        [int]$HostCount,
        [int]$PortCount,
        [int]$Threads,
        [int]$TimeoutMs
    )
    $probes = $HostCount * $PortCount
    Write-Host ("[{0}] [INFO] Pre-flight OK | Sector: {1} | Hosts: {2} | Ports: {3} | Probes: ~{4} | Threads: {5} | Timeout: {6}ms" -f `
        (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Sector, $HostCount, $PortCount, $probes, $Threads, $TimeoutMs)
}
