# Structured remediation metadata for scan report findings.

function Get-RemediationMetadata {
    param(
        [string]$Severity,
        [string]$Category = 'General'
    )

    $sev = [string]$Severity
    $cat = ([string]$Category).ToLowerInvariant()

    $priority = 'PLANNED'
    $action = 'verify'
    $owner = 'ot'

    switch ($sev.ToUpperInvariant()) {
        'CRITICAL' {
            $priority = 'IMMEDIATE'
            $action = 'block'
            $owner = if ($cat -match 'remote') { 'security' } else { 'ot' }
        }
        'HIGH' {
            $priority = 'URGENT'
            if ($cat -match 'cve') {
                $action = 'patch'; $owner = 'ot'
            } elseif ($cat -match 'remote') {
                $action = 'block'; $owner = 'security'
            } else {
                $action = 'segment'; $owner = 'ot'
            }
        }
        'MEDIUM' {
            $priority = 'PLANNED'
            $action = 'verify'
            $owner = 'it'
        }
    }

    return [ordered]@{
        RemediationPriority = $priority
        RemediationAction   = $action
        OwnerRole           = $owner
    }
}

function Add-RemediationMetadata {
    param([array]$Findings)

    if ($null -eq $Findings) { return @() }

    foreach ($f in $Findings) {
        $meta = Get-RemediationMetadata -Severity ([string]$f.Severity) -Category ([string]$f.Category)
        $f | Add-Member -NotePropertyName RemediationPriority -NotePropertyValue $meta.RemediationPriority -Force
        $f | Add-Member -NotePropertyName RemediationAction -NotePropertyValue $meta.RemediationAction -Force
        $f | Add-Member -NotePropertyName OwnerRole -NotePropertyValue $meta.OwnerRole -Force
    }

    return ,@($Findings)
}

function Get-ExtendedScanReportSummary {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][array]$Findings,
        [int]$HostsScanned = 0,
        [int]$PortsChecked = 0,
        [int]$DurationMs = 0
    )

    if ($null -eq $Findings) { $Findings = @() }

    $base = Get-ScanReportSummary -Findings $Findings -HostsScanned $HostsScanned `
        -PortsChecked $PortsChecked -DurationMs $DurationMs

    $byCategory = @{}
    $byPriority = @{}
    $byOwner = @{}
    $byHost = @{}

    foreach ($f in $Findings) {
        $cat = [string]$f.Category
        if (-not $byCategory.ContainsKey($cat)) { $byCategory[$cat] = 0 }
        $byCategory[$cat]++

        $pri = if ($f.RemediationPriority) { [string]$f.RemediationPriority } else { 'PLANNED' }
        if (-not $byPriority.ContainsKey($pri)) { $byPriority[$pri] = 0 }
        $byPriority[$pri]++

        $owner = if ($f.OwnerRole) { [string]$f.OwnerRole } else { 'ot' }
        if (-not $byOwner.ContainsKey($owner)) { $byOwner[$owner] = 0 }
        $byOwner[$owner]++

        $hostKey = [string]$f.Host
        if (-not $byHost.ContainsKey($hostKey)) { $byHost[$hostKey] = 0 }
        $byHost[$hostKey]++
    }

    $topHosts = $byHost.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 |
        ForEach-Object { [ordered]@{ host = $_.Key; findings = $_.Value } }

    $base.findings_by_category = $byCategory
    $base.findings_by_priority = $byPriority
    $base.findings_by_owner_role = $byOwner
    $base.top_hosts = @($topHosts)

    return $base
}
