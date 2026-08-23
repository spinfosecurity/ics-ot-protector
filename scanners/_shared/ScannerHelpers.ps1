# Shared subnet helpers for CLI scanners.

function Get-SubnetHosts {
    param([string]$CidrSubnet)
    $baseIp = $CidrSubnet -replace '/24$', ''
    $prefix = ($baseIp -split '\.')[0..2] -join '.'
    1..254 | ForEach-Object { "$prefix.$_" }
}

function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
        'CRITICAL' { return 'Red' }
        'HIGH'     { return 'DarkRed' }
        'MEDIUM'   { return 'Yellow' }
        default    { return 'Gray' }
    }
}

function Get-NetworkPrefix {
    param(
        [Alias('Subnet')]
        [string]$Cidr
    )
    return ($Cidr -split '/')[0] -replace '\.\d+$', ''
}

function ConvertTo-IpRange {
    param([string]$Cidr)

    if ($Cidr -notmatch '^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)/(3[0-2]|[12]?\d)$') {
        throw "Invalid CIDR notation: '$Cidr'. Expected format: x.x.x.x/n"
    }

    $parts  = $Cidr.Split('/')
    $baseIp = [System.Net.IPAddress]::Parse($parts[0])
    $prefix = [int]$parts[1]

    if ($prefix -lt 8 -or $prefix -gt 32) {
        throw "Prefix /$prefix outside safe scan range /8-/32. Please use a narrower subnet."
    }

    $bytes = $baseIp.GetAddressBytes()
    [array]::Reverse($bytes)
    $ipInt = [BitConverter]::ToUInt32($bytes, 0)

    $mask      = if ($prefix -eq 0) { [uint32]0 } else { [uint32]::MaxValue -shl (32 - $prefix) }
    $network   = $ipInt -band $mask
    $hostCount = [math]::Pow(2, (32 - $prefix))
    $broadcast = $network + $hostCount - 1

    $list = New-Object System.Collections.Generic.List[string]
    for ($cur = $network + 1; $cur -lt $broadcast; $cur++) {
        $b = [BitConverter]::GetBytes([uint32]$cur)
        [array]::Reverse($b)
        $list.Add(([System.Net.IPAddress]::new($b)).ToString())
    }
    return ,@($list.ToArray())
}

function Write-ScanEngineProgress {
    param(
        [string]$TargetHost,
        [int]$Processed,
        [int]$Total,
        [datetime]$StartTime,
        [int]$Interval = 25
    )

    if ($Total -le 0) { return }
    if ($Processed % $Interval -ne 0 -and $Processed -ne $Total) { return }

    $elapsed = ([datetime]::UtcNow - $StartTime).TotalSeconds
    $pct = [math]::Round(($Processed / $Total) * 100, 0)
    $rate = if ($elapsed -gt 0 -and $Processed -gt 0) { [math]::Round($Processed / $elapsed, 1) } else { '?' }
    $eta = if ($elapsed -gt 0 -and $Processed -gt 0) {
        [math]::Round((($Total - $Processed) * $elapsed) / $Processed, 0)
    } else { '?' }

    Write-Host ("[{0}] [INFO] Progress: {1}/{2} ({3}%) | {4} hosts/s | ETA ~{5}s" -f `
        (Get-Date -Format 'HH:mm:ss'), $Processed, $Total, $pct, $rate, $eta)
}

function Get-RailPortCatalogFromConfig {
    param(
        $Config,
        [switch]$FastEotHot
    )
    $entries = @($Config.port_catalog | ForEach-Object {
        [PSCustomObject]@{
            Port        = [int]$_.port
            Service     = $_.name
            Severity    = $_.severity
            Category    = $_.category
            Description = $_.description
            Remediation = ''
        }
    })
    if ($FastEotHot) {
        return , ($entries | Where-Object { $_.Category -eq 'EotHot' })
    }
    return , $entries
}
