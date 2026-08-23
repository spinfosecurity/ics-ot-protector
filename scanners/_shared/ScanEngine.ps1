# Shared TCP port scan engine for ICS OT Protector PowerShell scanners.

function Test-IcsTcpPort {
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$TargetHost,
        [Parameter(Mandatory)]
        [int]$Port,
        [ValidateRange(100, 60000)]
        [int]$TimeoutMs = 1000
    )

    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        if ($PSVersionTable.PSVersion.Major -ge 7) {
            $task = $client.ConnectAsync($TargetHost, $Port)
            return $task.Wait($TimeoutMs) -and $client.Connected
        }

        $asyncResult = $client.BeginConnect($TargetHost, $Port, $null, $null)
        if (-not $asyncResult.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) {
            return $false
        }
        $client.EndConnect($asyncResult)
        return $client.Connected
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function New-ScanFinding {
    param(
        [Parameter(Mandatory)][string]$Target,
        [Parameter(Mandatory)]$Entry
    )

    $service = if ($null -ne $Entry.Service -and "$($Entry.Service)".Length -gt 0) {
        [string]$Entry.Service
    } else {
        [string]$Entry.Name
    }

    [pscustomobject]@{
        Timestamp   = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        Host        = $Target
        Port        = [int]$Entry.Port
        Service     = $service
        Severity    = [string]$Entry.Severity
        Category    = [string]$Entry.Category
        Description = [string]$Entry.Description
        Remediation = [string]$Entry.Remediation
    }
}

function Build-ScanTargets {
    param(
        [Parameter(Mandatory)]
        [string[]]$Subnets
    )

    $seen = @{}
    $targets = [System.Collections.Generic.List[string]]::new()

    foreach ($subnet in $Subnets) {
        $subnet = $subnet.Trim()
        if ([string]::IsNullOrWhiteSpace($subnet)) { continue }
        try {
            foreach ($ip in (ConvertTo-IpRange -Cidr $subnet)) {
                if (-not $seen.ContainsKey($ip)) {
                    $seen[$ip] = $true
                    $targets.Add($ip)
                }
            }
        } catch {
            Write-Warning "Skipping invalid subnet '$subnet': $_"
        }
    }

    return ,@($targets)
}

function Invoke-TcpPortScan {
    <#
    .SYNOPSIS
        Scans targets against a port catalog using TCP connect probes.
    .PARAMETER OnFinding
        Optional scriptblock invoked for each open port: param($Finding)
    .PARAMETER OnProgress
        Optional scriptblock invoked per host: param($Host, $Processed, $Total)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Targets,
        [Parameter(Mandatory)]
        [array]$PortCatalog,
        [ValidateRange(100, 60000)]
        [int]$TimeoutMs = 1000,
        [ValidateRange(1, 512)]
        [int]$Threads = 1,
        [scriptblock]$OnFinding,
        [scriptblock]$OnProgress
    )

    if ($Targets.Count -eq 0) {
        throw 'Invoke-TcpPortScan: Targets is empty'
    }
    if (@($PortCatalog).Count -eq 0) {
        throw 'Invoke-TcpPortScan: PortCatalog is empty'
    }

    $catalog = @($PortCatalog)
    $findings = [System.Collections.Generic.List[pscustomobject]]::new()

    if ($Threads -le 1) {
        $seen = [System.Collections.Generic.HashSet[string]]::new()
        $processed = 0
        foreach ($target in $Targets) {
            $processed++
            if ($OnProgress) {
                & $OnProgress $target $processed $Targets.Count
            }

            foreach ($entry in $catalog) {
                $key = "${target}:$($entry.Port)"
                if ($seen.Contains($key)) { continue }
                if (Test-IcsTcpPort -TargetHost $target -Port $entry.Port -TimeoutMs $TimeoutMs) {
                    [void]$seen.Add($key)
                    $finding = New-ScanFinding -Target $target -Entry $entry
                    if ($OnFinding) {
                        & $OnFinding $finding
                    } else {
                        [void]$findings.Add($finding)
                    }
                }
            }
        }

        if ($OnFinding) {
            return @()
        }
        return ,@($findings)
    }

    $pool = [RunspaceFactory]::CreateRunspacePool(1, $Threads)
    $pool.Open()
    $jobs = [System.Collections.Generic.List[pscustomobject]]::new()

    $worker = {
        param($TargetHost, $Catalog, $TimeoutMs)

        function Test-PortLocal {
            param([string]$H, [int]$P, [int]$T)
            $c = [System.Net.Sockets.TcpClient]::new()
            try {
                $ar = $c.BeginConnect($H, $P, $null, $null)
                if (-not $ar.AsyncWaitHandle.WaitOne($T, $false)) { return $false }
                $c.EndConnect($ar)
                return $true
            } catch {
                return $false
            } finally {
                $c.Dispose()
            }
        }

        $hits = @()
        foreach ($entry in $Catalog) {
            if (Test-PortLocal -H $TargetHost -P $entry.Port -T $TimeoutMs) {
                $hits += [pscustomobject]@{
                    Timestamp   = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
                    Host        = $TargetHost
                    Port        = [int]$entry.Port
                    Service     = [string]$entry.Service
                    Severity    = [string]$entry.Severity
                    Category    = [string]$entry.Category
                    Description = [string]$entry.Description
                    Remediation = [string]$entry.Remediation
                }
            }
        }
        return $hits
    }

    foreach ($target in $Targets) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($worker).AddArgument($target).AddArgument($catalog).AddArgument($TimeoutMs)
        $jobs.Add([pscustomobject]@{
            PS     = $ps
            Handle = $ps.BeginInvoke()
            Host   = $target
        })
    }

    $done = 0
    foreach ($job in $jobs) {
        $results = @($job.PS.EndInvoke($job.Handle))
        foreach ($finding in $results) {
            if ($OnFinding) {
                & $OnFinding $finding
            } else {
                [void]$findings.Add($finding)
            }
        }
        if ($job.PS.HadErrors) {
            foreach ($err in $job.PS.Streams.Error) {
                Write-Warning "Runspace error on $($job.Host): $err"
            }
        }
        $job.PS.Dispose()
        $done++
        if ($OnProgress) {
            & $OnProgress $job.Host $done $Targets.Count
        } else {
            Write-Progress -Activity 'TCP Port Scan' `
                -Status "Hosts processed: $done / $($Targets.Count)" `
                -PercentComplete ([math]::Round(($done / $Targets.Count) * 100, 0))
        }
    }

    $pool.Close()
    $pool.Dispose()
    Write-Progress -Activity 'TCP Port Scan' -Completed

    if ($OnFinding) {
        return @()
    }
    return ,@($findings)
}
