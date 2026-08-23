# Shared sector configuration loader for PowerShell scanners.
# Reads compiled JSON from config/sectors/{sector}.json (source: .yaml).

function Get-RepoRoot {
    if ($script:RepoRoot) { return $script:RepoRoot }
    # scanners/_shared -> repo root
    $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    return $script:RepoRoot
}

function Import-SectorConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('water', 'energy-grid', 'bas', 'rail')]
        [string]$Sector,

        [string]$ConfigOverlay
    )
    $path = Join-Path (Get-RepoRoot) 'config' 'sectors' "$Sector.json"
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Sector config not found: $path (run scripts/config/compile_configs.py)"
    }
    if ($ConfigOverlay) {
        if (-not (Test-Path -LiteralPath $ConfigOverlay)) {
            throw "Config overlay not found: $ConfigOverlay"
        }
        $mergeScript = Join-Path (Get-RepoRoot) 'scripts' 'config' 'merge_overlay.py'
        $mergedJson = & python3 $mergeScript $path $ConfigOverlay
        if ($LASTEXITCODE -ne 0) {
            throw "Failed to merge config overlay: $ConfigOverlay"
        }
        return ($mergedJson | ConvertFrom-Json)
    }
    return (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json)
}

function Initialize-WaterConfig {
    param($Config)
    $script:ScriptInfo = @{
        Name     = $Config.metadata.name
        FullName = $Config.metadata.full_name
        Version  = $Config.metadata.version
        Tagline  = $Config.metadata.tagline
        Reference = $Config.metadata.reference
    }
    $script:RemoteAccessPorts = @{}
    foreach ($p in $Config.remote_access_ports) {
        $script:RemoteAccessPorts[[int]$p.port] = $p.label
    }
    $script:CriticalOTPorts = @{}
    foreach ($p in $Config.ot_protocol_ports) {
        $script:CriticalOTPorts[[int]$p.port] = $p.label
    }
    $script:ThreatContext = @{}
    $Config.threat_context.PSObject.Properties | ForEach-Object {
        $script:ThreatContext[$_.Name] = $_.Value
    }
}

function Initialize-EnergyGridConfig {
    param($Config)
    $script:CveChecks = @{}
    $Config.cve_checks.PSObject.Properties | ForEach-Object {
        $script:CveChecks[$_.Name] = @{
            Description = $_.Value.description
            Ports       = @($_.Value.ports | ForEach-Object { [int]$_ })
            Severity    = $_.Value.severity
            Remediation = $_.Value.remediation
        }
    }
    $script:RemoteAccessPorts = @{}
    foreach ($p in $Config.remote_access_ports) {
        $port = [int]$p.port
        $script:RemoteAccessPorts[$port] = @{
            Name        = $p.name
            Severity    = $p.severity
            Description = $p.description
        }
    }
    $script:IcsPorts = @{}
    foreach ($p in $Config.ics_ports) {
        $port = [int]$p.port
        $script:IcsPorts[$port] = @{
            Name        = $p.name
            Severity    = $p.severity
            Description = $p.description
        }
    }
}

function Initialize-BasConfig {
    param($Config)
    $script:ScriptName    = $Config.metadata.name
    $script:ScriptVersion = $Config.metadata.version
    $script:ScriptTagline = $Config.metadata.tagline
    $script:Reference     = $Config.metadata.reference
    $script:CriticalBASPorts = @{}
    foreach ($p in $Config.bas_protocol_ports) {
        $script:CriticalBASPorts[[int]$p.port] = $p.label
    }
    $script:RemoteAccessPorts = @{}
    foreach ($p in $Config.remote_access_ports) {
        $script:RemoteAccessPorts[[int]$p.port] = $p.label
    }
    $script:ThreatContext = @{}
    $Config.threat_context.PSObject.Properties | ForEach-Object {
        $script:ThreatContext[$_.Name] = $_.Value
    }
    $script:VendorAlerts = @(
        foreach ($a in $Config.vendor_alerts) {
            [PSCustomObject]@{
                Vendor      = $a.vendor
                Port        = [int]$a.port
                CVE         = $a.cve
                CVSS        = $a.cvss
                Description = $a.description
                Action      = $a.action
            }
        }
    )
}

function Initialize-RailConfig {
    param($Config)
    $script:RailConfig = $Config
}

function Get-RailPortCatalog {
    param([switch]$FastEotHot)
    $entries = @($script:RailConfig.port_catalog | ForEach-Object {
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

function Get-ThreatContextFromConfig {
    param(
        $Config,
        [string]$Key,
        [string]$Fallback = 'Exposed service — review access controls'
    )
    if ($Config.threat_context.PSObject.Properties.Name -contains $Key) {
        return [string]$Config.threat_context.$Key
    }
    return $Fallback
}

function Get-WaterPortCatalogFromConfig {
    param($Config)

    $entries = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($p in $Config.remote_access_ports) {
        $token = ($p.label -split '[\s(/]')[0]
        $ctx = Get-ThreatContextFromConfig -Config $Config -Key $token
        if ($p.severity -eq 'CRITICAL') {
            $category = 'Remote Access - Immediate Threat'
            $remediation = 'BLOCK IMMEDIATELY or restrict to VPN only'
        } else {
            $category = 'Web HMI Exposure'
            $remediation = 'Restrict to engineering VLAN; implement MFA'
        }
        $entries.Add([PSCustomObject]@{
            Port        = [int]$p.port
            Service     = $p.label
            Severity    = $p.severity
            Category    = $category
            Description = $ctx
            Remediation = $remediation
        })
    }
    foreach ($p in $Config.ot_protocol_ports) {
        $token = ($p.label -split '[\s(/]')[0]
        $ctx = Get-ThreatContextFromConfig -Config $Config -Key $token -Fallback 'OT protocol exposed to network — restrict access'
        $entries.Add([PSCustomObject]@{
            Port        = [int]$p.port
            Service     = $p.label
            Severity    = 'HIGH'
            Category    = 'OT Protocol Exposure'
            Description = $ctx
            Remediation = 'Remove from internet; implement firewall rules'
        })
    }
    return ,@($entries)
}

function Get-EnergyGridPortCatalogFromConfig {
    param(
        $Config,
        [switch]$CveOnly
    )

    $entries = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($prop in $Config.cve_checks.PSObject.Properties) {
        $cveId = $prop.Name
        $cve = $prop.Value
        foreach ($port in $cve.ports) {
            $entries.Add([PSCustomObject]@{
                Port        = [int]$port
                Service     = $cveId
                Severity    = $cve.severity
                Category    = 'CVE'
                Description = $cve.description
                Remediation = $cve.remediation
            })
        }
    }
    if (-not $CveOnly) {
        foreach ($p in $Config.remote_access_ports) {
            $entries.Add([PSCustomObject]@{
                Port        = [int]$p.port
                Service     = "REMOTE-ACCESS:$($p.name)"
                Severity    = $p.severity
                Category    = 'RemoteAccess'
                Description = $p.description
                Remediation = 'See docs/CISA-Reference.md for hardening guidance'
            })
        }
        foreach ($p in $Config.ics_ports) {
            $entries.Add([PSCustomObject]@{
                Port        = [int]$p.port
                Service     = "ICS-PROTOCOL:$($p.name)"
                Severity    = $p.severity
                Category    = 'ICS'
                Description = $p.description
                Remediation = 'See docs/Threat-Intelligence.md for ICS protocol hardening'
            })
        }
    }
    return ,@($entries)
}

function Get-BasPortCatalogFromConfig {
    param($Config)

    $entries = [System.Collections.Generic.List[pscustomobject]]::new()
    foreach ($p in $Config.remote_access_ports) {
        $port = [int]$p.port
        $severity = [string]$p.severity
        $key = ($p.label -split ' ')[0]
        if ($port -eq 80) {
            $description = Get-ThreatContextFromConfig -Config $Config -Key 'Honeywell' `
                -Fallback 'Remote access point - verify authorization and MFA'
        } else {
            $description = Get-ThreatContextFromConfig -Config $Config -Key $key `
                -Fallback 'Remote access point - verify authorization and MFA'
        }
        $remediation = if ($severity -eq 'CRITICAL') {
            'BLOCK IMMEDIATELY or restrict to VPN only'
        } else {
            'Restrict to management VLAN; implement MFA; verify auth enabled'
        }
        $entries.Add([PSCustomObject]@{
            Port        = $port
            Service     = $p.label
            Severity    = $severity
            Category    = 'BAS Exposure'
            Description = $description
            Remediation = $remediation
        })
    }
    foreach ($p in $Config.bas_protocol_ports) {
        $key = ($p.label -split ' ')[0]
        $description = Get-ThreatContextFromConfig -Config $Config -Key $key `
            -Fallback 'BAS protocol exposure - review segmentation'
        $entries.Add([PSCustomObject]@{
            Port        = [int]$p.port
            Service     = $p.label
            Severity    = 'HIGH'
            Category    = 'BAS Exposure'
            Description = $description
            Remediation = 'Remove from internet; segment from IT network; patch bacnet-stack'
        })
    }
    foreach ($a in $Config.vendor_alerts) {
        $entries.Add([PSCustomObject]@{
            Port        = [int]$a.port
            Service     = "$($a.vendor) BMS Platform"
            Severity    = 'CRITICAL'
            Category    = 'BAS Exposure'
            Description = "$($a.cve) - $($a.description)"
            Remediation = $a.action
        })
    }
    return ,@($entries)
}
