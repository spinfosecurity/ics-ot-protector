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
        [string]$Sector
    )
    $path = Join-Path (Get-RepoRoot) 'config' 'sectors' "$Sector.json"
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Sector config not found: $path (run scripts/config/compile_configs.py)"
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
            Name        = $_.name
            Severity    = $_.severity
            Category    = $_.category
            Description = $_.description
        }
    })
    if ($FastEotHot) {
        return , ($entries | Where-Object { $_.Category -eq 'EotHot' })
    }
    return , $entries
}
