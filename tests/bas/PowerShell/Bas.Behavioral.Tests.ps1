BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $script:Root 'scanners' '_shared' 'Import-SectorConfig.ps1')
    . (Join-Path $script:Root 'scanners' '_shared' 'ScannerHelpers.ps1')
    Initialize-BasConfig -Config (Import-SectorConfig -Sector 'bas')
    $script:CriticalBASPorts = $CriticalBASPorts
    $script:RemoteAccessPorts = $RemoteAccessPorts
    $script:ThreatContext = $ThreatContext
    $script:VendorAlerts = $VendorAlerts
}

Describe 'BAS Guardian config' {
    It 'loads BACnet/IP on port 47808' {
        $script:CriticalBASPorts.ContainsKey(47808) | Should -BeTrue
    }

    It 'includes Honeywell CVE-2026-3611 vendor alert' {
        ($script:VendorAlerts | Where-Object { $_.CVE -eq 'CVE-2026-3611' }).Port | Should -Be 5489
    }

    It 'ThreatContext includes BACnet/IP guidance' {
        $script:ThreatContext['BACnet/IP'] | Should -Match 'CVE-2026-24060'
    }

    It 'remote access includes RDP on 3389' {
        $script:RemoteAccessPorts.ContainsKey(3389) | Should -BeTrue
    }
}

Describe 'Get-NetworkPrefix' {
    It 'extracts /24 prefix from CIDR' {
        Get-NetworkPrefix '192.168.10.0/24' | Should -Be '192.168.10'
    }
}
