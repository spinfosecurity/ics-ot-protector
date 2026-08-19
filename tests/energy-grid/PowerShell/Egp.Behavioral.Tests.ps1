BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $script:Root 'scanners' '_shared' 'Import-SectorConfig.ps1')
    . (Join-Path $script:Root 'scanners' '_shared' 'ScannerHelpers.ps1')
    Initialize-EnergyGridConfig -Config (Import-SectorConfig -Sector 'energy-grid')
    $script:CveChecks = $CveChecks
    $script:RemoteAccessPorts = $RemoteAccessPorts
    $script:IcsPorts = $IcsPorts
}

Describe 'Energy Grid Protector config' {
    It 'loads four CVE check definitions' {
        @($script:CveChecks.Keys).Count | Should -Be 4
    }

    It 'CVE-2026-42945 includes web management ports' {
        $script:CveChecks['CVE-2026-42945'].Ports | Should -Contain 443
    }

    It 'remote access includes Telnet as CRITICAL' {
        $script:RemoteAccessPorts[23].Severity | Should -Be 'CRITICAL'
    }

    It 'ICS ports include DNP3 on 20000' {
        $script:IcsPorts.Contains(20000) | Should -BeTrue
    }
}

Describe 'Get-SubnetHosts' {
    It 'returns 254 hosts for a /24 subnet' {
        (Get-SubnetHosts -CidrSubnet '192.168.10.0/24').Count | Should -Be 254
    }

    It 'starts at .1 and ends at .254' {
        $hosts = Get-SubnetHosts -CidrSubnet '10.0.0.0/24'
        $hosts[0] | Should -Be '10.0.0.1'
        $hosts[-1] | Should -Be '10.0.0.254'
    }
}

Describe 'Get-SeverityColor' {
    It 'maps CRITICAL to Red' {
        Get-SeverityColor 'CRITICAL' | Should -Be 'Red'
    }
}
