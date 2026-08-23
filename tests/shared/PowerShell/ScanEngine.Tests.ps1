BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $script:Root 'scanners' '_shared' 'Import-SectorConfig.ps1')
    . (Join-Path $script:Root 'scanners' '_shared' 'ScannerHelpers.ps1')
    . (Join-Path $script:Root 'scanners' '_shared' 'ScanEngine.ps1')
}

Describe 'Port catalog builders' {
    It 'builds energy-grid full catalog with more entries than cve-only' {
        $cfg = Import-SectorConfig -Sector 'energy-grid'
        $full = Get-EnergyGridPortCatalogFromConfig -Config $cfg
        $cveOnly = Get-EnergyGridPortCatalogFromConfig -Config $cfg -CveOnly
        @($full).Count | Should -BeGreaterThan @($cveOnly).Count
        ($full | Select-Object -First 1).Service | Should -Match 'CVE'
    }

    It 'builds water catalog with expected port count' {
        $cfg = Import-SectorConfig -Sector 'water'
        $catalog = Get-WaterPortCatalogFromConfig -Config $cfg
        @($catalog).Count | Should -Be 15
    }

    It 'builds bas catalog with vendor alert ports' {
        $cfg = Import-SectorConfig -Sector 'bas'
        $catalog = Get-BasPortCatalogFromConfig -Config $cfg
        @($catalog).Count | Should -BeGreaterThan 15
        ($catalog | Where-Object { $_.Service -like '*BMS Platform*' }).Count | Should -Be 4
    }
}

Describe 'Build-ScanTargets' {
    It 'expands comma-separated /24 subnets without duplicates' {
        $targets = Build-ScanTargets -Subnets @('192.168.10.0/24', '192.168.10.0/24')
        $targets.Count | Should -Be 254
    }

    It 'combines multiple /24 subnets' {
        $targets = Build-ScanTargets -Subnets @('10.0.1.0/24', '10.0.2.0/24')
        $targets.Count | Should -Be 508
    }
}

Describe 'New-ScanFinding' {
    It 'normalizes catalog entries into standard finding objects' {
        $entry = [PSCustomObject]@{
            Port        = 502
            Service     = 'Modbus TCP'
            Severity    = 'HIGH'
            Category    = 'ICS'
            Description = 'test'
            Remediation = 'segment'
        }
        $finding = New-ScanFinding -Target '10.0.0.5' -Entry $entry
        $finding.Host | Should -Be '10.0.0.5'
        $finding.Port | Should -Be 502
        $finding.Service | Should -Be 'Modbus TCP'
    }
}

Describe 'Test-IcsTcpPort' {
    It 'returns false for unreachable ports' {
        Test-IcsTcpPort -TargetHost '127.0.0.1' -Port 9 -TimeoutMs 200 | Should -BeFalse
    }
}
