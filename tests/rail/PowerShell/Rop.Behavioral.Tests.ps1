BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $script:Root 'scanners' '_shared' 'Import-SectorConfig.ps1')
    . (Join-Path $script:Root 'scanners' '_shared' 'ScannerHelpers.ps1')
    $script:RailConfig = Import-SectorConfig -Sector 'rail'
}

Describe 'Rail-OT-Protector port catalog' {
    It 'includes 17 ports in full catalog' {
        (Get-RailPortCatalogFromConfig -Config $script:RailConfig).Count | Should -Be 17
    }

    It 'EotHot-only mode returns two ports' {
        (Get-RailPortCatalogFromConfig -Config $script:RailConfig -FastEotHot).Count | Should -Be 2
    }

    It 'includes CVE-2025-1727 EOT/HOT ports' {
        $ports = (Get-RailPortCatalogFromConfig -Config $script:RailConfig -FastEotHot | ForEach-Object { $_.Port })
        $ports | Should -Contain 4510
        $ports | Should -Contain 4511
    }

    It 'includes RailSafe legacy API port' {
        $catalog = Get-RailPortCatalogFromConfig -Config $script:RailConfig
        ($catalog | Where-Object { $_.Category -eq 'RailSafe' }).Port | Should -Be 28784
    }
}

Describe 'ConvertTo-IpRange' {
    It 'expands /24 to 254 host addresses' {
        (ConvertTo-IpRange -Cidr '192.168.10.0/24').Count | Should -Be 254
    }

    It 'rejects invalid CIDR notation' {
        { ConvertTo-IpRange -Cidr 'not-a-cidr' } | Should -Throw
    }
}
