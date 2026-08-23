BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $script:Root 'scanners' '_shared' 'Import-SectorConfig.ps1')
}

Describe 'Shared sector configs' {
    It 'loads water config with expected port counts' {
        $cfg = Import-SectorConfig -Sector 'water'
        $cfg.remote_access_ports.Count | Should -Be 8
        $cfg.ot_protocol_ports.Count | Should -Be 7
        $cfg.threat_context.RDP | Should -Match 'CISA'
    }

    It 'loads energy-grid config with CVE checks' {
        $cfg = Import-SectorConfig -Sector 'energy-grid'
        @($cfg.cve_checks.PSObject.Properties).Count | Should -Be 4
        $cfg.remote_access_ports.Count | Should -Be 8
        $cfg.ics_ports.Count | Should -Be 9
    }

    It 'loads bas config with vendor alerts' {
        $cfg = Import-SectorConfig -Sector 'bas'
        $cfg.bas_protocol_ports.Count | Should -Be 9
        $cfg.vendor_alerts.Count | Should -Be 4
        ($cfg.vendor_alerts | Where-Object { $_.cve -eq 'CVE-2026-3611' }).port | Should -Be 5489
    }

    It 'loads rail config with EotHot ports' {
        $cfg = Import-SectorConfig -Sector 'rail'
        $cfg.port_catalog.Count | Should -Be 17
        ($cfg.port_catalog | Where-Object { $_.category -eq 'EotHot' }).Count | Should -Be 2
    }
}
