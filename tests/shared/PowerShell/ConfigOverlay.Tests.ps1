BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $script:Root 'scanners' '_shared' 'Import-SectorConfig.ps1')
    $script:Overlay = Join-Path ([System.IO.Path]::GetTempPath()) ("ics-overlay-test-" + [guid]::NewGuid().ToString('N') + '.yaml')
    @'
remote_access_ports:
  - port: 3390
    label: Overlay test port
    severity: HIGH
    context_key: RDP
'@ | Set-Content -LiteralPath $script:Overlay -Encoding UTF8
}

AfterAll {
    if (Test-Path $script:Overlay) {
        Remove-Item -LiteralPath $script:Overlay -Force
    }
}

Describe 'Import-SectorConfig overlay' {
    It 'merges overlay ports onto the water sector config' {
        $config = Import-SectorConfig -Sector 'water' -ConfigOverlay $script:Overlay
        $ports = @($config.remote_access_ports | ForEach-Object { [int]$_.port })
        $ports | Should -Contain 3390
    }
}
