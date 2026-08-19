BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $script:Root 'scanners' '_shared' 'Export-ScanReport.ps1')
    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ics-export-test-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:TempDir -Force | Out-Null
}

AfterAll {
    if (Test-Path $script:TempDir) {
        Remove-Item -LiteralPath $script:TempDir -Recurse -Force
    }
}

Describe 'Sort-ScanFindings' {
    It 'orders findings by severity then host and port' {
        $findings = @(
            [pscustomobject]@{ Timestamp = 't'; Host = '10.0.0.2'; Port = 80; Service = 'a'; Severity = 'MEDIUM'; Category = 'x'; Description = 'd' }
            [pscustomobject]@{ Timestamp = 't'; Host = '10.0.0.1'; Port = 443; Service = 'b'; Severity = 'CRITICAL'; Category = 'x'; Description = 'd' }
            [pscustomobject]@{ Timestamp = 't'; Host = '10.0.0.1'; Port = 22; Service = 'c'; Severity = 'HIGH'; Category = 'x'; Description = 'd' }
        )
        $sorted = Sort-ScanFindings -Findings $findings
        $sorted[0].Severity | Should -Be 'CRITICAL'
        $sorted[1].Severity | Should -Be 'HIGH'
        $sorted[2].Severity | Should -Be 'MEDIUM'
    }
}

Describe 'Export-ScanReport' {
    It 'writes JSON and CSV report files' {
        $findings = @(
            [pscustomobject]@{
                Timestamp = '2026-08-19T12:00:00'
                Host = '192.168.1.10'
                Port = 502
                Service = 'ICS-PROTOCOL:Modbus'
                Severity = 'HIGH'
                Category = 'ICS'
                Description = 'Modbus TCP exposed'
                Remediation = 'Segment OT network'
            }
        )

        $paths = Export-ScanReport -Findings $findings -OutputDir $script:TempDir -Prefix 'test-export' -Timestamp '20260819-120000'
        Test-Path -LiteralPath $paths.JsonPath | Should -BeTrue
        Test-Path -LiteralPath $paths.CsvPath | Should -BeTrue

        $csv = Get-Content -LiteralPath $paths.CsvPath -Raw
        $csv | Should -Match '192.168.1.10'
        $csv | Should -Match 'Modbus'
    }

    It 'wraps JSON with metadata when provided' {
        $paths = Export-ScanReport -Findings @() -OutputDir $script:TempDir -Prefix 'meta-export' -Timestamp '20260819-120001' `
            -Metadata @{ sector = 'energy-grid'; scanner = 'EGP' }

        $json = Get-Content -LiteralPath $paths.JsonPath -Raw | ConvertFrom-Json
        $json.schema_version | Should -Be '1.0'
        $json.metadata.sector | Should -Be 'energy-grid'
        @($json.findings).Count | Should -Be 0
    }
}
