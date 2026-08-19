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

Describe 'ConvertTo-StandardFindings' {
    It 'maps IP and ThreatContext fields to the standard schema' {
        $normalized = ConvertTo-StandardFindings -Findings @(
            [pscustomobject]@{
                IP = '10.0.0.5'; Port = 502; Service = 'Modbus'
                Severity = 'HIGH'; ThreatType = 'OT Protocol Exposure'
                ThreatContext = 'Modbus exposed'; Action = 'Segment network'
            }
        )
        $normalized[0].Host | Should -Be '10.0.0.5'
        $normalized[0].Category | Should -Be 'OT Protocol Exposure'
        $normalized[0].Description | Should -Be 'Modbus exposed'
        $normalized[0].Remediation | Should -Be 'Segment network'
    }
}

Describe 'Sort-ScanFindings' {
    It 'orders findings by severity then host and port' {
        $findings = @(
            [pscustomobject]@{ Timestamp = 't'; Host = '10.0.0.2'; Port = 80; Service = 'a'; Severity = 'MEDIUM'; Category = 'x'; Description = 'd'; Remediation = '' }
            [pscustomobject]@{ Timestamp = 't'; Host = '10.0.0.1'; Port = 443; Service = 'b'; Severity = 'CRITICAL'; Category = 'x'; Description = 'd'; Remediation = '' }
            [pscustomobject]@{ Timestamp = 't'; Host = '10.0.0.1'; Port = 22; Service = 'c'; Severity = 'HIGH'; Category = 'x'; Description = 'd'; Remediation = '' }
        )
        $sorted = Sort-ScanFindings -Findings $findings
        $sorted[0].Severity | Should -Be 'CRITICAL'
        $sorted[1].Severity | Should -Be 'HIGH'
        $sorted[2].Severity | Should -Be 'MEDIUM'
    }
}

Describe 'Export-ScanReport' {
    It 'writes a JSON report using the shared schema' {
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

        $paths = Export-ScanReport -Findings $findings -OutputDir $script:TempDir -Prefix 'test-export' -Timestamp '20260819-120000' `
            -Metadata @{ sector = 'energy-grid'; scanner = 'EGP' }
        Test-Path -LiteralPath $paths.ReportPath | Should -BeTrue
        $paths.ReportPath | Should -Match '\.json$'

        $json = Get-Content -LiteralPath $paths.ReportPath -Raw | ConvertFrom-Json
        $json.schema_version | Should -Be '1.0'
        $json.metadata.sector | Should -Be 'energy-grid'
        @($json.findings).Count | Should -Be 1
        $json.findings[0].Host | Should -Be '192.168.1.10'
    }

    It 'supports empty findings with metadata' {
        $paths = Export-ScanReport -Findings @() -OutputDir $script:TempDir -Prefix 'meta-export' -Timestamp '20260819-120001' `
            -Metadata @{ sector = 'energy-grid'; scanner = 'EGP' }

        $json = Get-Content -LiteralPath $paths.ReportPath -Raw | ConvertFrom-Json
        $json.schema_version | Should -Be '1.0'
        $json.metadata.sector | Should -Be 'energy-grid'
        @($json.findings).Count | Should -Be 0
    }
}
