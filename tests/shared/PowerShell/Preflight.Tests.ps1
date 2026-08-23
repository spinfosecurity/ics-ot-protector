BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $script:Root 'scanners' '_shared' 'ScannerHelpers.ps1')
    . (Join-Path $script:Root 'scanners' '_shared' 'Preflight.ps1')
    . (Join-Path $script:Root 'scanners' '_shared' 'ScanEngine.ps1')
    . (Join-Path $script:Root 'scanners' '_shared' 'Export-ScanReport.ps1')
    $script:TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ics-preflight-test-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:TempDir -Force | Out-Null
}

AfterAll {
    if (Test-Path $script:TempDir) {
        Remove-Item -LiteralPath $script:TempDir -Recurse -Force
    }
}

Describe 'Confirm-ScanScope' {
    It 'accepts a normal /24 subnet' {
        $scope = Confirm-ScanScope -Subnets @('192.168.10.0/24')
        $scope.HostCount | Should -Be 254
    }

    It 'rejects /16 without Force' {
        { Confirm-ScanScope -Subnets @('10.0.0.0/16') } | Should -Throw
    }

    It 'allows /16 with Force' {
        $scope = Confirm-ScanScope -Subnets @('10.0.0.0/16') -Force
        $scope.HostCount | Should -BeGreaterThan 60000
    }
}

Describe 'Invoke-TcpPortScan integration' {
    It 'detects a local mock TCP listener' {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ($listener.LocalEndpoint).Port
        try {
            $catalog = @([PSCustomObject]@{
                Port = $port; Service = 'Mock'; Severity = 'HIGH'
                Category = 'Test'; Description = 'mock'; Remediation = 'none'
            })
            $hits = Invoke-TcpPortScan -Targets @('127.0.0.1') -PortCatalog $catalog -TimeoutMs 500 -Threads 1
            $hits.Count | Should -Be 1
            $hits[0].Port | Should -Be $port
        } finally {
            $listener.Stop()
        }
    }
}

Describe 'Export summary and CSV' {
    It 'writes metadata.summary and optional CSV' {
        $findings = @(
            [pscustomobject]@{
                Timestamp = '2026-08-19T12:00:00'
                Host = '192.168.1.10'
                Port = 502
                Service = 'Modbus'
                Severity = 'HIGH'
                Category = 'ICS'
                Description = 'Modbus exposed'
                Remediation = 'Segment OT network'
            }
        )

        $export = Export-ScanReport -Findings $findings -OutputDir $script:TempDir -Prefix 'summary-test' `
            -Timestamp '20260819-120000' -Metadata @{ sector = 'energy-grid'; scanner = 'EGP' } `
            -HostsScanned 254 -PortsChecked 15 -DurationMs 1200 -ExportCsv

        Test-Path -LiteralPath $export.ReportPath | Should -BeTrue
        Test-Path -LiteralPath $export.CsvPath | Should -BeTrue

        $json = Get-Content -LiteralPath $export.ReportPath -Raw | ConvertFrom-Json
        $json.metadata.summary.hosts_scanned | Should -Be 254
        $json.metadata.summary.findings_total | Should -Be 1
        $json.metadata.summary.findings_by_severity.HIGH | Should -Be 1
    }
}
