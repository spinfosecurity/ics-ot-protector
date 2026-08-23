BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $script:Root 'scanners' '_shared' 'Export-ScanReport.ps1')
    . (Join-Path $script:Root 'scanners' '_shared' 'RemediationMetadata.ps1')
}

Describe 'Get-RemediationMetadata' {
    It 'classifies CRITICAL remote access as IMMEDIATE block for security' {
        $meta = Get-RemediationMetadata -Severity 'CRITICAL' -Category 'Remote Access'
        $meta.RemediationPriority | Should -Be 'IMMEDIATE'
        $meta.RemediationAction | Should -Be 'block'
        $meta.OwnerRole | Should -Be 'security'
    }

    It 'classifies HIGH OT exposure as URGENT segment for ot' {
        $meta = Get-RemediationMetadata -Severity 'HIGH' -Category 'OT Protocol Exposure'
        $meta.RemediationPriority | Should -Be 'URGENT'
        $meta.RemediationAction | Should -Be 'segment'
        $meta.OwnerRole | Should -Be 'ot'
    }
}

Describe 'Export with remediation metadata' {
    It 'adds remediation fields and extended summary' {
        $temp = Join-Path ([System.IO.Path]::GetTempPath()) ("ics-remediation-test-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $temp -Force | Out-Null
        try {
            $export = Export-ScanReport -Findings @(
                [pscustomobject]@{
                    Timestamp = '2026-08-19T12:00:00'
                    Host = '192.168.1.10'
                    Port = 5900
                    Service = 'VNC'
                    Severity = 'CRITICAL'
                    Category = 'Remote Access'
                    Description = 'VNC exposed'
                    Remediation = 'Block'
                }
            ) -OutputDir $temp -Prefix 'rem-test' -Timestamp '20260819-120000' `
                -Metadata @{ sector = 'water'; scanner = 'WUP WUP' } -HostsScanned 254 -PortsChecked 15 -DurationMs 1000

            $json = Get-Content -LiteralPath $export.ReportPath -Raw | ConvertFrom-Json
            $json.findings[0].RemediationPriority | Should -Be 'IMMEDIATE'
            $json.metadata.summary.findings_by_priority.IMMEDIATE | Should -Be 1
            $json.metadata.summary.top_hosts[0].host | Should -Be '192.168.1.10'
        } finally {
            Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Review-ScanReport.ps1' {
    It 'prints triage output for the sample report' {
        $sample = Join-Path $script:Root 'docs' 'sample-report.json'
        $out = & (Join-Path $script:Root 'scripts' 'Review-ScanReport.ps1') -ReportPath $sample 6>&1 | Out-String
        $out | Should -Match 'IMMEDIATE'
        $out | Should -Match '192.168.10.78'
    }
}
