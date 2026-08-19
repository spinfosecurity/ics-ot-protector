$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ScriptPath = Join-Path $Root 'scripts' 'powershell' 'WUP-WUP.ps1'

# Dot-source only the configuration/function blocks without triggering the
# interactive main execution block (which is wrapped in try{} at file root).
# We extract and invoke the non-interactive parts via AST.
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $ScriptPath, [ref]$tokens, [ref]$errors)

# Execute configuration assignments and helper function definitions by
# running everything except the top-level try{} main block.
$nonMainStatements = $ast.EndBlock.Statements | Where-Object {
    -not ($_ -is [System.Management.Automation.Language.TryStatementAst])
}
foreach ($stmt in $nonMainStatements) {
    Invoke-Expression $stmt.Extent.Text
}

Describe 'ThreatContext table' {
    It 'contains an entry for RDP' {
        $ThreatContext['RDP'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for VNC' {
        $ThreatContext['VNC'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for SSH' {
        $ThreatContext['SSH'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for HTTP (Web HMI)' {
        $ThreatContext['HTTP'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for HTTPS (Web HMI)' {
        $ThreatContext['HTTPS'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for Modbus' {
        $ThreatContext['Modbus'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for EtherNet/IP' {
        $ThreatContext['EtherNet/IP'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for DNP3' {
        $ThreatContext['DNP3'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for UniLogic' {
        $ThreatContext['UniLogic'] | Should -Not -BeNullOrEmpty
    }
}

Describe 'Port tables' {
    It 'RemoteAccessPorts includes RDP (3389)' {
        $RemoteAccessPorts.ContainsKey(3389) | Should -BeTrue
    }

    It 'RemoteAccessPorts includes VNC (5900)' {
        $RemoteAccessPorts.ContainsKey(5900) | Should -BeTrue
    }

    It 'RemoteAccessPorts includes SSH (22)' {
        $RemoteAccessPorts.ContainsKey(22) | Should -BeTrue
    }

    It 'RemoteAccessPorts includes HTTP (80)' {
        $RemoteAccessPorts.ContainsKey(80) | Should -BeTrue
    }

    It 'CriticalOTPorts includes Modbus (502)' {
        $CriticalOTPorts.ContainsKey(502) | Should -BeTrue
    }

    It 'CriticalOTPorts includes EtherNet/IP (44818)' {
        $CriticalOTPorts.ContainsKey(44818) | Should -BeTrue
    }

    It 'CriticalOTPorts includes S7 (102)' {
        $CriticalOTPorts.ContainsKey(102) | Should -BeTrue
    }

    It 'CriticalOTPorts includes DNP3 (20000)' {
        $CriticalOTPorts.ContainsKey(20000) | Should -BeTrue
    }
}

Describe 'Get-NetworkPrefix' {
    It 'extracts the correct /24 prefix from a CIDR notation' {
        Get-NetworkPrefix -Subnet '192.168.10.0/24' | Should -Be '192.168.10'
    }

    It 'works with a non-zero host octet in the input' {
        Get-NetworkPrefix -Subnet '10.0.1.0/24' | Should -Be '10.0.1'
    }
}

Describe 'ThreatContext service token extraction' {
    It 'extracts RDP from "RDP (Remote Desktop) - #1 attack vector"' {
        $service = $RemoteAccessPorts[3389]
        $token = ($service -split '[\s(/]')[0]
        $ThreatContext.ContainsKey($token) | Should -BeTrue
    }

    It 'extracts HTTP from "HTTP (Web HMI)"' {
        $service = $RemoteAccessPorts[80]
        $token = ($service -split '[\s(/]')[0]
        $token | Should -Be 'HTTP'
        $ThreatContext.ContainsKey($token) | Should -BeTrue
    }

    It 'extracts HTTPS from "HTTPS (Web HMI)"' {
        $service = $RemoteAccessPorts[443]
        $token = ($service -split '[\s(/]')[0]
        $token | Should -Be 'HTTPS'
        $ThreatContext.ContainsKey($token) | Should -BeTrue
    }

    It 'extracts Modbus from Modbus TCP label' {
        $protocol = $CriticalOTPorts[502]
        $token = ($protocol -split '[\s(/]')[0]
        $token | Should -Be 'Modbus'
        $ThreatContext.ContainsKey($token) | Should -BeTrue
    }
}

Describe 'Show-ScanHeader box width' {
    It 'does not overflow for a normal subnet' {
        # If padding calculation would go negative, PowerShell throws — just verify no error
        { Show-ScanHeader -Subnet '192.168.10.0/24' -StartTime (Get-Date) } | Should -Not -Throw
    }

    It 'does not overflow for an unusually long subnet string' {
        { Show-ScanHeader -Subnet '255.255.255.255/24' -StartTime (Get-Date) } | Should -Not -Throw
    }
}

Describe 'Show-ScanComplete box padding' {
    It 'does not throw for small values' {
        { Show-ScanComplete -StartTime (Get-Date).AddSeconds(-5) -FindingsCount 3 } | Should -Not -Throw
    }

    It 'does not throw for large elapsed time and finding count' {
        { Show-ScanComplete -StartTime (Get-Date).AddSeconds(-9999) -FindingsCount 9999 } | Should -Not -Throw
    }
}

Describe 'Generate-Report' {
    BeforeAll {
        $testReportDir = Join-Path $env:TEMP 'WupWupTestReports'
        if (Test-Path $testReportDir) { Remove-Item $testReportDir -Recurse -Force }
    }

    AfterAll {
        if (Test-Path $testReportDir) { Remove-Item $testReportDir -Recurse -Force }
    }

    It 'creates a report file and returns its path' {
        $startTime = Get-Date
        $endTime   = $startTime.AddSeconds(10)
        $findings  = @(
            [PSCustomObject]@{
                IP = '192.168.1.1'; Port = 3389
                Service = 'RDP (Remote Desktop)'; Severity = 'CRITICAL'
                ThreatType = 'Remote Access'; ThreatContext = 'Test context'
                Action = 'Block immediately'
            }
        )
        $reportPath = Generate-Report -Subnets @('192.168.1.0/24') -Timeout 2 `
                                      -Findings $findings -TotalScanned 254 `
                                      -CriticalCount 1 -HighCount 0 `
                                      -StartTime $startTime -EndTime $endTime
        $reportPath | Should -Not -BeNullOrEmpty
        Test-Path $reportPath | Should -BeTrue
    }

    It 'report file contains critical finding IP and port' {
        $startTime = Get-Date
        $endTime   = $startTime.AddSeconds(5)
        $findings  = @(
            [PSCustomObject]@{
                IP = '10.0.0.42'; Port = 5900
                Service = 'VNC'; Severity = 'CRITICAL'
                ThreatType = 'Remote Access'; ThreatContext = 'VNC context'
                Action = 'Block'
            }
        )
        $reportPath = Generate-Report -Subnets @('10.0.0.0/24') -Timeout 2 `
                                      -Findings $findings -TotalScanned 254 `
                                      -CriticalCount 1 -HighCount 0 `
                                      -StartTime $startTime -EndTime $endTime
        $content = Get-Content $reportPath -Raw
        $content | Should -Match '10\.0\.0\.42'
        $content | Should -Match '5900'
    }

    It 'generates a clean-scan report with no findings' {
        $startTime = Get-Date
        $endTime   = $startTime.AddSeconds(3)
        $reportPath = Generate-Report -Subnets @('172.16.0.0/24') -Timeout 2 `
                                      -Findings @() -TotalScanned 254 `
                                      -CriticalCount 0 -HighCount 0 `
                                      -StartTime $startTime -EndTime $endTime
        $reportPath | Should -Not -BeNullOrEmpty
        Test-Path $reportPath | Should -BeTrue
        $content = Get-Content $reportPath -Raw
        $content | Should -Match 'No critical findings'
        $content | Should -Match 'No high-priority findings'
    }
}

Describe 'ScriptInfo' {
    It 'version is a non-empty string' {
        $ScriptInfo.Version | Should -Not -BeNullOrEmpty
    }

    It 'reference mentions CISA' {
        $ScriptInfo.Reference | Should -Match 'CISA'
    }
}
