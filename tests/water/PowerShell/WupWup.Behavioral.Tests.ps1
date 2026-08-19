BeforeAll {
    # Load all functions and configuration from the script without triggering
    # the interactive main-execution block. $WUP_TEST_MODE causes the script
    # to return before the try{} session starts.
    $WUP_TEST_MODE = $true
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $script:Root 'scanners' 'water' 'powershell' 'WUP-WUP.ps1')

    # Capture everything loaded by dot-source into $script: scope so it is
    # accessible inside all It blocks (Pester 6 runs It in a child scope).
    $script:ScriptInfo        = $ScriptInfo
    $script:ThreatContext     = $ThreatContext
    $script:RemoteAccessPorts = $RemoteAccessPorts
    $script:CriticalOTPorts   = $CriticalOTPorts
}

Describe 'Script meta' {
    It 'ScriptInfo.Version is populated' {
        $script:ScriptInfo.Version | Should -Not -BeNullOrEmpty
    }

    It 'ScriptInfo.Reference mentions CISA' {
        $script:ScriptInfo.Reference | Should -Match 'CISA'
    }
}

Describe 'ThreatContext table' {
    It 'contains an entry for RDP' {
        $script:ThreatContext['RDP'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for VNC' {
        $script:ThreatContext['VNC'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for SSH' {
        $script:ThreatContext['SSH'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for HTTP (Web HMI)' {
        $script:ThreatContext['HTTP'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for HTTPS (Web HMI)' {
        $script:ThreatContext['HTTPS'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for Modbus' {
        $script:ThreatContext['Modbus'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for EtherNet/IP' {
        $script:ThreatContext['EtherNet/IP'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for DNP3' {
        $script:ThreatContext['DNP3'] | Should -Not -BeNullOrEmpty
    }

    It 'contains an entry for UniLogic' {
        $script:ThreatContext['UniLogic'] | Should -Not -BeNullOrEmpty
    }
}

Describe 'Port tables' {
    It 'RemoteAccessPorts includes RDP (3389)' {
        $script:RemoteAccessPorts.ContainsKey(3389) | Should -BeTrue
    }

    It 'RemoteAccessPorts includes VNC (5900)' {
        $script:RemoteAccessPorts.ContainsKey(5900) | Should -BeTrue
    }

    It 'RemoteAccessPorts includes SSH (22)' {
        $script:RemoteAccessPorts.ContainsKey(22) | Should -BeTrue
    }

    It 'RemoteAccessPorts includes HTTP (80)' {
        $script:RemoteAccessPorts.ContainsKey(80) | Should -BeTrue
    }

    It 'CriticalOTPorts includes Modbus (502)' {
        $script:CriticalOTPorts.ContainsKey(502) | Should -BeTrue
    }

    It 'CriticalOTPorts includes EtherNet/IP (44818)' {
        $script:CriticalOTPorts.ContainsKey(44818) | Should -BeTrue
    }

    It 'CriticalOTPorts includes S7 (102)' {
        $script:CriticalOTPorts.ContainsKey(102) | Should -BeTrue
    }

    It 'CriticalOTPorts includes DNP3 (20000)' {
        $script:CriticalOTPorts.ContainsKey(20000) | Should -BeTrue
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
    It 'extracts RDP correctly' {
        $service = $script:RemoteAccessPorts[3389]
        $token = ($service -split '[\s(/]')[0]
        $script:ThreatContext.ContainsKey($token) | Should -BeTrue
    }

    It 'extracts HTTP from Web HMI label' {
        $service = $script:RemoteAccessPorts[80]
        $token = ($service -split '[\s(/]')[0]
        $token | Should -Be 'HTTP'
        $script:ThreatContext.ContainsKey($token) | Should -BeTrue
    }

    It 'extracts HTTPS from Web HMI label' {
        $service = $script:RemoteAccessPorts[443]
        $token = ($service -split '[\s(/]')[0]
        $token | Should -Be 'HTTPS'
        $script:ThreatContext.ContainsKey($token) | Should -BeTrue
    }

    It 'extracts Modbus from Modbus TCP label' {
        $protocol = $script:CriticalOTPorts[502]
        $token = ($protocol -split '[\s(/]')[0]
        $token | Should -Be 'Modbus'
        $script:ThreatContext.ContainsKey($token) | Should -BeTrue
    }
}

Describe 'Show-ScanHeader box width' {
    It 'does not throw for a normal subnet' {
        { Show-ScanHeader -Subnet '192.168.10.0/24' -StartTime (Get-Date) } | Should -Not -Throw
    }

    It 'does not throw for a long subnet string' {
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
    AfterAll {
        $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) 'WupWupTestReports'
        if (Test-Path $tmpDir) { Remove-Item $tmpDir -Recurse -Force }
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

    It 'report contains critical finding IP and port' {
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
