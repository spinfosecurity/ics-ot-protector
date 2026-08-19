BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $script:ScannerRoot = Join-Path $script:Root 'scanners'
    $script:ScriptFiles = @(Get-ChildItem -Path $script:ScannerRoot -Filter '*.ps1' -Recurse)
    $script:Sectors = @('water', 'energy-grid', 'bas', 'rail')
}

Describe 'ICS OT Protector monorepo' {
    It 'contains all four sector scanner directories' {
        foreach ($sector in $script:Sectors) {
            Test-Path (Join-Path $script:ScannerRoot $sector) | Should -BeTrue -Because "$sector scanner directory must exist"
        }
    }

    It 'contains at least one PowerShell scanner per sector' {
        foreach ($sector in $script:Sectors) {
            $files = @(Get-ChildItem -Path (Join-Path $script:ScannerRoot $sector) -Filter '*.ps1' -Recurse)
            $files.Count | Should -BeGreaterThan 0 -Because "$sector must have a PowerShell scanner"
        }
    }

    It 'contains at least one Bash scanner per sector' {
        foreach ($sector in $script:Sectors) {
            $files = @(Get-ChildItem -Path (Join-Path $script:ScannerRoot $sector) -Filter '*.sh' -Recurse)
            $files.Count | Should -BeGreaterThan 0 -Because "$sector must have a Bash scanner"
        }
    }

    It 'has PowerShell scanner files that parse without errors' {
        foreach ($file in $script:ScriptFiles) {
            $tokens = $null
            $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0 -Because "Parse errors in $($file.FullName)"
        }
    }

    It 'contains required governance and safety documentation' {
        @(
            'CHANGELOG.md'
            'CODE_OF_CONDUCT.md'
            'docs/safe-operation.md'
            'docs/threat-model.md'
            'docs/sample-report.md'
        ) | ForEach-Object {
            Test-Path (Join-Path $script:Root $_) | Should -BeTrue -Because "$_ must exist"
        }
    }

    It 'contains sector-specific documentation for each scanner' {
        foreach ($sector in $script:Sectors) {
            Test-Path (Join-Path $script:Root 'docs' 'sectors' $sector 'threat-model.md') | Should -BeTrue -Because "$sector threat-model.md must exist"
            Test-Path (Join-Path $script:Root 'docs' 'sectors' $sector 'sample-report.md') | Should -BeTrue -Because "$sector sample-report.md must exist"
        }
    }

    It 'states that use requires authorization' {
        (Get-Content (Join-Path $script:Root 'README.md') -Raw) | Should -Match '(?i)authorized|permission'
    }
}
