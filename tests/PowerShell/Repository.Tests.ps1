BeforeAll {
    $Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $Scripts = Get-ChildItem -Path (Join-Path $Root 'scripts') -Filter '*.ps1' -Recurse
}

Describe 'Water Utility Protector repository' {
    It 'contains at least one PowerShell scanner file' {
        $Scripts.Count | Should -BeGreaterThan 0
    }

    It 'has PowerShell scanner files that parse without errors' -ForEach $Scripts {
        $tokens = $null
        $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It 'contains required governance and safety documentation' {
        @('CHANGELOG.md','CODE_OF_CONDUCT.md','docs/safe-operation.md','docs/threat-model.md','docs/sample-report.md') | ForEach-Object {
            Test-Path (Join-Path $Root $_) | Should -BeTrue
        }
    }

    It 'states that use requires authorization' {
        (Get-Content (Join-Path $Root 'README.md') -Raw) | Should -Match '(?i)authorized|permission'
    }
}
