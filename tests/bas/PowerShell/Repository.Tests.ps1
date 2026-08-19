BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
}

Describe 'BAS Guardian scanner' {
    It 'contains the BAS Guardian PowerShell scanner' {
        $files = @(Get-ChildItem -Path (Join-Path $script:Root 'scanners' 'bas') -Filter '*.ps1' -Recurse)
        $files.Count | Should -BeGreaterThan 0
    }

    It 'has PowerShell scanner files that parse without errors' {
        $files = @(Get-ChildItem -Path (Join-Path $script:Root 'scanners' 'bas') -Filter '*.ps1' -Recurse)
        foreach ($file in $files) {
            $tokens = $null
            $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0 -Because "Parse errors found in $($file.Name)"
        }
    }

    It 'contains BAS sector documentation' {
        @(
            'docs/sectors/bas/CISA-Reference.md'
            'docs/sectors/bas/Threat-Intelligence.md'
            'docs/sectors/bas/threat-model.md'
            'docs/sectors/bas/sample-report.md'
        ) | ForEach-Object {
            Test-Path (Join-Path $script:Root $_) | Should -BeTrue -Because "$_ must exist"
        }
    }
}
