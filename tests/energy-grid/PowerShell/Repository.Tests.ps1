BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $script:ScriptFiles = @(Get-ChildItem -Path (Join-Path $script:Root 'scanners' 'energy-grid') -Filter '*.ps1' -Recurse)
}

Describe 'Energy Grid Protector scanner' {
    It 'contains the EGP PowerShell scanner' {
        $script:ScriptFiles.Count | Should -BeGreaterThan 0
    }

    It 'has PowerShell scanner files that parse without errors' {
        foreach ($file in $script:ScriptFiles) {
            $tokens = $null
            $errors = $null
            [void][System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            $errors.Count | Should -Be 0 -Because "Parse errors in $($file.Name)"
        }
    }

    It 'contains energy-grid sector documentation' {
        @(
            'docs/sectors/energy-grid/threat-model.md'
            'docs/sectors/energy-grid/sample-report.md'
        ) | ForEach-Object {
            Test-Path (Join-Path $script:Root $_) | Should -BeTrue -Because "$_ must exist"
        }
    }
}
