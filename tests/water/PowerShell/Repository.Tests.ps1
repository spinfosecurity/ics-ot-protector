BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $script:ScriptFiles = @(Get-ChildItem -Path (Join-Path $script:Root 'scanners' 'water') -Filter '*.ps1' -Recurse)
}

Describe 'Water Utility Protector scanner' {
    It 'contains the WUP-WUP PowerShell scanner' {
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

    It 'contains water sector documentation' {
        @(
            'docs/sectors/water/CISA-Reference.md'
            'docs/sectors/water/Threat-Intelligence.md'
            'docs/sectors/water/threat-model.md'
            'docs/sectors/water/sample-report.md'
        ) | ForEach-Object {
            Test-Path (Join-Path $script:Root $_) | Should -BeTrue -Because "$_ must exist"
        }
    }
}
