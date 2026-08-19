BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    $script:ScriptFiles = @(Get-ChildItem -Path (Join-Path $script:Root 'scanners' 'rail') -Filter '*.ps1' -Recurse)
}

Describe 'Rail-OT-Protector scanner' {
    It 'contains the ROP PowerShell scanner' {
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

    It 'contains rail sector documentation' {
        @(
            'docs/sectors/rail/CISA-Reference.md'
            'docs/sectors/rail/Threat-Intelligence.md'
            'docs/sectors/rail/threat-model.md'
            'docs/sectors/rail/sample-report.md'
        ) | ForEach-Object {
            Test-Path (Join-Path $script:Root $_) | Should -BeTrue -Because "$_ must exist"
        }
    }
}
