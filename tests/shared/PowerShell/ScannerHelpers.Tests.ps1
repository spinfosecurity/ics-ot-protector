BeforeAll {
    $script:Root = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
    . (Join-Path $script:Root 'scanners' '_shared' 'ScannerHelpers.ps1')
}

Describe 'Get-NetworkPrefix' {
    It 'extracts the first three octets from a /24 CIDR' {
        Get-NetworkPrefix -Cidr '192.168.10.0/24' | Should -Be '192.168.10'
    }

    It 'works for other /24 subnets' {
        Get-NetworkPrefix -Cidr '10.0.1.0/24' | Should -Be '10.0.1'
    }
}

Describe 'Get-SubnetHosts' {
    It 'returns 254 hosts for a /24 subnet' {
        (Get-SubnetHosts -CidrSubnet '172.16.5.0/24').Count | Should -Be 254
    }
}
