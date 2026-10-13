BeforeAll {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $scriptPath = Join-Path $root 'extensions\scanner\scripts\Test-ScannerFileConnectivity.ps1'
    function global:Resolve-DnsName {
        [CmdletBinding()]
        param([string]$Name, [string]$Type, [switch]$DnsOnly)
    }
    function global:Test-NetConnection {
        [CmdletBinding()]
        param([string]$ComputerName, [int]$Port)
    }
}

Describe 'Scanner private file connectivity' {
    BeforeEach {
        Mock Resolve-DnsName { [pscustomobject]@{ Type = 'A'; IPAddress = '10.40.2.6' } }
        Mock Test-NetConnection {
            [pscustomobject]@{ TcpTestSucceeded = $true; RemoteAddress = [System.Net.IPAddress]::Parse('10.40.2.6') }
        }
    }
    It 'verifies exact private DNS and TCP without claiming SMB authentication' {
        $result = & $scriptPath -StorageAccountName 'demostorage' -ExpectedPrivateEndpointIp '10.40.2.6'
        $result.DnsVerified | Should -BeTrue
        $result.Tcp445Verified | Should -BeTrue
        $result.AuthenticatedSmbVerified | Should -BeFalse
        Should -Invoke Test-NetConnection -Times 1 -ParameterFilter { $ComputerName -eq 'demostorage.file.core.windows.net' -and $Port -eq 445 }
    }
    It 'rejects a public expected endpoint' {
        { & $scriptPath -StorageAccountName 'demostorage' -ExpectedPrivateEndpointIp '8.8.8.8' } | Should -Throw '*must be private*'
        Should -Invoke Resolve-DnsName -Times 0
    }
    It 'rejects DNS resolving to the wrong private endpoint' {
        { & $scriptPath -StorageAccountName 'demostorage' -ExpectedPrivateEndpointIp '10.40.2.7' } | Should -Throw '*not the expected*'
        Should -Invoke Test-NetConnection -Times 0
    }
    It 'rejects mixed private and public DNS answers' {
        Mock Resolve-DnsName {
            [pscustomobject]@{ Type = 'A'; IPAddress = '10.40.2.6' }
            [pscustomobject]@{ Type = 'A'; IPAddress = '8.8.8.8' }
        }
        { & $scriptPath -StorageAccountName 'demostorage' -ExpectedPrivateEndpointIp '10.40.2.6' } | Should -Throw '*not the expected*'
    }
    It 'surfaces DNS resolution failures' {
        Mock Resolve-DnsName { throw 'DNS failed.' }
        { & $scriptPath -StorageAccountName 'demostorage' -ExpectedPrivateEndpointIp '10.40.2.6' } | Should -Throw '*DNS failed*'
    }
    It 'fails when TCP 445 is unreachable' {
        Mock Test-NetConnection {
            [pscustomobject]@{ TcpTestSucceeded = $false; RemoteAddress = [System.Net.IPAddress]::Parse('10.40.2.6') }
        }
        { & $scriptPath -StorageAccountName 'demostorage' -ExpectedPrivateEndpointIp '10.40.2.6' } | Should -Throw '*TCP 445*failed*'
    }
}

AfterAll {
    Remove-Item Function:\global:Resolve-DnsName, Function:\global:Test-NetConnection -ErrorAction SilentlyContinue
}
