BeforeAll {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $scriptPath = Join-Path $root 'extensions\scanner\scripts\Test-ScannerSmbAuthContext.ps1'
}

Describe 'Scanner SMB authentication context preflight' {
    BeforeEach {
        Mock Get-CimInstance {
            switch ($ClassName) {
                'Win32_ComputerSystem' { [pscustomobject]@{ Name = 'scanner'; PartOfDomain = $false } }
                'Win32_Service' { [pscustomobject]@{ State = 'Running'; ProcessId = 42; StartName = '.\PurviewScannerSvc' } }
                'Win32_Process' {
                    $process = [Microsoft.Management.Infrastructure.CimInstance]::new('Win32_Process', 'root/cimv2')
                    $processId = if ($Filter -eq 'ProcessId=42') { [uint32]42 } else { [uint32]99 }
                    $process.CimInstanceProperties.Add(
                        [Microsoft.Management.Infrastructure.CimProperty]::Create('ProcessId', $processId, [Microsoft.Management.Infrastructure.CimType]::UInt32, [Microsoft.Management.Infrastructure.CimFlags]::None)
                    )
                    $process
                }
            }
        }
        Mock Get-CimAssociatedInstance {
            [pscustomobject]@{ LogonId = if ($InputObject.ProcessId -eq 42) { '12345' } else { '999' } }
        }
        Mock Write-Warning {}
    }
    It 'reports different sessions without claiming authentication was configured' {
        $result = & $scriptPath
        $result.SameLogonSession | Should -BeFalse
        $result.ScannerAccount | Should -Be '.\PurviewScannerSvc'
        $result.AuthenticationConfigured | Should -BeFalse
        $result.ChangesMade | Should -BeFalse
        $result.Status | Should -Be 'BlockedPendingServiceSessionIntegration'
        Should -Invoke Write-Warning -Times 1
    }
    It 'does not claim same-session identity proves authenticated SMB access' {
        Mock Get-CimAssociatedInstance { [pscustomobject]@{ LogonId = '12345' } }
        $result = & $scriptPath
        $result.SameLogonSession | Should -BeTrue
        $result.AuthenticationConfigured | Should -BeFalse
        $result.Status | Should -Be 'BlockedPendingServiceSessionIntegration'
    }
    It 'fails when the scanner is stopped' {
        Mock Get-CimInstance { [pscustomobject]@{ State = 'Stopped'; ProcessId = 0 } } -ParameterFilter { $ClassName -eq 'Win32_Service' }
        { & $scriptPath } | Should -Throw '*must be running*'
    }
    It 'fails on ambiguous session associations' {
        Mock Get-CimAssociatedInstance { [pscustomobject]@{ LogonId = '1' }; [pscustomobject]@{ LogonId = '2' } }
        { & $scriptPath } | Should -Throw '*unambiguously*'
    }
    It 'surfaces CIM read errors instead of assuming compatibility' {
        Mock Get-CimAssociatedInstance { throw 'Access denied.' }
        { & $scriptPath } | Should -Throw '*Access denied*'
    }
    It 'reports domain-joined clients as an additional blocker' {
        Mock Get-CimInstance { [pscustomobject]@{ Name = 'scanner'; PartOfDomain = $true } } -ParameterFilter { $ClassName -eq 'Win32_ComputerSystem' }
        $result = & $scriptPath
        $result.DomainJoined | Should -BeTrue
        ($result.Blockers -join ' ') | Should -Match 'non-domain-joined'
    }
}
