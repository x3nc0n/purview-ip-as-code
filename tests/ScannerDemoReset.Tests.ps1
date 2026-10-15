BeforeAll {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $reset = Join-Path $root 'extensions\scanner\scripts\Reset-ScannerDemoFiles.ps1'
    $worker = Join-Path $root 'extensions\scanner\scripts\Reset-ScannerDemoFilesWorker.ps1'
    $archivePath = Join-Path $TestDrive 'pristine.zip'
    git -C $root archive --format=zip "--output=$archivePath" HEAD -- demo/content/generated demo/manifests/fixtures.json
    if ($LASTEXITCODE -ne 0) { throw 'Test fixture packaging failed.' }
    $arguments = @{
        StorageAccountName = 'stscannerdemod12f'; ShareName = 'scanner-demo'
        IdentityClientId = 'test-identity'
        ArchiveBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($archivePath))
        ArchiveSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
        SourceCommit = ('a' * 40)
    }
    function Get-ScanStatus {}
    function Get-ScannerContentScan {}
    function az {
        param([string]$o, [Parameter(ValueFromRemainingArguments)][string[]]$Arguments)
    }
}

Describe 'Repeatable private scanner demo reset' {
    BeforeEach {
        $originalProgramData = $env:ProgramData
        $originalModulePath = $env:PSModulePath
        $env:ProgramData = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path (Join-Path $env:ProgramData 'PurviewIPAsCode'), (Join-Path $env:ProgramData 'PurviewIPAsCode-AdLab') -Force | Out-Null
        @{
            repositoryPath = '\\stscannerdemod12f.file.core.windows.net\scanner-demo\fixtures'
            discoveryComplete = $true; readyForEnforcement = $false
        } | ConvertTo-Json | Set-Content (Join-Path $env:ProgramData 'PurviewIPAsCode\readiness.json')
        'old-evidence' | Set-Content (Join-Path $env:ProgramData 'PurviewIPAsCode-AdLab\scan-result.json')
        'old-enforcement' | Set-Content (Join-Path $env:ProgramData 'PurviewIPAsCode-AdLab\enforcement-result.json')
        $global:DemoResetFakeState = @{
            Files = @{ 'old-labeled.docx' = [byte[]](1, 2, 3); 'old-protected.pfile' = [byte[]](4, 5) }
            HasSubdirectory = $false; FailUpload = $false; GuestScriptPath = $null; ListingEncoding = 'Text'
        }
        Mock Start-Sleep {}
        Mock az {
            param($Arguments, $o)
            $global:LASTEXITCODE = 0
            $command = $Arguments -join ' '
            if ($command -match '^vm identity show ') {
                return '{"userAssignedIdentities":{"identity":{"clientId":"ee77d47c-820d-487c-8503-b28ac881f054","principalId":"f95657be-3e10-442f-b339-861a7a6b5913"}}}'
            }
            if ($command -match '^role assignment list ') { return '[]' }
            if ($command -match '^role assignment create ') { return '/test/roleAssignments/reset-only' }
            if ($command -match '^role assignment delete ') { return }
            if ($command -match '^vm run-command invoke ') {
                $index = [array]::IndexOf($Arguments, '--scripts')
                $path = $Arguments[$index + 1].Substring(1)
                $global:DemoResetFakeState.GuestScriptPath = $path
                $output = & $path
                return (@{ value = @(
                    @{ code = 'ComponentStatus/StdOut/succeeded'; message = ($output -join "`n") }
                    @{ code = 'ComponentStatus/StdErr/succeeded'; message = '' }
                ) } | ConvertTo-Json -Depth 5)
            }
            throw "Unexpected Azure command: $command"
        }
        Mock Import-Module {} -ParameterFilter { $Name -eq 'PurviewInformationProtection' }
        Mock Get-ScanStatus { [pscustomobject]@{ ClusterStatus = 'Idle' } }
        Mock Get-ScannerContentScan { [pscustomobject]@{ Schedule = 'Manual' } }
        Mock Get-Service { [pscustomobject]@{ Status = 'Running' } } -ParameterFilter { $Name -eq 'MIPScanner' }
        Mock Stop-Service {}
        Mock Start-Service {}
        Mock Invoke-RestMethod { [pscustomobject]@{ access_token = 'test-token' } }
        Mock Invoke-WebRequest {
            param($Uri, $Method, $Headers, $Body)
            if ($Uri -match '\?restype=directory&comp=list') {
                $entries = @($global:DemoResetFakeState.Files.Keys | ForEach-Object { "<File><Name>$_</Name></File>" }) -join ''
                if ($global:DemoResetFakeState.HasSubdirectory) { $entries += '<Directory><Name>do-not-delete</Name></Directory>' }
                $xml = "<EnumerationResults><Entries>$entries</Entries><NextMarker /></EnumerationResults>"
                $content = switch ($global:DemoResetFakeState.ListingEncoding) {
                    'Bom' { [string][char]0xfeff + $xml }
                    'Bytes' { ,([Text.Encoding]::UTF8.GetPreamble() + [Text.Encoding]::UTF8.GetBytes($xml)) }
                    default { $xml }
                }
                $bytes = if ($global:DemoResetFakeState.ListingEncoding -eq 'Text') {
                    [Text.Encoding]::UTF8.GetBytes($xml)
                } else { [byte[]]([Text.Encoding]::UTF8.GetPreamble() + [Text.Encoding]::UTF8.GetBytes($xml)) }
                return [pscustomobject]@{ Content = $content; RawContentStream = [IO.MemoryStream]::new([byte[]]$bytes, $false) }
            }
            if ($Uri -notmatch '^https://stscannerdemod12f\.file\.core\.windows\.net/scanner-demo/fixtures/([^?]+)(\?comp=range)?$') {
                throw "Out-of-scope REST request: $Uri"
            }
            $name = [uri]::UnescapeDataString($Matches[1])
            if ($Method -eq 'Delete') { $global:DemoResetFakeState.Files.Remove($name); return }
            if ($Method -eq 'Put') {
                if ($global:DemoResetFakeState.FailUpload) { throw 'Intentional upload failure.' }
                if ($Uri -match '\?comp=range') { $global:DemoResetFakeState.Files[$name] = [byte[]]$Body }
                else {
                    if ($Headers['x-ms-file-permission'] -ne 'inherit') { throw 'File ACLs must inherit.' }
                    $global:DemoResetFakeState.Files[$name] = New-Object byte[] ([int]$Headers['x-ms-content-length'])
                }
                return
            }
            return [pscustomobject]@{ RawContentStream = [IO.MemoryStream]::new([byte[]]$global:DemoResetFakeState.Files[$name], $false) }
        }
    }

    AfterEach {
        $env:ProgramData = $originalProgramData
        $env:PSModulePath = $originalModulePath
        Remove-Variable DemoResetFakeState -Scope Global -ErrorAction SilentlyContinue
    }

    It 'is plan-only unless Apply is supplied' {
        $plan = & $reset
        $plan.Action | Should -Match 'Plan only'
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
        Should -Invoke Stop-Service -Times 0 -Exactly
        Should -Invoke az -Times 0 -Exactly
    }

    It 'honors WhatIf before temporary permissions or guest invocation' {
        & $reset -Apply -WhatIf
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
        Should -Invoke Stop-Service -Times 0 -Exactly
        Should -Invoke az -Times 0 -Exactly
    }

    It 'packages the payload in a script file and removes temporary privilege and artifacts after success' {
        $result = & $reset -Apply -Confirm:$false
        $result.ResetComplete | Should -BeTrue
        $result.VerifiedFiles | Should -Be 29
        Test-Path -LiteralPath $global:DemoResetFakeState.GuestScriptPath | Should -BeFalse
        Test-Path -LiteralPath ([IO.Path]::ChangeExtension($global:DemoResetFakeState.GuestScriptPath, '.zip')) | Should -BeFalse
        Should -Invoke az -ParameterFilter { ($Arguments -join ' ') -match '^role assignment delete .*reset-only' } -Times 1 -Exactly
    }

    It 'removes only its temporary role and artifacts when the guest fails' {
        $global:DemoResetFakeState.FailUpload = $true
        { & $reset -Apply -Confirm:$false } | Should -Throw '*Intentional upload failure*'
        Test-Path -LiteralPath $global:DemoResetFakeState.GuestScriptPath | Should -BeFalse
        Should -Invoke az -ParameterFilter { ($Arguments -join ' ') -match '^role assignment delete .*reset-only' } -Times 1 -Exactly
    }

    It 'deletes old labeled files, restores and verifies pristine bytes, and invalidates stale evidence' {
        $result = & $worker @arguments -Confirm:$false | ConvertFrom-Json
        $result.ResetComplete | Should -BeTrue
        $result.VerifiedFiles | Should -Be 29
        $result.DeletedFiles | Should -Be 2
        $global:DemoResetFakeState.Files.Count | Should -Be 29
        $global:DemoResetFakeState.Files.ContainsKey('old-protected.pfile') | Should -BeFalse
        Test-Path (Join-Path $env:ProgramData 'PurviewIPAsCode-AdLab\scan-result.json') | Should -BeFalse
        Test-Path (Join-Path $env:ProgramData 'PurviewIPAsCode-AdLab\enforcement-result.json') | Should -BeFalse
        $readiness = Get-Content (Join-Path $env:ProgramData 'PurviewIPAsCode\readiness.json') -Raw | ConvertFrom-Json
        $readiness.discoveryComplete | Should -BeFalse
        Should -Invoke Stop-Service -Times 1 -Exactly
        Should -Invoke Start-Service -Times 1 -Exactly
    }

    It 'refuses subdirectories without deleting anything or stopping the service' {
        $global:DemoResetFakeState.HasSubdirectory = $true
        { & $worker @arguments -Confirm:$false } | Should -Throw '*subdirectory*'
        Should -Invoke Invoke-WebRequest -ParameterFilter { $Method -eq 'Delete' } -Times 0 -Exactly
        Should -Invoke Stop-Service -Times 0 -Exactly
    }

    It 'accepts a UTF8 BOM directory listing before restoring files' {
        $global:DemoResetFakeState.ListingEncoding = 'Bom'
        $result = & $worker @arguments -Confirm:$false | ConvertFrom-Json
        $result.ResetComplete | Should -BeTrue
        $result.VerifiedFiles | Should -Be 29
    }

    It 'accepts a byte-array directory listing with a UTF8 BOM' {
        $global:DemoResetFakeState.ListingEncoding = 'Bytes'
        $result = & $worker @arguments -Confirm:$false | ConvertFrom-Json
        $result.ResetComplete | Should -BeTrue
        $result.VerifiedFiles | Should -Be 29
    }

    It 'refuses an active scan before touching the share' {
        Mock Get-ScanStatus { [pscustomobject]@{ ClusterStatus = 'Scanning' } }
        { & $worker @arguments -Confirm:$false } | Should -Throw '*scan to finish*'
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }

    It 'refuses a scheduled job that could immediately label the restored files' {
        Mock Get-ScannerContentScan { [pscustomobject]@{ Schedule = 'Always' } }
        { & $worker @arguments -Confirm:$false } | Should -Throw '*schedule to Manual*'
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }

    It 'restarts the scanner and surfaces upload errors without reporting success' {
        $global:DemoResetFakeState.FailUpload = $true
        { & $worker @arguments -Confirm:$false } | Should -Throw '*Intentional upload failure*'
        Should -Invoke Start-Service -Times 1 -Exactly
        Test-Path (Join-Path $env:ProgramData 'PurviewIPAsCode-AdLab\demo-reset.json') | Should -BeFalse
    }

    It 'refuses a tampered archive before touching the scanner or share' {
        $invalid = $arguments.Clone()
        $invalid.ArchiveSha256 = ('0' * 64)
        { & $worker @invalid -Confirm:$false } | Should -Throw '*checksum mismatch*'
        Should -Invoke Stop-Service -Times 0 -Exactly
        Should -Invoke Invoke-WebRequest -Times 0 -Exactly
    }
}
