BeforeAll {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $path = Join-Path $root 'extensions\scanner\scripts\Invoke-ScannerAdLab.ps1'
    $script:source = Get-Content -LiteralPath $path -Raw
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
    if ($errors) { throw 'AD lab script failed to parse.' }
    foreach ($name in 'ConvertTo-LabSecureString', 'Get-LabRandomPassword', 'Assert-DiscoveryJob') {
        $definition = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
        . ([scriptblock]::Create($definition.Extent.Text))
    }
    function Get-ScannerContentScan { }
}

Describe 'AD lab security and scan contract' {
    It 'uses strong random secrets and secure-string conversion without literal credentials' {
        $password = Get-LabRandomPassword
        $password.Length | Should -BeGreaterThan 40
        $password | Should -Not -Be (Get-LabRandomPassword)
        $credential = [pscredential]::new('test', (ConvertTo-LabSecureString $password))
        $credential.GetNetworkCredential().Password | Should -Be $password
        $source | Should -Match 'Protect-CmsMessage'
        $source | Should -Match 'Unprotect-CmsMessage'
        $source | Should -Match 'DataProtectionScope\]::LocalMachine'
        $source | Should -Match 'KeyExportPolicy NonExportable'
    }

    It 'requires explicit safe discovery switches before starting a scan' {
        Mock Get-ScannerContentScan {
            [pscustomobject]@{ Enforce='Off'; LabelFilesByContent='On'; RelabelFiles='Off'; EnforceDefaultLabel='Off' }
        }
        { Assert-DiscoveryJob } | Should -Not -Throw
        Mock Get-ScannerContentScan {
            [pscustomobject]@{ Enforce=$false; LabelFilesByContent=$true; RelabelFiles=$false; EnforceDefaultLabel=$false }
        }
        { Assert-DiscoveryJob } | Should -Not -Throw
        Mock Get-ScannerContentScan {
            [pscustomobject]@{ Enforce=$null; LabelFilesByContent=$true; RelabelFiles=$false; EnforceDefaultLabel=$false }
        }
        { Assert-DiscoveryJob } | Should -Throw '*must be Off*'
        Mock Get-ScannerContentScan {
            [pscustomobject]@{ Enforce=$false; LabelFilesByContent=$false; RelabelFiles=$false; EnforceDefaultLabel=$false }
        }
        { Assert-DiscoveryJob } | Should -Throw '*content inspection*'
        Mock Get-ScannerContentScan {
            [pscustomobject]@{ Enforce=$false; LabelFilesByContent=$null; RelabelFiles=$false; EnforceDefaultLabel=$false }
        }
        { Assert-DiscoveryJob } | Should -Throw '*content inspection*'
        Mock Get-ScannerContentScan { [pscustomobject]@{ Enforce='On' } }
        { Assert-DiscoveryJob } | Should -Throw '*must be Off*'
        Mock Get-ScannerContentScan { }
        { Assert-DiscoveryJob } | Should -Throw '*one configured*'
    }

    It 'guards promotion and uses a separate disk and AES256 storage identity' {
        $source | Should -Match "LUN 0"
        $source | Should -Match "FileSystemLabel -ne 'AD-Lab-Data'"
        $source | Should -Match "DatabasePath 'F:\\NTDS'"
        $source | Should -Match 'KerberosEncryptionType AES256'
        $source | Should -Not -Match 'Connect-AzAccount|cmdkey|net use'
    }

    It 'cleans temporary administrator membership and tasks even on worker failure' {
        $source | Should -Match '(?s)finally \{.*Stop-ScheduledTask.*Unregister-ScheduledTask.*finally \{.*Remove-LocalGroupMember'
        $source | Should -Match "Set-ScannerDatabase.*-ServiceUserCredentials"
        $source | Should -Match "Set-ScannerConfiguration -OnlineConfiguration Off"
    }

    It 'requires fresh report coverage of every UNC file rather than idle status' {
        $source | Should -Match "Start-Scan -Reset -Force"
        $source | Should -Match 'LastWriteTimeUtc -ge \$started'
        $source | Should -Match '''File Name'' -ieq \$file.FullName'
        $source | Should -Match "Status -ne 'Success'"
        $source | Should -Match 'ExpectedDetectionsValidated = \$false'
        $source | Should -Match '\[IO.File\]::ReadAllText\(\$summaries\[0\].FullName\)'
        $source | Should -Match 'Scan ended at:'
        $source | Should -Match 'StopExistingScan -ne ''On'''
        $source | Should -Match 'discoveryComplete=\$false'
        $source | Should -Match 'Persisted report predates the requested scan'
        $source | Should -Match '-DiscoverInformationTypes All -EnableDlp Off -LabelFilesByContent On'
        $source | Should -Match 'Start-ScannerDiagnostics -ResetConfig -OnBehalfOf'
    }

    It 'uses protected read-only fixture ACLs and validates actual service-account access' {
        $source | Should -Match "'x-ms-file-request-intent' = 'backup'"
        $source | Should -Match 'D:P\(A;'
        $source | Should -Match '0x1200a9'
        $source | Should -Match "files-acl-inventory.json"
        $source | Should -Match 'path outside the approved fixture repository'
        $source | Should -Match 'AreAccessRulesProtected'
        $source | Should -Match 'OpenRead\(\$file.FullName\)'
        $source | Should -Match 'ScannerWriteDenied = \$writeDenied'
        $source | Should -Match 'RestrictiveAclsValidated = \$true'
    }

    It 'cleans only newly created FilesREST roles and uses the data-plane share scope' {
        $helper = Get-Content (Join-Path $root 'extensions\scanner\scripts\Set-ScannerAdLabFilePermissions.ps1') -Raw
        $helper | Should -Match 'fileServices/default/fileshares/'
        $helper | Should -Match 'Storage File Data Privileged Contributor'
        $helper | Should -Match '--include-inherited'
        $helper | Should -Match '(?s)finally \{.*if \(\$createdAssignment\).*role assignment delete'
        $helper | Should -Match 'FilesREST ACL guest failure'
    }
}
