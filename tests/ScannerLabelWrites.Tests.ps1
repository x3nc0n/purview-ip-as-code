BeforeAll {
    $verifier = Join-Path $PSScriptRoot '..\extensions\scanner\scripts\Test-ScannerLabelWrites.ps1'
    $besId = '2631698b-e361-4800-b826-224d5c297cce'
    $lowId = '00000000-0000-0000-0000-000000000003'
    $highId = '00000000-0000-0000-0000-000000000004'
    $publishing = Join-Path $PSScriptRoot '..\extensions\scanner\scripts\Set-ScannerPublishingSettings.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($publishing, [ref]$null, [ref]$null)
    $parser = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'ConvertFrom-ScannerPolicySettingMap'
    }, $true)
    . ([scriptblock]::Create($parser.Extent.Text))
}

Describe 'Scanner publishing settings read-back' {
    It 'accepts REST string pairs without truncating nested extension JSON' {
        $settings = ConvertFrom-ScannerPolicySettingMap @('[enableaudit, True]', '[pfilesupportedextensions, [".txt"]]')
        $settings.EnableAudit | Should -Be 'True'
        $settings.PFileSupportedExtensions | Should -Be '[".txt"]'
    }

    It 'accepts key/value objects and rejects unknown serialization' {
        (ConvertFrom-ScannerPolicySettingMap @([pscustomobject]@{ Key='EnableAudit'; Value='True' })).EnableAudit | Should -Be 'True'
        { ConvertFrom-ScannerPolicySettingMap @('EnableAudit=True') } | Should -Throw '*Unrecognized*'
        { ConvertFrom-ScannerPolicySettingMap @([pscustomobject]@{ Unknown='True' }) } | Should -Throw '*Unsupported*'
    }
}

Describe 'Persisted scanner label verification' {
    BeforeEach {
        $reportPath = Join-Path $TestDrive 'detailed.csv'
        $statusPath = Join-Path $TestDrive 'status.json'
        $resultPath = Join-Path $TestDrive 'result.json'
        $rows = @()
        $statuses = @()
        foreach ($base in 'bcsi-explicit', 'bcsi-network', 'bcsi-access') {
            foreach ($extension in 'txt', 'docx', 'pdf') {
                $name = "$base.$extension"
                $rows += [pscustomobject]@{ 'File Name'=$name; Status='Success'; 'Applied Label ID'=$besId }
                $actual = if ($extension -eq 'txt') { "$base.ptxt" } else { $name }
                $statuses += [pscustomobject]@{
                    FileName=$actual; IsLabeled=$true; IsRMSProtected=$true
                    MainLabelId='00000000-0000-0000-0000-000000000001'; SubLabelId=$besId
                }
            }
        }
        foreach ($name in 'control-public-standard.txt', 'control-isolated-address.txt', 'control-generic-scada.txt', 'control-generic-credential.txt') {
            $rows += [pscustomobject]@{
                'File Name'=$name; Status='Skipped'; Comment='No label or action to apply'; 'Applied Label ID'=''
            }
            $statuses += [pscustomobject]@{
                FileName=$name; IsLabeled=$false; IsRMSProtected=$false
                MainLabelId=[guid]::Empty; SubLabelId=[guid]::Empty
            }
        }
        foreach ($base in 'pii-spo-1','pii-spo-198','pii-spo-199','pii-spo-200','pii-spo-201','pii-spo-250','pii-exchange-200') {
            $id = if ($base -in @('pii-spo-1','pii-spo-198','pii-spo-199')) { $lowId } else { $highId }
            $formats = if ($base -in @('pii-spo-1','pii-spo-200')) { @('txt','docx','pdf') } else { @('txt') }
            foreach ($extension in $formats) {
                $actual = if ($extension -eq 'txt') { "$base.ptxt" } else { "$base.$extension" }
                $rows += [pscustomobject]@{ 'File Name'="$base.$extension"; Status='Success'; 'Applied Label ID'=$id }
                $statuses += [pscustomobject]@{
                    FileName=$actual; IsLabeled=$true; IsRMSProtected=$true
                    MainLabelId='00000000-0000-0000-0000-000000000001'; SubLabelId=$id
                }
            }
        }
        foreach ($row in $rows) {
            if ($row.PSObject.Properties.Name -notcontains 'Comment') { $row | Add-Member -NotePropertyName Comment -NotePropertyValue '' }
        }
        $result = @{
            EnforcementEnabled=$true; ScannerWriteDenied=$false; RestrictiveAclsValidated=$true
            FixtureCount=24; DetailedReportPath=$reportPath; FileStatusPath=$statusPath
            ScanEndedAtUtc='2026-10-14T23:09:26Z'; Repository='\\demo\fixtures'
        }
        $rows | Export-Csv -LiteralPath $reportPath -NoTypeInformation
        $statuses | ConvertTo-Json | Set-Content -LiteralPath $statusPath
        $result | ConvertTo-Json | Set-Content -LiteralPath $resultPath
    }

    It 'requires all nine persisted labels and encryption, including protected text names' {
        $evidence = (& $verifier -ScanResultPath $resultPath -BesLabelId $besId) | ConvertFrom-Json
        $evidence.BesWritesValidated | Should -Be 9
        $evidence.LabelWritesValidated | Should -BeTrue
        $evidence.PersistedBesProtectedCount | Should -Be 9
        $evidence.NegativeControlsValidated | Should -Be 4
    }

    It 'does not accept discovery proposals as writes' {
        $result.EnforcementEnabled = $false
        $result | ConvertTo-Json | Set-Content -LiteralPath $resultPath
        { & $verifier -ScanResultPath $resultPath -BesLabelId $besId } | Should -Throw '*not discovery proposals*'
    }

    It 'rejects metadata that has the right report label but no persisted encryption' {
        $statuses[0].IsRMSProtected = $false
        $statuses | ConvertTo-Json | Set-Content -LiteralPath $statusPath
        { & $verifier -ScanResultPath $resultPath -BesLabelId $besId } | Should -Throw '*actual persisted BES*'
    }

    It 'rejects missing persisted metadata rather than counting successful report rows' {
        $statuses[1..23] | ConvertTo-Json | Set-Content -LiteralPath $statusPath
        { & $verifier -ScanResultPath $resultPath -BesLabelId $besId } | Should -Throw '*Missing unique*'
    }

    It 'rejects failed files and report coverage gaps' {
        $rows[0].Status = 'Failed'
        $rows | Export-Csv -LiteralPath $reportPath -NoTypeInformation
        { & $verifier -ScanResultPath $resultPath -BesLabelId $besId } | Should -Throw '*cover every fixture*'
    }

    It 'rejects the wrong persisted sublabel despite a matching scan report' {
        $statuses[0].SubLabelId = '00000000-0000-0000-0000-000000000002'
        $statuses | ConvertTo-Json | Set-Content -LiteralPath $statusPath
        { & $verifier -ScanResultPath $resultPath -BesLabelId $besId } | Should -Throw '*actual persisted BES*'
    }

    It 'rejects unexpected skipped statuses rather than accepting all skipped files' {
        $rows[9].Comment = 'Access denied'
        $rows | Export-Csv -LiteralPath $reportPath -NoTypeInformation
        { & $verifier -ScanResultPath $resultPath -BesLabelId $besId } | Should -Throw '*cover every fixture*'
    }

    It 'rejects a BCSI false positive on a negative control' {
        $statuses[9].SubLabelId = $besId
        $statuses | ConvertTo-Json | Set-Content -LiteralPath $statusPath
        { & $verifier -ScanResultPath $resultPath -BesLabelId $besId } | Should -Throw '*negative control*'
    }

    It 'verifies all eleven PII persisted file tiers, including the 200-record PDF' {
        $evidence = (& $verifier -ScanResultPath $resultPath -BesLabelId $besId -ConfidentialLabelId $lowId -HighlyConfidentialLabelId $highId) | ConvertFrom-Json
        $evidence.PiiWritesValidated | Should -Be 11
        @($evidence.PiiObservations | Where-Object LabelId -eq $lowId).Count | Should -Be 5
        @($evidence.PiiObservations | Where-Object LabelId -eq $highId).Count | Should -Be 6
    }

    It 'rejects an incorrect native 200-record PDF label rather than trusting local counts' {
        ($statuses | Where-Object FileName -eq 'pii-spo-200.pdf').SubLabelId = $lowId
        $statuses | ConvertTo-Json | Set-Content -LiteralPath $statusPath
        { & $verifier -ScanResultPath $resultPath -BesLabelId $besId -ConfidentialLabelId $lowId -HighlyConfidentialLabelId $highId } | Should -Throw '*PII fixture*'
    }
}
