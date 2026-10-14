BeforeAll {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $verifier = Join-Path $root 'extensions\scanner\scripts\Test-ScannerBcsiDetection.ps1'
}

Describe 'Native BCSI report verification' {
    BeforeEach {
        $labelId = '11111111-1111-4111-8111-111111111111'
        $reportPath = Join-Path $TestDrive 'report.csv'
        $resultPath = Join-Path $TestDrive 'result.json'
        $rows = @(
            foreach ($fixture in @(
                @{ Name = 'bcsi-explicit'; Sit = 'BCSI Explicit Designation' }
                @{ Name = 'bcsi-network'; Sit = 'BCSI Network and Security Configuration' }
                @{ Name = 'bcsi-access'; Sit = 'BCSI Access and Security Procedures' }
            )) {
                foreach ($extension in @('txt', 'docx', 'pdf')) {
                    [pscustomobject]@{
                        'File Name' = "C:\fixtures\$($fixture.Name).$extension"
                        Status = 'Success'
                        'Information Type Name' = $fixture.Sit
                        'Condition Name' = $fixture.Sit
                        'Applied Label' = 'BES'
                        'Applied Label ID' = $labelId
                    }
                }
            }
        )
        $rows | Export-Csv -LiteralPath $reportPath -NoTypeInformation
        @{
            EnforcementEnabled = $false
            ScannerWriteDenied = $true
            DetailedReportPath = $reportPath
            FixtureCount = 9
            ScanEndedAtUtc = [datetime]::UtcNow.ToString('o')
        } | ConvertTo-Json | Set-Content -LiteralPath $resultPath
    }

    It 'requires native SIT matches and BES proposals for all nine positive fixtures' {
        $evidencePath = Join-Path $TestDrive 'evidence.json'
        $output = & $verifier -ScanResultPath $resultPath -BesLabelId $labelId -EvidencePath $evidencePath | ConvertFrom-Json
        $output.BcsiDetectionsValidated | Should -BeTrue
        $output.BcsiPositiveCount | Should -Be 9
        $output.LabelWritesValidated | Should -BeFalse
        ([IO.File]::ReadAllText($evidencePath) | ConvertFrom-Json).BcsiDetectionsValidated | Should -BeTrue
    }

    It 'rejects successful scans that only propose General' {
        $rows[0].'Information Type Name' = ''
        $rows[0].'Applied Label' = 'General'
        $rows[0].'Applied Label ID' = ''
        $rows | Export-Csv -LiteralPath $reportPath -NoTypeInformation
        { & $verifier -ScanResultPath $resultPath -BesLabelId $labelId } | Should -Throw '*not observed*'
    }

    It 'rejects incomplete or failed reports' {
        $rows[0].Status = 'Failure'
        $rows | Export-Csv -LiteralPath $reportPath -NoTypeInformation
        { & $verifier -ScanResultPath $resultPath -BesLabelId $labelId } | Should -Throw '*successfully*'
    }
}
