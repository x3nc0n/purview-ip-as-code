BeforeAll {
    $repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $bootstrapPath = Join-Path $repositoryRoot 'extensions\scanner\scripts\Invoke-LabBootstrap.ps1'
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($bootstrapPath, [ref]$null, [ref]$null)
    foreach ($name in @('Get-CompletedScannerReport', 'Assert-DiscoveryContentScan')) {
        $definition = $ast.Find({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true)
        . ([scriptblock]::Create($definition.Extent.Text))
    }
}

Describe 'Report-backed scanner readiness' {
    BeforeEach {
        $reports = Join-Path $TestDrive ([guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $reports | Out-Null
        $start = [datetime]::UtcNow.AddMinutes(-1)
        $fixturePaths = @('C:\PurviewScannerDemo\fixtures\a.txt', 'C:\PurviewScannerDemo\fixtures\b.docx')
        $summaryPath = Join-Path $reports 'Summary_test.txt'
        $detailPath = Join-Path $reports 'DetailedReport_test.csv'
    }

    It 'does not accept idle time without reports' {
        Get-CompletedScannerReport -ReportDirectory $reports -StartedAtUtc $start -FixturePaths $fixturePaths | Should -BeNullOrEmpty
    }

    It 'requires a fresh summary and detailed coverage of every fixture' {
        Set-Content -LiteralPath $summaryPath -Value "Scanned files:2`nFailed:0"
        @(
            [pscustomobject]@{'File Name' = $fixturePaths[0]; Status = 'Success'}
            [pscustomobject]@{'File Name' = $fixturePaths[1]; Status = 'Success'}
        ) | Export-Csv -LiteralPath $detailPath -NoTypeInformation
        $report = Get-CompletedScannerReport -ReportDirectory $reports -StartedAtUtc $start -FixturePaths $fixturePaths
        $report.ScannedFileCount | Should -Be 2
        $report.SummaryPath | Should -Be $summaryPath
        (Get-Item $summaryPath).LastWriteTimeUtc = $start.AddMinutes(-1)
        Get-CompletedScannerReport -ReportDirectory $reports -StartedAtUtc $start -FixturePaths $fixturePaths | Should -BeNullOrEmpty
    }

    It 'rejects missing fixtures and failed scan outcomes' {
        Set-Content -LiteralPath $summaryPath -Value "Scanned files:1`nFailed:0"
        [pscustomobject]@{'File Name' = $fixturePaths[0]; Status = 'Success'} | Export-Csv -LiteralPath $detailPath -NoTypeInformation
        Get-CompletedScannerReport -ReportDirectory $reports -StartedAtUtc $start -FixturePaths $fixturePaths | Should -BeNullOrEmpty
        Set-Content -LiteralPath $summaryPath -Value "Scanned files:2`nFailed:1"
        { Get-CompletedScannerReport -ReportDirectory $reports -StartedAtUtc $start -FixturePaths $fixturePaths } | Should -Throw '*failed files*'
    }

    It 'rejects a failed detail row even when the summary claims no failures' {
        Set-Content -LiteralPath $summaryPath -Value "Scanned files:2`nFailed:0"
        @(
            [pscustomobject]@{'File Name' = $fixturePaths[0]; Status = 'Success'}
            [pscustomobject]@{'File Name' = $fixturePaths[1]; Status = 'Failure'}
        ) | Export-Csv -LiteralPath $detailPath -NoTypeInformation
        { Get-CompletedScannerReport -ReportDirectory $reports -StartedAtUtc $start -FixturePaths $fixturePaths } | Should -Throw '*not scanned successfully*'
    }

    It 'requires explicit safe portal job switches' {
        $job = [pscustomobject]@{Enforce = 'Off'; LabelFilesByContent = 'Off'; RelabelFiles = 'Off'; EnforceDefaultLabel = 'Off'}
        { Assert-DiscoveryContentScan -ContentScan $job } | Should -Not -Throw
        { Assert-DiscoveryContentScan -ContentScan @($job, 'Repositories:', @()) } | Should -Not -Throw
        $job.Enforce = ''
        { Assert-DiscoveryContentScan -ContentScan $job } | Should -Throw '*Enforce*Off*'
        $job.Enforce = 'On'
        { Assert-DiscoveryContentScan -ContentScan $job } | Should -Throw '*Enforce*Off*'
    }
}

Describe 'Scanner beta release contract' {
    It 'requires a portal cluster and makes offline configuration opt-in' {
        $main = Get-Content (Join-Path $repositoryRoot 'extensions\scanner\infra\main.bicep') -Raw
        $main | Should -Match 'param scannerClusterName string'
        $main | Should -Match "param scannerConfigurationMode string = 'Online'"
        $main | Should -Not -Match 'storageKeyRole'
        $bootstrap = Get-Content -LiteralPath $bootstrapPath -Raw
        $bootstrap | Should -Match 'Set-ScannerDatabase.*-Cluster \$ClusterName'
        $bootstrap | Should -Match "if \(\`$ConfigurationMode -eq 'Offline'\)"
        $bootstrap | Should -Not -Match 'TotalMinutes -ge 5'
        $bootstrap | Should -Match 'Remove-LocalGroupMember'
    }

    It 'builds reproducible fixture archives containing only fixtures and manifest' {
        $builder = Join-Path $repositoryRoot 'extensions\scanner\scripts\New-ScannerReleaseAssets.ps1'
        $first = Join-Path $TestDrive 'release-first'
        $second = Join-Path $TestDrive 'release-second'
        & $builder -OutputDirectory $first | Out-Null
        & $builder -OutputDirectory $second | Out-Null
        $firstHash = (Get-FileHash (Join-Path $first 'demo-content.zip')).Hash
        $firstHash | Should -Be (Get-FileHash (Join-Path $second 'demo-content.zip')).Hash
        $archive = [System.IO.Compression.ZipFile]::OpenRead((Join-Path $first 'demo-content.zip'))
        try {
            @($archive.Entries | Where-Object { $_.FullName -ne 'fixtures.json' -and -not $_.FullName.StartsWith('generated/') }).Count | Should -Be 0
            @($archive.Entries | Where-Object FullName -eq 'fixtures.json').Count | Should -Be 1
            $expectedCount = @(Get-ChildItem (Join-Path $repositoryRoot 'demo\content\generated') -File -Recurse).Count + 1
            $archive.Entries.Count | Should -Be $expectedCount
        }
        finally { $archive.Dispose() }
        foreach ($line in (Get-Content (Join-Path $first 'SHA256SUMS.txt'))) {
            $hash, $name = $line -split '\s+', 2
            (Get-FileHash (Join-Path $first $name)).Hash.ToLowerInvariant() | Should -Be $hash
        }
    }
}
