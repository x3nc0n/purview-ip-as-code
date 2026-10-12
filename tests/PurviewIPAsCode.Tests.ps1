BeforeAll {
    $repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    Import-Module (Join-Path $repositoryRoot 'src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
}

Describe 'Purview configuration contracts' {
    It 'validates canonical JSON definitions without requiring a tenant' {
        $result = Test-PurviewConfiguration
        $result.Valid | Should -BeTrue
        @($result.Errors).Count | Should -Be 0
        $result.Warnings | Should -Contain 'Tenant ID is a placeholder.'
    }

    It 'blocks tenant operations for the unconfigured demonstration overlay' {
        $result = Test-PurviewConfiguration -RequireTenantValues
        $result.Valid | Should -BeFalse
        $result.Errors | Should -Contain 'A real tenant ID and detected label scheme are required for tenant operations.'
    }

    It 'returns a safe deployment plan by default and blocks incomplete live apply before mutation' {
        $plan = Invoke-PurviewDeployment -EnvironmentPath 'config\environments\demo.example.json'
        $plan.Actions | Should -Not -BeNullOrEmpty
        $environment = Get-Content (Join-Path $repositoryRoot 'config\environments\demo.example.json') -Raw | ConvertFrom-Json
        $environment.tenant.id = '11111111-1111-4111-8111-111111111111'
        $environment.tenant.labelScheme = 'modern'
        $environment.groups[0].id = '22222222-2222-4222-8222-222222222222'
        $environment.groups[0].email = 'bes-authorized@example.com'
        $environment.groups[1].id = '33333333-3333-4333-8333-333333333333'
        $environment.groups[1].email = 'internal-audience@example.com'
        $environment.scopes.sharePointLocations = @('https://example.sharepoint.com/sites/demo')
        $configuredEnvironment = Join-Path $TestDrive 'configured-environment.json'
        $environment | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $configuredEnvironment -Encoding utf8
        { Invoke-PurviewDeployment -EnvironmentPath $configuredEnvironment -Apply } | Should -Throw '*does not yet provide verified publishing-policy*'
    }

    It 'keeps BCSI and PII policies independent with the inclusive 200-occurrence boundary' {
        $policies = Get-Content (Join-Path $repositoryRoot 'config\auto-labeling-policies.json') -Raw | ConvertFrom-Json
        @($policies | Where-Object family -eq 'bcsi' | Where-Object targetLabelKey -ne 'highly-confidential-bes').Count | Should -Be 0
        @($policies | Where-Object family -eq 'pii' | Where-Object { $_.conditions[0].maxCount -eq 199 -and $_.conditions[0].minCount -eq 1 }) | Should -HaveCount 3
        @($policies | Where-Object family -eq 'pii' | Where-Object { $_.conditions[0].minCount -eq 200 -and $null -eq $_.conditions[0].maxCount }) | Should -HaveCount 3
        @($policies | Where-Object { $_.key -like 'pii-*' -and $_.conditions[0].sitKey -ne 'us-ssn' }).Count | Should -Be 0
    }

    It 'keeps BES as the sole final Highly Confidential child' {
        $labels = Get-Content (Join-Path $repositoryRoot 'config\labels.json') -Raw | ConvertFrom-Json
        $bes = @($labels | Where-Object key -eq 'highly-confidential-bes')
        $bes | Should -HaveCount 1
        $bes[0].parent | Should -Be 'highly-confidential'
        $bes[0].priority | Should -BeGreaterThan (@($labels | Where-Object parent -eq 'highly-confidential' | ForEach-Object priority | Where-Object { $_ -ne 240 } | Measure-Object -Maximum).Maximum)
        @($labels | Where-Object key -eq 'confidential-bes').Count | Should -Be 0
    }

    It 'rejects schema-invalid environment data' {
        $temporary = Join-Path $TestDrive 'invalid-environment.json'
        Set-Content -LiteralPath $temporary -Value '{"schemaVersion":1,"unexpected":true}' -Encoding utf8
        $result = Test-PurviewConfiguration -EnvironmentPath $temporary
        $result.Valid | Should -BeFalse
        ($result.Errors -join ' ') | Should -Match 'JSON Schema validation failed'
    }

    It 'surfaces tenant read failures instead of reporting labels as missing' {
        $environmentPath = Join-Path $repositoryRoot 'config\environments\demo.example.json'
        $environment = Get-Content -LiteralPath $environmentPath -Raw | ConvertFrom-Json
        $inventoryPath = Join-Path $TestDrive 'managed-inventory.json'
        @{
            schemaVersion = 1
            tenantId = $environment.tenant.id
            labels = @{ public = '44444444-4444-4444-8444-444444444444' }
            policies = @{}
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $inventoryPath -Encoding utf8
        function global:Get-Label {
            [CmdletBinding()]
            param([string]$Identity, [string]$ErrorAction)
        }
        Mock Get-Label { throw 'Read failed intentionally.' } -ModuleName PurviewIPAsCode

        try {
            { Get-PurviewDriftReport -EnvironmentPath $environmentPath -InventoryPath $inventoryPath } |
                Should -Throw '*Read failed intentionally*'
        }
        finally {
            Remove-Item Function:\global:Get-Label -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Deterministic SIT XML compiler' {
    It 'emits valid UTF-8 XML with stable entity ids, 300-character proximity, and confidence tiers' {
        $output = Join-Path $TestDrive 'rules.xml'
        Build-PurviewRulePackage -OutputPath $output | Out-Null
        $bytes = [System.IO.File]::ReadAllBytes($output)
        $text = [System.Text.Encoding]::UTF8.GetString($bytes)
        $document = [xml]$text
        $document.DocumentElement.LocalName | Should -Be 'RulePackage'
        $text | Should -Match 'encoding="utf-8"'
        $entities = $document.SelectNodes("//*[local-name()='Entity']")
        $entities.Count | Should -Be 3
        foreach ($entity in $entities) {
            $entity.GetAttribute('patternsProximity') | Should -Be '300'
            @($entity.SelectNodes("*[local-name()='Pattern']") | ForEach-Object { $_.GetAttribute('confidenceLevel') } | Sort-Object -Unique) -join ',' | Should -Be '65,75,85'
        }
    }

    It 'produces byte-identical output on repeated compilation' {
        $first = Join-Path $TestDrive 'first.xml'
        $second = Join-Path $TestDrive 'second.xml'
        Build-PurviewRulePackage -OutputPath $first | Out-Null
        Build-PurviewRulePackage -OutputPath $second | Out-Null
        (Get-FileHash -LiteralPath $first -Algorithm SHA256).Hash | Should -Be (Get-FileHash -LiteralPath $second -Algorithm SHA256).Hash
    }

    It 'keeps unsupported live cmdlets from appearing available' {
        $capabilities = Get-PurviewAdapterCapability -Adapter Service
        $capabilities.Adapter | Should -Be 'Service'
        $capabilities.ReadyForApply | Should -BeFalse
        @($capabilities.Commands).Count | Should -BeGreaterThan 0
        @($capabilities.Commands | Where-Object { -not $_.PSObject.Properties.Match('Available').Count }).Count | Should -Be 0
    }

    It 'does not let an approval file bypass an unsupported activation adapter' {
        $approval = Join-Path $TestDrive 'approval.json'
        Set-Content -LiteralPath $approval -Value '{"approved":true,"approvedBy":"reviewer","simulationRunId":"demo-123"}' -Encoding utf8
        { Enable-PurviewAutoLabeling -EnvironmentPath 'config\environments\demo.example.json' -ApprovalRecordPath $approval } | Should -Throw '*intentionally blocked*'
    }
}

Describe 'Scanner lab safety gates' {
    It 'requires Windows Server Desktop Experience and leaves scanner labeling off' {
        $bootstrap = Get-Content (Join-Path $repositoryRoot 'extensions\scanner\scripts\Invoke-LabBootstrap.ps1') -Raw
        $bootstrap | Should -Match "installationType -ne 'Server'"
        $bootstrap | Should -Match 'Set-ScannerContentScan -Enforce Off -DiscoverInformationTypes All -EnableDlp On -LabelFilesByContent Off -RelabelFiles Off -EnforceDefaultLabel Off'
        $bootstrap | Should -Match '\$state\.scannerLabelConditionsSupported = \$false'
        $bootstrap | Should -Match '\$state\.readyForEnforcement = \$false'
    }

    It 'does not allow approval alone to enable scanner protection' {
        $activation = Get-Content (Join-Path $repositoryRoot 'extensions\scanner\scripts\Enable-ScannerProtection.ps1') -Raw
        $activation | Should -Match 'if \(-not \$readiness\.scannerLabelConditionsSupported\)'
        $activation | Should -Match 'manual-label preservation'
    }
}
