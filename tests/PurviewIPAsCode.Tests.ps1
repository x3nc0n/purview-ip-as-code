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
        $result.Errors | Should -Contain 'A real tenant ID and detected modern label scheme are required for tenant operations.'
    }

    It 'returns a safe deployment plan by default and blocks live apply when the cmdlet contract is unavailable' {
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
        $inventoryPath = Join-Path $TestDrive 'managed-inventory.json'
        @{
            schemaVersion = 1
            tenantId = $environment.tenant.id
            labels = @{}
            policies = @{}
        } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $inventoryPath -Encoding utf8
        { Invoke-PurviewDeployment -EnvironmentPath $configuredEnvironment -InventoryPath $inventoryPath -Apply } |
            Should -Throw '*missing documented runtime capabilities*'
    }

    It 'keeps BCSI and PII policies independent with the inclusive 200-occurrence boundary' {
        $policies = Get-Content (Join-Path $repositoryRoot 'config\auto-labeling-policies.json') -Raw | ConvertFrom-Json
        @($policies | Where-Object family -eq 'bcsi' | Where-Object targetLabelKey -ne 'highly-confidential-bes').Count | Should -Be 0
        $policies | Should -HaveCount 4
        @($policies | Where-Object family -eq 'pii' | Where-Object { $_.conditions[0].maxCount -eq 199 -and $_.conditions[0].minCount -eq 1 }) | Should -HaveCount 1
        @($policies | Where-Object family -eq 'pii' | Where-Object { $_.conditions[0].minCount -eq 200 -and $null -eq $_.conditions[0].maxCount }) | Should -HaveCount 2
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

    It 'configures Do Not Forward on the Highly Confidential Recipients Only label used by the Exchange escalation' {
        $labels = Get-Content (Join-Path $repositoryRoot 'config\labels.json') -Raw | ConvertFrom-Json
        ($labels | Where-Object key -eq 'highly-confidential-recipients').protection.doNotForward | Should -BeTrue
        ($labels | Where-Object key -eq 'confidential-recipients').protection.doNotForward | Should -BeFalse
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
        function global:Connect-ExchangeOnline {}
        function global:Get-OrganizationConfig {
            [CmdletBinding()]
            param()
            return [pscustomobject]@{ ExternalDirectoryOrganizationId = '00000000-0000-0000-0000-000000000000' }
        }
        Mock Get-Label { throw 'Read failed intentionally.' } -ModuleName PurviewIPAsCode

        try {
            { Get-PurviewDriftReport -EnvironmentPath $environmentPath -InventoryPath $inventoryPath } |
                Should -Throw '*Read failed intentionally*'
        }
        finally {
            Remove-Item Function:\global:Get-Label -ErrorAction SilentlyContinue
            Remove-Item Function:\global:Get-OrganizationConfig -ErrorAction SilentlyContinue
            Remove-Item Function:\global:Connect-ExchangeOnline -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Deterministic SIT XML compiler' {
    It 'emits Unicode UTF-16 XML with stable entity ids, 300-character proximity, and confidence tiers' {
        $output = Join-Path $TestDrive 'rules.xml'
        Build-PurviewRulePackage -OutputPath $output | Out-Null
        $bytes = [System.IO.File]::ReadAllBytes($output)
        [System.BitConverter]::ToString($bytes[0..1]) | Should -Be 'FF-FE'
        $text = [System.IO.File]::ReadAllText($output, [System.Text.Encoding]::Unicode)
        $document = [xml]$text
        $document.DocumentElement.LocalName | Should -Be 'RulePackage'
        $text | Should -Match 'encoding="UTF-16"'
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

    It 'maps the 1-199 SSN rule to a documented exception at 200 occurrences' {
        InModuleScope PurviewIPAsCode {
            $definitions = Get-PurviewDefinition 'config\environments\demo.example.json'
            $definitions.Environment.scopes.sharePointLocations = @('https://example.sharepoint.com/sites/demo')
            $policy = $definitions.Policies | Where-Object key -eq 'pii-low'
            $arguments = Get-PurviewAutoRuleArgument -Policy $policy -Condition $policy.conditions[0] -Definitions $definitions -Workload SharePoint
            $arguments.ContentContainsSensitiveInformation | Should -HaveCount 1
            $arguments.ContentContainsSensitiveInformation[0].minCount | Should -Be '1'
            $arguments.ContentContainsSensitiveInformation[0].minConfidence | Should -Be '85'
            $arguments.ExceptIfContentContainsSensitiveInformation | Should -HaveCount 1
            $arguments.ExceptIfContentContainsSensitiveInformation[0].minCount | Should -Be '200'
            $bcsiPolicy = $definitions.Policies | Where-Object key -eq 'bcsi-high'
            $bcsiLabel = $definitions.Labels | Where-Object key -eq 'highly-confidential-bes'
            $bcsi = Get-PurviewAutoPolicyArgument -Policy $bcsiPolicy -Definitions $definitions -LabelId '44444444-4444-4444-8444-444444444444'
            $piiPolicy = $definitions.Policies | Where-Object key -eq 'pii-high-files'
            $piiLabel = $definitions.Labels | Where-Object key -eq 'highly-confidential-internal'
            $pii = Get-PurviewAutoPolicyArgument -Policy $piiPolicy -Definitions $definitions -LabelId '55555555-5555-4555-8555-555555555555'
            $bcsi.Priority | Should -Be $bcsiLabel.priority
            $pii.Priority | Should -Be $piiLabel.priority
            $bcsi.Priority | Should -BeGreaterThan $pii.Priority
        }
    }

    It 'creates an independent one-SIT rule for each BCSI detector' {
        InModuleScope PurviewIPAsCode {
            $definitions = Get-PurviewDefinition 'config\environments\demo.example.json'
            $policy = $definitions.Policies | Where-Object key -eq 'bcsi-high'
            foreach ($condition in $policy.conditions) {
                $arguments = Get-PurviewAutoRuleArgument -Policy $policy -Condition $condition -Definitions $definitions -Workload SharePoint
                $arguments.ContentContainsSensitiveInformation | Should -HaveCount 1
                $arguments.ContentContainsSensitiveInformation[0].Name | Should -Be (
                    Get-PurviewSensitiveInformationTypeName -SitKey $condition.sitKey -Definitions $definitions
                )
                $arguments.ContainsKey('ExceptIfContentContainsSensitiveInformation') | Should -BeFalse
            }
        }
    }

    It 'scopes policies to configured locations and expands conditions into single-workload rules' {
        InModuleScope PurviewIPAsCode {
            $definitions = Get-PurviewDefinition 'config\environments\demo.example.json'
            $definitions.Environment.scopes.sharePointLocations = @('https://example.sharepoint.com/sites/demo')
            $definitions.Environment.scopes.oneDriveLocations = @('https://example-my.sharepoint.com/personal/pilot')
            $definitions.Environment.scopes.exchangeLocations = @('pilot@example.com')
            $rules = @($definitions.Policies | ForEach-Object { Get-PurviewAutoRuleDefinition -Policy $_ -Definitions $definitions })
            $rules | Should -HaveCount 15
            $policy = $definitions.Policies | Where-Object key -eq 'bcsi-high'
            $arguments = Get-PurviewAutoPolicyArgument -Policy $policy -Definitions $definitions -LabelId '44444444-4444-4444-8444-444444444444'
            $arguments.SharePointLocation | Should -Be @('https://example.sharepoint.com/sites/demo')
            $arguments.OneDriveLocation | Should -Be @('https://example-my.sharepoint.com/personal/pilot')
            $arguments.ExchangeLocation | Should -Be @('pilot@example.com')
            foreach ($rule in (Get-PurviewAutoRuleDefinition -Policy $policy -Definitions $definitions)) {
                $ruleArguments = Get-PurviewAutoRuleArgument -Policy $policy -Condition $rule.Condition -Definitions $definitions -Workload $rule.Workload
                $ruleArguments.Workload | Should -BeIn @('SharePoint', 'OneDriveForBusiness', 'Exchange')
                $ruleArguments.Name | Should -Be "bcsi-high-$($rule.Key)"
            }
            { Get-PurviewAutoRuleArgument -Policy $policy -Condition $policy.conditions[0] -Definitions $definitions } |
                Should -Throw '*one explicit workload*'
            $definitions.Environment.scopes.oneDriveLocations = @()
            $arguments = Get-PurviewAutoPolicyArgument -Policy $policy -Definitions $definitions -LabelId '44444444-4444-4444-8444-444444444444'
            $arguments.ContainsKey('OneDriveLocation') | Should -BeFalse
            @(Get-PurviewAutoRuleDefinition -Policy $policy -Definitions $definitions) | Should -HaveCount 6
        }
    }

    It 'matches service-reported workload flags as tokens rather than substrings' {
        InModuleScope PurviewIPAsCode {
            $definitions = Get-PurviewDefinition 'config\environments\demo.example.json'
            $policy = $definitions.Policies | Where-Object key -eq 'pii-exchange-high'
            $expected = Get-PurviewAutoRuleArgument -Policy $policy -Condition $policy.conditions[0] -Definitions $definitions
            $actual = [pscustomobject]@{
                Name = $expected.Name; Policy = '44444444-4444-4444-8444-444444444444'
                Workload = 'Exchange, SharePoint, OneDriveForBusiness'
                ContentContainsSensitiveInformation = $expected.ContentContainsSensitiveInformation
            }
            Test-PurviewAutoRuleMatch -Actual $actual -Expected $expected -PolicyGuid $actual.Policy | Should -BeTrue
            $actual.Workload = 'NotExchange'
            Test-PurviewAutoRuleMatch -Actual $actual -Expected $expected -PolicyGuid $actual.Policy | Should -BeFalse
        }
    }

    It 'requires a manual-label preservation attestation in addition to approval' {
        $approval = Join-Path $TestDrive 'approval.json'
        Set-Content -LiteralPath $approval -Value '{"approved":true,"approvedBy":"reviewer","simulationRunId":"demo-123"}' -Encoding utf8
        { Enable-PurviewAutoLabeling -EnvironmentPath 'config\environments\demo.example.json' -ApprovalRecordPath $approval } |
            Should -Throw '*manualLabelPreservationVerified=true*'
    }
}

Describe 'Mocked service reconciliation contracts' {
    It 'reconciles and activates without repeat writes (all workloads: <AllWorkloads>)' -ForEach @(
        @{ AllWorkloads = $false; ExpectedRules = 5; ExpectedPolicies = 3; ExpectedBlocked = 1 },
        @{ AllWorkloads = $true; ExpectedRules = 15; ExpectedPolicies = 4; ExpectedBlocked = 0 }
    ) {
        $global:PurviewFakeState = @{
            Labels = [System.Collections.Generic.List[object]]::new()
            Packages = [System.Collections.Generic.List[object]]::new()
            Policies = [System.Collections.Generic.List[object]]::new()
            Rules = [System.Collections.Generic.List[object]]::new()
            Calls = [System.Collections.Generic.List[object]]::new()
            Groups = @{
                'bes-authorized@example.com' = '22222222-2222-4222-8222-222222222222'
                'internal-audience@example.com' = '33333333-3333-4333-8333-333333333333'
            }
        }
        function global:Connect-IPPSSession {}
        function global:Connect-ExchangeOnline {}
        function global:Get-OrganizationConfig {
            [CmdletBinding()]
            param()
            return [pscustomobject]@{ ExternalDirectoryOrganizationId = '11111111-1111-4111-8111-111111111111' }
        }
        function global:Get-Label {
            [CmdletBinding()]
            param([string]$Identity)
            if ($Identity) { return $global:PurviewFakeState.Labels | Where-Object { [string]$_.Guid -eq $Identity } | Select-Object -First 1 }
            return @($global:PurviewFakeState.Labels)
        }
        function global:New-Label {
            [CmdletBinding()]
            param(
                [string]$Name, [string]$DisplayName, [string]$Tooltip, [string[]]$ContentType,
                [bool]$IsLabelGroup, [string]$ParentId, [bool]$EncryptionEnabled,
                [string]$EncryptionProtectionType, [string[]]$EncryptionRightsDefinitions,
                [Nullable[int]]$EncryptionOfflineAccessDays, [string]$EncryptionContentExpiredOnDateInDaysOrNever,
                [bool]$EncryptionPromptUser, [bool]$EncryptionDoNotForward, [bool]$EncryptionEncryptOnly
            )
            $item = [pscustomobject]@{
                Guid = [guid]::NewGuid().ToString()
                Name = $Name; DisplayName = $DisplayName; Tooltip = $Tooltip; ContentType = $ContentType
                IsLabelGroup = $IsLabelGroup; ParentId = $ParentId; Priority = 0
                EncryptionEnabled = $EncryptionEnabled; EncryptionProtectionType = $EncryptionProtectionType
                EncryptionRightsDefinitions = $EncryptionRightsDefinitions
                EncryptionOfflineAccessDays = $EncryptionOfflineAccessDays
                EncryptionContentExpiredOnDateInDaysOrNever = $EncryptionContentExpiredOnDateInDaysOrNever
                EncryptionPromptUser = $EncryptionPromptUser; EncryptionDoNotForward = $EncryptionDoNotForward
                EncryptionEncryptOnly = $EncryptionEncryptOnly
            }
            [void]$global:PurviewFakeState.Labels.Add($item)
            [void]$global:PurviewFakeState.Calls.Add([pscustomobject]@{ Command = 'New-Label'; Name = $Name })
            return $item
        }
        function global:Set-Label {
            [CmdletBinding()]
            param(
                [string]$Identity, [string]$DisplayName, [string]$Tooltip, [string[]]$ContentType,
                [string]$ParentId, [int]$Priority, [bool]$EncryptionEnabled, [string]$EncryptionProtectionType,
                [string[]]$EncryptionRightsDefinitions, [Nullable[int]]$EncryptionOfflineAccessDays,
                [string]$EncryptionContentExpiredOnDateInDaysOrNever, [bool]$EncryptionPromptUser,
                [bool]$EncryptionDoNotForward, [bool]$EncryptionEncryptOnly,
                [string]$Conditions, [bool]$SiteAndGroupProtectionEnabled,
                [string]$SiteAndGroupProtectionPrivacy, [bool]$SiteAndGroupProtectionAllowAccessToGuestUsers,
                [string]$SiteExternalSharingControlType
            )
            $item = $global:PurviewFakeState.Labels | Where-Object { [string]$_.Guid -eq $Identity } | Select-Object -First 1
            foreach ($name in @('DisplayName', 'Tooltip', 'ContentType', 'ParentId', 'Priority', 'EncryptionEnabled', 'EncryptionProtectionType', 'EncryptionRightsDefinitions', 'EncryptionOfflineAccessDays', 'EncryptionContentExpiredOnDateInDaysOrNever', 'EncryptionPromptUser', 'EncryptionDoNotForward', 'EncryptionEncryptOnly')) {
                if ($PSBoundParameters.ContainsKey($name)) { $item.$name = $PSBoundParameters[$name] }
            }
            if ($PSBoundParameters.ContainsKey('Conditions')) { $item | Add-Member Conditions @($Conditions) -Force }
            if ($PSBoundParameters.ContainsKey('SiteAndGroupProtectionEnabled')) {
                $actions = @(
                    @{ Type = 'protectgroup'; Settings = @(
                        @{ Key = 'disabled'; Value = 'false' }
                        @{ Key = 'privacy'; Value = $SiteAndGroupProtectionPrivacy }
                        @{ Key = 'allowaccesstoguestusers'; Value = [string]$SiteAndGroupProtectionAllowAccessToGuestUsers }
                    ) }
                    @{ Type = 'protectsite'; Settings = @(
                        @{ Key = 'externalsharingcontroltype'; Value = $SiteExternalSharingControlType }
                    ) }
                )
                $item | Add-Member LabelActions @($actions | ForEach-Object { $_ | ConvertTo-Json -Depth 6 -Compress }) -Force
            }
            [void]$global:PurviewFakeState.Calls.Add([pscustomobject]@{ Command = 'Set-Label'; Identity = $Identity })
            return $item
        }
        function global:Get-DlpSensitiveInformationTypeRulePackage {
            [CmdletBinding()]
            param([string]$Identity)
            return @($global:PurviewFakeState.Packages)
        }
        function global:Get-DlpSensitiveInformationType {
            [CmdletBinding()]
            param([string]$Identity)
            return [pscustomobject]@{ Id = $Identity }
        }
        function global:New-DlpSensitiveInformationTypeRulePackage {
            [CmdletBinding()]
            param([byte[]]$FileData)
            $item = [pscustomobject]@{ Identity = '2439f4bb-f00c-5c0e-8a73-1ba7048bc146'; Version = '1.0.0.0' }
            [void]$global:PurviewFakeState.Packages.Add($item)
            [void]$global:PurviewFakeState.Calls.Add([pscustomobject]@{ Command = 'New-DlpSensitiveInformationTypeRulePackage' })
            return $item
        }
        function global:Set-DlpSensitiveInformationTypeRulePackage {
            [CmdletBinding(SupportsShouldProcess)]
            param([byte[]]$FileData)
            [void]$global:PurviewFakeState.Calls.Add([pscustomobject]@{ Command = 'Set-DlpSensitiveInformationTypeRulePackage' })
        }
        function global:Get-LabelPolicy {
            [CmdletBinding()]
            param([string]$Identity)
        }
        function global:New-LabelPolicy {
            [CmdletBinding()]
            param([string]$Name, [string[]]$Labels)
        }
        function global:Get-AutoSensitivityLabelPolicy {
            [CmdletBinding()]
            param([string]$Identity)
            if ($Identity) { return $global:PurviewFakeState.Policies | Where-Object { [string]$_.Guid -eq $Identity } | Select-Object -First 1 }
            return @($global:PurviewFakeState.Policies)
        }
        function global:New-AutoSensitivityLabelPolicy {
            [CmdletBinding()]
            param(
                [string]$Name, [string]$ApplySensitivityLabel, [string]$Mode,
                [string[]]$SharePointLocation, [string[]]$OneDriveLocation, [string[]]$ExchangeLocation,
                [int]$Priority, [bool]$OverwriteLabel
            )
            $item = [pscustomobject]@{
                Guid = [guid]::NewGuid().ToString(); Name = $Name
                ApplySensitivityLabel = $ApplySensitivityLabel; Mode = $Mode; Priority = $Priority; OverwriteLabel = $OverwriteLabel
                SharePointLocation = $SharePointLocation; OneDriveLocation = $OneDriveLocation; ExchangeLocation = $ExchangeLocation
            }
            [void]$global:PurviewFakeState.Policies.Add($item)
            [void]$global:PurviewFakeState.Calls.Add([pscustomobject]@{ Command = 'New-AutoSensitivityLabelPolicy'; Name = $Name })
            return $item
        }
        function global:Set-AutoSensitivityLabelPolicy {
            [CmdletBinding()]
            param([string]$Identity, [string]$Mode)
            $item = $global:PurviewFakeState.Policies | Where-Object { [string]$_.Guid -eq $Identity } | Select-Object -First 1
            $item.Mode = $Mode
            [void]$global:PurviewFakeState.Calls.Add([pscustomobject]@{ Command = 'Set-AutoSensitivityLabelPolicy'; Identity = $Identity })
        }
        function global:Get-AutoSensitivityLabelRule {
            [CmdletBinding()]
            param([string]$Identity)
            if ($Identity) { return $global:PurviewFakeState.Rules | Where-Object { [string]$_.Guid -eq $Identity } | Select-Object -First 1 }
            return @($global:PurviewFakeState.Rules)
        }
        function global:New-AutoSensitivityLabelRule {
            [CmdletBinding()]
            param(
                [string]$Name, [string]$Policy, [string]$Workload,
                [hashtable[]]$ContentContainsSensitiveInformation,
                [hashtable[]]$ExceptIfContentContainsSensitiveInformation
            )
            $item = [pscustomobject]@{
                Guid = [guid]::NewGuid().ToString(); Name = $Name; Policy = $Policy; Workload = $Workload
                ContentContainsSensitiveInformation = $ContentContainsSensitiveInformation
                ExceptIfContentContainsSensitiveInformation = $ExceptIfContentContainsSensitiveInformation
            }
            [void]$global:PurviewFakeState.Rules.Add($item)
            [void]$global:PurviewFakeState.Calls.Add([pscustomobject]@{ Command = 'New-AutoSensitivityLabelRule'; Name = $Name })
            return $item
        }
        function global:Get-Recipient {
            [CmdletBinding()]
            param([string]$Identity)
            return [pscustomobject]@{
                PrimarySmtpAddress = $Identity; RecipientTypeDetails = 'MailUniversalSecurityGroup'
                ExternalDirectoryObjectId = $global:PurviewFakeState.Groups[$Identity]
            }
        }
        $functionNames = @(
            'Connect-IPPSSession', 'Connect-ExchangeOnline', 'Get-OrganizationConfig', 'Get-Label', 'New-Label', 'Set-Label',
            'Get-DlpSensitiveInformationType', 'Get-DlpSensitiveInformationTypeRulePackage', 'New-DlpSensitiveInformationTypeRulePackage', 'Set-DlpSensitiveInformationTypeRulePackage',
            'Get-LabelPolicy', 'New-LabelPolicy', 'Get-AutoSensitivityLabelPolicy', 'New-AutoSensitivityLabelPolicy',
            'Set-AutoSensitivityLabelPolicy', 'Get-AutoSensitivityLabelRule', 'New-AutoSensitivityLabelRule', 'Get-Recipient'
        )
        try {
            $environment = Get-Content (Join-Path $repositoryRoot 'config\environments\demo.example.json') -Raw | ConvertFrom-Json
            $environment.tenant.id = '11111111-1111-4111-8111-111111111111'
            $environment.tenant.labelScheme = 'modern'
            $environment.groups[0].id = $global:PurviewFakeState.Groups['bes-authorized@example.com']
            $environment.groups[0].email = 'bes-authorized@example.com'
            $environment.groups[1].id = $global:PurviewFakeState.Groups['internal-audience@example.com']
            $environment.groups[1].email = 'internal-audience@example.com'
            $environment.scopes.sharePointLocations = @('https://example.sharepoint.com/sites/demo')
            if ($AllWorkloads) {
                $environment.scopes.oneDriveLocations = @('https://example-my.sharepoint.com/personal/pilot')
                $environment.scopes.exchangeLocations = @('pilot@example.com')
            }
            $environmentPath = Join-Path $TestDrive 'mocked-environment.json'
            $environment | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $environmentPath -Encoding utf8
            $inventoryPath = Join-Path $TestDrive "mocked-inventory-$AllWorkloads.json"
            Initialize-PurviewInventory -EnvironmentPath $environmentPath -InventoryPath $inventoryPath

            $first = Invoke-PurviewDeployment -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -Apply
            $first.Status | Should -Be 'PartiallyApplied'
            @($first.Actions | Where-Object { $_.Status -eq 'Created' -and $_.Kind -eq 'Label' }).Count | Should -Be 12
            @($global:PurviewFakeState.Calls | Where-Object Command -eq 'New-AutoSensitivityLabelRule').Count | Should -Be $ExpectedRules
            @($first.Actions | Where-Object { $_.Status -eq 'Blocked' }).Count | Should -Be $ExpectedBlocked
            $global:PurviewFakeState.Calls.Clear()

            $second = Invoke-PurviewDeployment -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -Apply
            $second.Status | Should -Be 'PartiallyApplied'
            @($global:PurviewFakeState.Calls | Where-Object { $_.Command -in @('New-Label', 'Set-Label', 'New-AutoSensitivityLabelPolicy', 'New-AutoSensitivityLabelRule', 'New-DlpSensitiveInformationTypeRulePackage') }).Count |
                Should -Be 0
            $second.Limitations[0].Reason | Should -Match 'no recipient-user/group audience parameter'

            $approvalPath = Join-Path $TestDrive 'activation-approval.json'
            Set-Content -LiteralPath $approvalPath -Value '{"approved":true,"approvedBy":"reviewer","simulationRunId":"mock-run","manualLabelPreservationVerified":true}' -Encoding utf8
            $activation = Enable-PurviewAutoLabeling -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -ApprovalRecordPath $approvalPath
            $activation.Status | Should -Be 'Enabled'
            @($activation.Policies).Count | Should -Be $ExpectedPolicies
            @($global:PurviewFakeState.Calls | Where-Object Command -eq 'Set-AutoSensitivityLabelPolicy').Count | Should -Be $ExpectedPolicies
            $global:PurviewFakeState.Calls.Clear()

            $afterActivation = Invoke-PurviewDeployment -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -Apply
            $afterActivation.Status | Should -Be 'PartiallyApplied'
            @($global:PurviewFakeState.Calls | Where-Object { $_.Command -in @('New-Label', 'Set-Label', 'New-AutoSensitivityLabelPolicy', 'New-AutoSensitivityLabelRule', 'New-DlpSensitiveInformationTypeRulePackage', 'Set-AutoSensitivityLabelPolicy') }).Count |
                Should -Be 0

            $rogueLabel = $global:PurviewFakeState.Labels | Where-Object DisplayName -eq 'Public' | Select-Object -First 1 | Select-Object *
            $rogueLabel.Guid = [guid]::NewGuid().ToString()
            [void]$global:PurviewFakeState.Labels.Add($rogueLabel)
            $global:PurviewFakeState.Calls.Clear()
            { Invoke-PurviewDeployment -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -Apply } |
                Should -Throw '*collides with a different tenant label*'
            @($global:PurviewFakeState.Calls | Where-Object { $_.Command -in @('New-Label', 'Set-Label', 'New-AutoSensitivityLabelPolicy', 'New-AutoSensitivityLabelRule', 'New-DlpSensitiveInformationTypeRulePackage') }).Count |
                Should -Be 0
        }
        finally {
            foreach ($name in $functionNames) { Remove-Item "Function:\global:$name" -ErrorAction SilentlyContinue }
            Remove-Variable PurviewFakeState -Scope Global -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Scanner lab safety gates' {
    It 'requires Windows Server Desktop Experience and leaves scanner labeling off' {
        $bootstrap = Get-Content (Join-Path $repositoryRoot 'extensions\scanner\scripts\Invoke-LabBootstrap.ps1') -Raw
        $bootstrap | Should -Match "installationType -ne 'Server'"
        $bootstrap | Should -Match 'Set-ScannerContentScan -Enforce Off -DiscoverInformationTypes All -EnableDlp Off -LabelFilesByContent On -RelabelFiles Off -EnforceDefaultLabel Off'
        $bootstrap | Should -Match '\$state\.scannerLabelConditionsSupported = \$false'
        $bootstrap | Should -Match '\$state\.readyForEnforcement = \$false'
    }

    It 'does not allow approval alone to enable scanner protection' {
        $activation = Get-Content (Join-Path $repositoryRoot 'extensions\scanner\scripts\Enable-ScannerProtection.ps1') -Raw
        $activation | Should -Match 'if \(-not \$readiness\.scannerLabelConditionsSupported\)'
        $activation | Should -Match 'manual-label preservation'
    }
}
