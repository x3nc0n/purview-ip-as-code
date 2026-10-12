Set-StrictMode -Version Latest

$script:RepositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..\')).Path
$script:ConfigurationFiles = @{
    Labels = 'config\labels.json'
    Publishing = 'config\publishing-policies.json'
    Detection = 'config\detection.json'
    Policies = 'config\auto-labeling-policies.json'
    EnvironmentSchema = 'schemas\environment.schema.json'
    LabelsSchema = 'schemas\config.schema.json'
    PublishingSchema = 'schemas\publishing-policy.schema.json'
    DetectionSchema = 'schemas\detection.schema.json'
    PoliciesSchema = 'schemas\policies.schema.json'
}

function Get-PurviewConfigPath {
    param([Parameter(Mandatory)][string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) {
        return $Path
    }
    return Join-Path $script:RepositoryRoot $Path
}

function Read-PurviewJson {
    param([Parameter(Mandatory)][string]$Path)
    $resolvedPath = Get-PurviewConfigPath $Path
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        throw "Required configuration file was not found: $resolvedPath"
    }
    try {
        return Get-Content -LiteralPath $resolvedPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    }
    catch {
        throw "Invalid JSON in '$resolvedPath': $($_.Exception.Message)"
    }
}

function Get-PurviewDefinition {
    param([Parameter(Mandatory)][string]$EnvironmentPath)

    $environment = Read-PurviewJson $EnvironmentPath
    $labels = Read-PurviewJson $script:ConfigurationFiles.Labels
    $publishing = Read-PurviewJson $script:ConfigurationFiles.Publishing
    $detection = Read-PurviewJson $script:ConfigurationFiles.Detection
    $policies = Read-PurviewJson $script:ConfigurationFiles.Policies
    return @{
        Environment = $environment
        Labels = $labels
        Publishing = $publishing
        Detection = $detection
        Policies = $policies
    }
}

function Test-PurviewConfiguration {
    [CmdletBinding()]
    param(
        [string]$EnvironmentPath = 'config\environments\demo.example.json',
        [switch]$RequireTenantValues
    )

    $errors = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $schemaScript = Join-Path $script:RepositoryRoot 'scripts\validate-json.py'
    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        $errors.Add('Python 3 and the pinned jsonschema dependency are required for JSON Schema validation.')
    }
    else {
        $schemaOutput = @(& $python.Source $schemaScript --environment (Get-PurviewConfigPath $EnvironmentPath) 2>&1)
        if ($LASTEXITCODE -ne 0) {
            $errors.Add("JSON Schema validation failed: $($schemaOutput -join ' ')")
        }
    }

    if ($errors.Count -gt 0) {
        return [pscustomobject]@{ Valid = $false; Errors = @($errors); Warnings = @($warnings) }
    }

    $definitions = Get-PurviewDefinition $EnvironmentPath
    $labels = $definitions.Labels
    $environment = $definitions.Environment
    $detectors = $definitions.Detection.detectors
    $policies = $definitions.Policies
    $labelKeys = @($labels | ForEach-Object key)
    $detectorKeys = @($detectors | ForEach-Object key)
    $groupKeys = @($environment.groups | ForEach-Object key)

    if (($labelKeys | Select-Object -Unique).Count -ne $labelKeys.Count) {
        $errors.Add('Label keys must be unique.')
    }
    if (($detectorKeys | Select-Object -Unique).Count -ne $detectorKeys.Count) {
        $errors.Add('Custom detector keys must be unique.')
    }
    if (($policies.key | Select-Object -Unique).Count -ne $policies.Count) {
        $errors.Add('Policy keys must be unique.')
    }
    foreach ($label in $labels) {
        if ($label.parent -and $label.parent -notin $labelKeys) {
            $errors.Add("Label '$($label.key)' references missing parent '$($label.parent)'.")
        }
        if ($label.protection.groupKey -and $label.protection.groupKey -notin $groupKeys) {
            $errors.Add("Label '$($label.key)' references missing group '$($label.protection.groupKey)'.")
        }
    }

    $bes = @($labels | Where-Object key -eq 'highly-confidential-bes')
    if ($bes.Count -ne 1 -or $bes[0].parent -ne 'highly-confidential' -or $bes[0].priority -ne 240) {
        $errors.Add('The only BES label must be the final/highest-priority child of Highly Confidential.')
    }
    if (@($labels | Where-Object key -eq 'confidential-bes').Count -gt 0) {
        $errors.Add('A Confidential / BES label is prohibited.')
    }
    foreach ($key in @('confidential-internal', 'highly-confidential-internal')) {
        $internal = @($labels | Where-Object key -eq $key)
        if ($internal.Count -ne 1 -or $internal[0].protection.groupKey -ne 'internal-only-audience' -or $internal[0].protection.offlineAccessDays -ne 14) {
            $errors.Add("Label '$key' must use the internal-only audience group with 14 days of offline access.")
        }
    }
    $besGroup = @($environment.groups | Where-Object purpose -eq 'bes-authorized')
    $internalGroup = @($environment.groups | Where-Object purpose -eq 'internal-only-audience')
    if ($besGroup.Count -ne 1 -or $internalGroup.Count -ne 1) {
        $errors.Add('Exactly one BES Authorized group and one internal-only audience group are required.')
    }
    if ($environment.features.encryptBes -eq $false) {
        $warnings.Add('BES encryption is explicitly disabled. No fallback will enable or validate encryption for you.')
    }
    foreach ($group in $environment.groups) {
        if ($group.id -eq '00000000-0000-0000-0000-000000000000' -or $group.email -match '\.invalid$') {
            $warnings.Add("Group '$($group.key)' still has a placeholder value.")
        }
    }
    if ($environment.scopes.sharePointLocations.Count -eq 0 -and $environment.scopes.oneDriveLocations.Count -eq 0 -and $environment.scopes.exchangeLocations.Count -eq 0) {
        $warnings.Add('No Microsoft 365 workload locations are configured; policy deployment will be blocked.')
    }
    if ($environment.tenant.id -eq '00000000-0000-0000-0000-000000000000') {
        $warnings.Add('Tenant ID is a placeholder.')
    }
    if ($environment.tenant.labelScheme -eq 'detect') {
        $warnings.Add('The tenant label scheme must be detected and recorded before applying labels.')
    }

    foreach ($detector in $detectors) {
        $confidences = @($detector.patterns | ForEach-Object confidence | Sort-Object -Unique)
        if (($confidences -join ',') -ne '65,75,85') {
            $errors.Add("Detector '$($detector.key)' must define the 65/75/85 confidence tiers.")
        }
        foreach ($pattern in $detector.patterns) {
            foreach ($expression in @($pattern.primaryRegex) + @($pattern.supportRegexes)) {
                try {
                    [void][regex]::new($expression, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
                }
                catch {
                    $errors.Add("Detector '$($detector.key)' contains invalid regex: $($_.Exception.Message)")
                }
            }
        }
    }

    $bcsiPolicies = @($policies | Where-Object family -eq 'bcsi')
    if ($bcsiPolicies.Count -ne 3 -or @($bcsiPolicies | Where-Object targetLabelKey -ne 'highly-confidential-bes').Count -gt 0) {
        $errors.Add('The three independent BCSI policies must all target Highly Confidential / BES.')
    }
    foreach ($policy in $policies) {
        foreach ($condition in $policy.conditions) {
            if ($policy.family -eq 'bcsi' -and ($condition.sitKey -notin $detectorKeys -or $condition.minConfidence -ne 85)) {
                $errors.Add("BCSI policy '$($policy.key)' must reference only declared high-confidence custom detectors.")
            }
            if ($policy.family -eq 'pii' -and $condition.sitKey -ne 'us-ssn') {
                $errors.Add("PII policy '$($policy.key)' must be independent and use only the configured US SSN SIT.")
            }
        }
        if ($policy.family -eq 'bcsi' -and $policy.conditions.Count -ne $detectors.Count) {
            $errors.Add("BCSI policy '$($policy.key)' must include each approved high-confidence detector.")
        }
        if ($policy.family -eq 'pii' -and $policy.conditions.Count -ne 1) {
            $errors.Add("PII policy '$($policy.key)' must have exactly one independent SSN condition.")
        }
        if ($policy.workload -eq 'Exchange' -and $policy.key -eq 'pii-exchange-high' -and $policy.protectionAction -ne 'do-not-forward') {
            $errors.Add('The high-volume Exchange PII policy must explicitly select Do Not Forward.')
        }
    }
    $thresholdPolicies = @($policies | Where-Object { $_.family -eq 'pii' -and $_.conditions[0].maxCount -eq 199 })
    if ($thresholdPolicies.Count -ne 3 -or @($thresholdPolicies | Where-Object { $_.conditions[0].minCount -ne 1 }).Count -gt 0) {
        $errors.Add('Each PII workload requires an inclusive 1-199 occurrence policy.')
    }
    $escalationPolicies = @($policies | Where-Object { $_.family -eq 'pii' -and $_.conditions[0].minCount -eq 200 -and $null -eq $_.conditions[0].maxCount })
    if ($escalationPolicies.Count -ne 3) {
        $errors.Add('Each PII workload requires an unbounded 200+ occurrence policy.')
    }
    if ($RequireTenantValues) {
        if ($environment.tenant.id -eq '00000000-0000-0000-0000-000000000000' -or $environment.tenant.labelScheme -eq 'detect') {
            $errors.Add('A real tenant ID and detected label scheme are required for tenant operations.')
        }
        foreach ($group in $environment.groups) {
            if ($group.id -eq '00000000-0000-0000-0000-000000000000' -or $group.email -match '\.invalid$') {
                $errors.Add("Group '$($group.key)' must be explicitly configured before tenant operations.")
            }
        }
        if ($environment.scopes.sharePointLocations.Count -eq 0 -and $environment.scopes.oneDriveLocations.Count -eq 0 -and $environment.scopes.exchangeLocations.Count -eq 0) {
            $errors.Add('At least one explicit workload scope is required for tenant operations.')
        }
    }
    return [pscustomobject]@{
        Valid = ($errors.Count -eq 0)
        Errors = @($errors)
        Warnings = @($warnings | Select-Object -Unique)
    }
}

function Build-PurviewRulePackage {
    [CmdletBinding()]
    param(
        [string]$DetectionPath = 'config\detection.json',
        [string]$OutputPath = 'config\generated\bcsi-rule-package.xml'
    )

    $detection = Read-PurviewJson $DetectionPath
    $tempEnvironmentPath = 'config\environments\demo.example.json'
    $validation = Test-PurviewConfiguration -EnvironmentPath $tempEnvironmentPath
    if (-not $validation.Valid) {
        throw "Configuration validation failed: $($validation.Errors -join '; ')"
    }
    $settings = [System.Xml.XmlWriterSettings]::new()
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)
    $settings.Indent = $true
    $settings.IndentChars = '  '
    $settings.NewLineChars = "`n"
    $settings.NewLineHandling = [System.Xml.NewLineHandling]::Replace
    $settings.OmitXmlDeclaration = $false
    $stream = [System.IO.MemoryStream]::new()
    $writer = [System.Xml.XmlWriter]::Create($stream, $settings)
    try {
        $writer.WriteStartDocument()
        $writer.WriteStartElement('RulePackage', 'http://schemas.microsoft.com/office/2011/mce')
        $writer.WriteStartElement('RulePack')
        $writer.WriteAttributeString('id', [string]$detection.package.id)
        $writer.WriteStartElement('Version')
        $versionParts = $detection.package.version.Split('.')
        for ($index = 0; $index -lt 4; $index++) {
            $writer.WriteAttributeString(@('major', 'minor', 'build', 'revision')[$index], [string]$versionParts[$index])
        }
        $writer.WriteEndElement()
        $writer.WriteStartElement('Publisher')
        $writer.WriteAttributeString('id', [string]$detection.package.publisherId)
        $writer.WriteEndElement()
        $writer.WriteStartElement('Details')
        $writer.WriteAttributeString('defaultLangCode', 'en')
        $writer.WriteStartElement('LocalizedDetails')
        $writer.WriteAttributeString('langcode', 'en')
        $writer.WriteElementString('PublisherName', 'Purview IP as code')
        $writer.WriteElementString('Name', [string]$detection.package.name)
        $writer.WriteElementString('Description', 'Illustrative contextual BCSI indicators. Not a legal classifier.')
        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $writer.WriteStartElement('Rules')
        foreach ($detector in @($detection.detectors | Sort-Object key)) {
            $writer.WriteStartElement('Rule')
            $writer.WriteAttributeString('id', "Rule_$($detector.key)")
            $writer.WriteStartElement('Entity')
            $writer.WriteAttributeString('id', [string]$detector.entityId)
            $writer.WriteAttributeString('patternsProximity', [string]$detection.proximityCharacters)
            $writer.WriteAttributeString('recommendedConfidence', '85')
            foreach ($pattern in @($detector.patterns | Sort-Object confidence)) {
                $suffix = [string]$pattern.confidence
                $primaryId = "Regex_$($detector.key)_Primary_$suffix"
                $writer.WriteStartElement('Pattern')
                $writer.WriteAttributeString('confidenceLevel', $suffix)
                $writer.WriteStartElement('IdMatch')
                $writer.WriteAttributeString('idRef', $primaryId)
                $writer.WriteEndElement()
                $supportIndex = 0
                foreach ($supportRegex in $pattern.supportRegexes) {
                    $supportIndex++
                    $writer.WriteStartElement('Match')
                    $writer.WriteAttributeString('idRef', "Regex_$($detector.key)_Support_${suffix}_$supportIndex")
                    $writer.WriteEndElement()
                }
                $writer.WriteEndElement()
            }
            $writer.WriteEndElement()
            $writer.WriteEndElement()
        }
        foreach ($detector in @($detection.detectors | Sort-Object key)) {
            foreach ($pattern in @($detector.patterns | Sort-Object confidence)) {
                $suffix = [string]$pattern.confidence
                $writer.WriteStartElement('Regex')
                $writer.WriteAttributeString('id', "Regex_$($detector.key)_Primary_$suffix")
                $writer.WriteString([string]$pattern.primaryRegex)
                $writer.WriteEndElement()
                $supportIndex = 0
                foreach ($supportRegex in $pattern.supportRegexes) {
                    $supportIndex++
                    $writer.WriteStartElement('Regex')
                    $writer.WriteAttributeString('id', "Regex_$($detector.key)_Support_${suffix}_$supportIndex")
                    $writer.WriteString([string]$supportRegex)
                    $writer.WriteEndElement()
                }
            }
        }
        $writer.WriteEndElement()
        $writer.WriteEndElement()
        $writer.WriteEndDocument()
        $writer.Flush()
    }
    finally {
        $writer.Dispose()
    }
    $xml = [System.Text.Encoding]::UTF8.GetString($stream.ToArray())
    $stream.Dispose()
    [void][xml]$xml
    $destination = Get-PurviewConfigPath $OutputPath
    $directory = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $directory)) {
        [void](New-Item -ItemType Directory -Path $directory -Force)
    }
    [System.IO.File]::WriteAllText($destination, $xml, [System.Text.UTF8Encoding]::new($false))
    return $destination
}

function Get-PurviewDeploymentPlan {
    [CmdletBinding()]
    param([string]$EnvironmentPath = 'config\environments\demo.example.json')

    $validation = Test-PurviewConfiguration -EnvironmentPath $EnvironmentPath
    if (-not $validation.Valid) {
        throw "Configuration validation failed: $($validation.Errors -join '; ')"
    }
    $definitions = Get-PurviewDefinition $EnvironmentPath
    $actions = [System.Collections.Generic.List[object]]::new()
    $actions.Add([pscustomobject]@{ Kind = 'SensitiveInformationTypeRulePackage'; Key = $definitions.Detection.package.id; Desired = 'CreateOrUpdate'; LiveSupport = 'Requires connected Security & Compliance PowerShell.' })
    foreach ($label in $definitions.Labels | Sort-Object priority) {
        $actions.Add([pscustomobject]@{
            Kind = 'SensitivityLabel'
            Key = $label.key
            Desired = $label.name
            Parent = $label.parent
            Priority = $label.priority
            Protection = $label.protection.mode
            LiveSupport = 'Create only when absent or update only with a matching GUID in the local managed inventory.'
        })
    }
    $actions.Add([pscustomobject]@{
        Kind = 'LabelPublishingPolicy'
        Key = $definitions.Publishing.policyKey
        Desired = 'CreateOrUpdate'
        PriorityOrder = @($definitions.Labels | Sort-Object priority | ForEach-Object key)
        LiveSupport = 'Label order and audience must be verified after publishing in the target tenant.'
    })
    foreach ($policy in $definitions.Policies) {
        $actions.Add([pscustomobject]@{
            Kind = 'AutoSensitivityLabelPolicy'
            Key = $policy.key
            Desired = $policy.mode
            Family = $policy.family
            Workload = $policy.workload
            TargetLabel = $policy.targetLabelKey
            LiveSupport = 'Create only in simulation; verify rule OR/count semantics and propagation in tenant.'
        })
    }
    return [pscustomobject]@{
        Environment = $definitions.Environment.environment
        Tenant = $definitions.Environment.tenant.id
        Status = if ($validation.Warnings.Count -gt 0) { 'BlockedByConfiguration' } else { 'PlanOnly' }
        Warnings = $validation.Warnings
        Actions = @($actions)
        Deletions = @()
    }
}

function Initialize-PurviewInventory {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string]$EnvironmentPath,
        [string]$InventoryPath = '.purview-state\managed-inventory.json'
    )
    $validation = Test-PurviewConfiguration -EnvironmentPath $EnvironmentPath -RequireTenantValues
    if (-not $validation.Valid) {
        throw "Cannot initialize inventory: $($validation.Errors -join '; ')"
    }
    $destination = Get-PurviewConfigPath $InventoryPath
    if (Test-Path -LiteralPath $destination) {
        throw "Refusing to overwrite existing managed inventory '$destination'."
    }
    if ($PSCmdlet.ShouldProcess($destination, 'Create empty tenant-scoped ownership inventory')) {
        $directory = Split-Path -Parent $destination
        [void](New-Item -ItemType Directory -Path $directory -Force)
        $environment = Read-PurviewJson $EnvironmentPath
        $inventory = [ordered]@{
            schemaVersion = 1
            tenantId = $environment.tenant.id
            labels = [ordered]@{}
            policies = [ordered]@{}
        }
        $json = $inventory | ConvertTo-Json -Depth 8
        [System.IO.File]::WriteAllText($destination, "$json`n", [System.Text.UTF8Encoding]::new($false))
    }
}

function Get-PurviewAdapterCapability {
    [CmdletBinding()]
    param([ValidateSet('Service', 'Scanner')][string]$Adapter = 'Service')

    if ($Adapter -eq 'Service') {
        $required = @{
            'Connect-IPPSSession' = @()
            'Get-Label' = @('Identity')
            'New-Label' = @('Name', 'DisplayName', 'Tooltip', 'ContentType', 'IsLabelGroup', 'ParentId', 'EncryptionEnabled', 'EncryptionProtectionType', 'EncryptionRightsDefinitions', 'EncryptionOfflineAccessDays', 'EncryptionContentExpiredOnDateInDaysOrNever', 'EncryptionPromptUser', 'EncryptionDoNotForward')
            'Set-Label' = @('Identity', 'DisplayName', 'Tooltip', 'ContentType', 'ParentId', 'EncryptionEnabled', 'EncryptionProtectionType', 'EncryptionRightsDefinitions', 'EncryptionOfflineAccessDays', 'EncryptionContentExpiredOnDateInDaysOrNever', 'EncryptionPromptUser', 'EncryptionDoNotForward')
            'Get-DlpSensitiveInformationTypeRulePackage' = @('Identity')
            'New-DlpSensitiveInformationTypeRulePackage' = @('FileData')
            'Set-DlpSensitiveInformationTypeRulePackage' = @('FileData')
            'Get-LabelPolicy' = @('Identity')
            'New-LabelPolicy' = @('Name', 'Labels')
            'Set-LabelPolicy' = @('Identity', 'Labels')
            'Get-AutoSensitivityLabelPolicy' = @('Identity')
            'New-AutoSensitivityLabelPolicy' = @('Name', 'ApplySensitivityLabel', 'Mode', 'SharePointLocation', 'OneDriveLocation', 'ExchangeLocation')
            'New-AutoSensitivityLabelRule' = @('Name', 'Policy', 'Workload', 'ContentContainsSensitiveInformation')
            'Get-AutoSensitivityLabelRule' = @('Identity')
            'Get-Recipient' = @('Identity')
        }
    }
    else {
        $required = @{
            'Set-Authentication' = @('AppId', 'AppSecret', 'TenantId', 'DelegatedUser', 'OnBehalfOf')
            'Set-ScannerContentScan' = @('Enforce', 'DiscoverInformationTypes', 'LabelFilesByContent', 'RelabelFiles', 'EnforceDefaultLabel', 'EnableDlp')
            'Add-ScannerRepository' = @('Path')
            'Get-ScannerRepository' = @()
            'Start-Scan' = @()
            'Get-ScanStatus' = @()
        }
    }

    $results = foreach ($entry in $required.GetEnumerator()) {
        $command = Get-Command $entry.Key -CommandType Cmdlet, Function -ErrorAction SilentlyContinue
        $parameterNames = if ($command -and $command.Parameters) { @($command.Parameters.Keys) } else { @() }
        $missing = if ($command) { @($entry.Value | Where-Object { $_ -notin $parameterNames }) } else { @('command not installed or not connected') }
        $missingCount = @($missing).Count
        [pscustomobject]@{
            Command = $entry.Key
            Available = ($null -ne $command -and $missingCount -eq 0)
            Missing = $missing
            Module = if ($command) { $command.Source } else { $null }
        }
    }
    return [pscustomobject]@{
        Adapter = $Adapter
        Supported = (@($results | Where-Object { -not $_.Available }).Count -eq 0)
        ReadyForApply = $false
        Commands = @($results)
        Notes = if ($Adapter -eq 'Scanner') {
            @('The documented scanner command surface does not expose a label-condition rule writer. This capability probe is necessary but not sufficient to prove BCSI/PII label conditions or manual-label behavior.', 'Enforcement is not supported by this adapter.')
        } else {
            @('Command discovery proves parameter availability only. It does not prove tenant licensing, permission, label-scheme compatibility, propagation, or behavior.', 'Complete publishing-policy and independent auto-label-rule reconciliation is not implemented; tenant apply remains blocked before mutation.')
        }
    }
}

function Assert-PurviewInventory {
    param([Parameter(Mandatory)][string]$InventoryPath, [Parameter(Mandatory)][string]$TenantId)
    if (-not (Test-Path -LiteralPath $InventoryPath -PathType Leaf)) {
        throw "Managed inventory '$InventoryPath' is missing. Run Initialize-PurviewInventory with an explicitly configured environment first."
    }
    $inventory = Get-Content -LiteralPath $InventoryPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    if ($inventory.schemaVersion -ne 1 -or $inventory.tenantId -ne $TenantId) {
        throw 'Managed inventory schema or tenant ID does not match the selected environment.'
    }
    return $inventory
}

function Invoke-PurviewDeployment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EnvironmentPath,
        [switch]$Apply
    )

    $plan = Get-PurviewDeploymentPlan -EnvironmentPath $EnvironmentPath
    if (-not $Apply) {
        return $plan
    }
    $validation = Test-PurviewConfiguration -EnvironmentPath $EnvironmentPath -RequireTenantValues
    if (-not $validation.Valid) {
        throw "Apply blocked by configuration validation: $($validation.Errors -join '; ')"
    }
    throw 'Apply is blocked before any tenant mutation: the service adapter does not yet provide verified publishing-policy and independent auto-label-rule reconciliation, stable custom-SIT ownership recovery, or label-priority behavior checks. Use the returned deployment plan only; no partial labels or SIT package are written.'
}

function Get-PurviewDriftReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EnvironmentPath,
        [string]$InventoryPath = '.purview-state\managed-inventory.json'
    )
    $definitions = Get-PurviewDefinition $EnvironmentPath
    $inventory = Assert-PurviewInventory -InventoryPath (Get-PurviewConfigPath $InventoryPath) -TenantId $definitions.Environment.tenant.id
    $readCommand = Get-Command Get-Label -ErrorAction SilentlyContinue
    if (-not $readCommand -or 'Identity' -notin $readCommand.Parameters.Keys) {
        throw 'Drift export requires a connected Security & Compliance PowerShell session with Get-Label -Identity.'
    }
    $rows = foreach ($label in $definitions.Labels) {
        $id = [string]$inventory.labels[$label.key]
        if (-not $id) {
            [pscustomobject]@{ Key = $label.key; Kind = 'Label'; Status = 'NotInInventory'; Expected = $label.name; Actual = $null }
            continue
        }
        $actual = Get-Label -Identity $id -ErrorAction Stop
        if (-not $actual) {
            [pscustomobject]@{ Key = $label.key; Kind = 'Label'; Status = 'Missing'; Expected = $label.name; Actual = $null }
            continue
        }
        $differences = [System.Collections.Generic.List[string]]::new()
        if ($actual.DisplayName -ne $label.name) { $differences.Add('DisplayName') }
        if ($actual.Tooltip -ne $label.description) { $differences.Add('Tooltip') }
        $expectedEncryption = [bool]$label.protection.encrypt
        if ($label.key -eq 'highly-confidential-bes' -and -not $definitions.Environment.features.encryptBes) { $expectedEncryption = $false }
        if ([bool]$actual.EncryptionEnabled -ne $expectedEncryption) { $differences.Add('EncryptionEnabled') }
        [pscustomobject]@{
            Key = $label.key
            Kind = 'Label'
            Status = if ($differences.Count) { 'Drift' } else { 'NoChange' }
            Expected = $label.name
            Actual = $actual.DisplayName
            Differences = @($differences)
        }
    }
    return [pscustomobject]@{
        Tenant = $definitions.Environment.tenant.id
        GeneratedAtUtc = [datetime]::UtcNow.ToString('o')
        Results = @($rows)
        RemovalProposals = @()
        Limitations = @('Only inventory-owned label GUIDs are queried. Publishing-policy and auto-label rule state is not inferred from display-name matches.')
    }
}

function Enable-PurviewAutoLabeling {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EnvironmentPath,
        [Parameter(Mandatory)][string]$ApprovalRecordPath,
        [string]$InventoryPath = '.purview-state\managed-inventory.json'
    )
    if (-not (Test-Path -LiteralPath $ApprovalRecordPath -PathType Leaf)) {
        throw 'Activation requires a reviewed simulation-results and explicit approval record file.'
    }
    $approval = Get-Content -LiteralPath $ApprovalRecordPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    if ($approval.approved -ne $true -or [string]::IsNullOrWhiteSpace([string]$approval.approvedBy) -or [string]::IsNullOrWhiteSpace([string]$approval.simulationRunId)) {
        throw 'Approval record must include approved=true, approvedBy, and simulationRunId.'
    }
    throw "Automatic activation for environment '$EnvironmentPath' and inventory '$InventoryPath' is intentionally blocked: this adapter does not yet provide a verified, tenant-tested mapping for preserving manually applied labels and validating actual policy rule state. No policy was changed."
}

function Set-PurviewScannerDiscovery {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param([Parameter(Mandatory)][string]$RepositoryPath)

    $capabilities = Get-PurviewAdapterCapability -Adapter Scanner
    if (-not $capabilities.Supported) {
        $missing = @($capabilities.Commands | Where-Object { -not $_.Available } | ForEach-Object { "$($_.Command): $($_.Missing -join ', ')" })
        throw "Scanner discovery blocked by missing runtime capabilities: $($missing -join '; '). No certificate-authentication parameters are assumed."
    }
    if (-not (Test-Path -LiteralPath $RepositoryPath -PathType Container)) {
        throw "Scanner repository '$RepositoryPath' does not exist or is not reachable in this service context."
    }
    $configured = $false
    if ($PSCmdlet.ShouldProcess($RepositoryPath, 'Configure scanner discovery without enforcement or relabeling')) {
        Set-ScannerContentScan -Enforce Off -DiscoverInformationTypes All -LabelFilesByContent Off -RelabelFiles Off -EnforceDefaultLabel Off -EnableDlp On -ErrorAction Stop
        $existing = Get-ScannerRepository -ErrorAction Stop | Where-Object { [string]$_.Path -eq $RepositoryPath }
        if (-not $existing) {
            Add-ScannerRepository -Path $RepositoryPath -ErrorAction Stop
        }
        $configured = $true
    }
    return [pscustomobject]@{
        State = if ($configured) { 'DiscoveryConfigured' } else { 'Planned' }
        Enforcement = 'Off'
        RelabelFiles = 'Off'
        LabelFilesByContent = 'Off'
        RepositoryPath = $RepositoryPath
        ClassificationLabelsApplied = $false
        BlockingLimitation = 'The documented cmdlets do not provide a label-condition rule writer; this configuration performs discovery only. Do not claim BCSI/PII label selection or scanner readiness.'
    }
}

Export-ModuleMember -Function @(
    'Test-PurviewConfiguration',
    'Build-PurviewRulePackage',
    'Get-PurviewDeploymentPlan',
    'Initialize-PurviewInventory',
    'Invoke-PurviewDeployment',
    'Get-PurviewDriftReport',
    'Enable-PurviewAutoLabeling',
    'Get-PurviewAdapterCapability',
    'Set-PurviewScannerDiscovery'
)
