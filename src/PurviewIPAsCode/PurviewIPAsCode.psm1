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
        if ($environment.tenant.id -eq '00000000-0000-0000-0000-000000000000' -or $environment.tenant.labelScheme -ne 'modern') {
            $errors.Add('A real tenant ID and detected modern label scheme are required for tenant operations.')
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
    $settings.Encoding = [System.Text.Encoding]::Unicode
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
    $xmlBytes = $stream.ToArray()
    $xml = [System.Text.Encoding]::Unicode.GetString($xmlBytes).TrimStart([char]0xFEFF)
    $stream.Dispose()
    [void][xml]$xml
    $destination = Get-PurviewConfigPath $OutputPath
    $directory = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $directory)) {
        [void](New-Item -ItemType Directory -Path $directory -Force)
    }
    [System.IO.File]::WriteAllBytes($destination, $xmlBytes)
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
        LiveSupport = 'Blocked: the documented New-LabelPolicy interface cannot enforce the configured recipient user/group audience.'
    })
    foreach ($policy in $definitions.Policies) {
        $actions.Add([pscustomobject]@{
            Kind = 'AutoSensitivityLabelPolicy'
            Key = $policy.key
            Desired = $policy.mode
            Family = $policy.family
            Workload = $policy.workload
            TargetLabel = $policy.targetLabelKey
            LiveSupport = 'Create only in simulation; each sensitive-information detector is an independent rule. Verify behavior and propagation in tenant.'
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
    param(
        [ValidateSet('Service', 'Scanner')][string]$Adapter = 'Service',
        [ValidateSet('Apply', 'Activation')][string]$Operation = 'Apply'
    )

    if ($Adapter -eq 'Service') {
        $required = @{
            'Connect-IPPSSession' = @()
            'Connect-ExchangeOnline' = @()
            'Get-OrganizationConfig' = @()
            'Get-Label' = @('Identity')
            'New-Label' = @('Name', 'DisplayName', 'Tooltip', 'ContentType', 'IsLabelGroup', 'ParentId', 'EncryptionEnabled', 'EncryptionProtectionType', 'EncryptionRightsDefinitions', 'EncryptionOfflineAccessDays', 'EncryptionContentExpiredOnDateInDaysOrNever', 'EncryptionPromptUser', 'EncryptionDoNotForward')
            'Set-Label' = @('Identity', 'DisplayName', 'Tooltip', 'ContentType', 'ParentId', 'Priority', 'EncryptionEnabled', 'EncryptionProtectionType', 'EncryptionRightsDefinitions', 'EncryptionOfflineAccessDays', 'EncryptionContentExpiredOnDateInDaysOrNever', 'EncryptionPromptUser', 'EncryptionDoNotForward')
            'Get-DlpSensitiveInformationTypeRulePackage' = @('Identity')
            'New-DlpSensitiveInformationTypeRulePackage' = @('FileData')
            'Set-DlpSensitiveInformationTypeRulePackage' = @('FileData')
            'Get-AutoSensitivityLabelPolicy' = @('Identity')
            'New-AutoSensitivityLabelPolicy' = @('Name', 'ApplySensitivityLabel', 'Mode', 'Priority', 'SharePointLocation', 'OneDriveLocation', 'ExchangeLocation', 'OverwriteLabel')
            'Get-AutoSensitivityLabelRule' = @('Identity')
            'New-AutoSensitivityLabelRule' = @('Name', 'Policy', 'Workload', 'ContentContainsSensitiveInformation', 'ExceptIfContentContainsSensitiveInformation')
            'Get-Recipient' = @('Identity')
        }
        if ($Operation -eq 'Activation') {
            $required['Set-AutoSensitivityLabelPolicy'] = @('Identity', 'Mode')
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
        Operation = $Operation
        Supported = (@($results | Where-Object { -not $_.Available }).Count -eq 0)
        ReadyForApply = ($Adapter -eq 'Service' -and @($results | Where-Object { -not $_.Available }).Count -eq 0)
        Commands = @($results)
        Notes = if ($Adapter -eq 'Scanner') {
            @('The documented scanner command surface does not expose a label-condition rule writer. This capability probe is necessary but not sufficient to prove BCSI/PII label conditions or manual-label behavior.', 'Enforcement is not supported by this adapter.')
        } else {
            @('Command discovery proves parameter availability only. It does not prove tenant licensing, permission, label-scheme compatibility, propagation, or behavior.', 'Label publishing is blocked when the configured recipient audience cannot be represented by the documented New-LabelPolicy cmdlet.')
        }
    }
}

function Assert-PurviewTenantContext {
    param([Parameter(Mandatory)][string]$TenantId)
    $organization = Get-OrganizationConfig -ErrorAction Stop
    $connectedTenantId = [string](Get-PurviewPropertyValue -Object $organization -Name 'ExternalDirectoryOrganizationId')
    if ([string]::IsNullOrWhiteSpace($connectedTenantId) -or $connectedTenantId -ine $TenantId) {
        throw "Connected Security & Compliance tenant '$connectedTenantId' does not match configured tenant '$TenantId'."
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

function Save-PurviewInventory {
    param([Parameter(Mandatory)][string]$InventoryPath, [Parameter(Mandatory)]$Inventory)
    $directory = Split-Path -Parent $InventoryPath
    if ($directory) { [void](New-Item -ItemType Directory -Path $directory -Force) }
    $temporary = "$InventoryPath.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $json = $Inventory | ConvertTo-Json -Depth 12
        [System.IO.File]::WriteAllText($temporary, "$json`n", [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $InventoryPath -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}

function Get-PurviewIdentityGuid {
    param([Parameter(Mandatory)]$Object, [Parameter(Mandatory)][string]$Kind)
    foreach ($propertyName in @('Guid', 'ObjectId', 'Id', 'Identity')) {
        $property = $Object.PSObject.Properties[$propertyName]
        if ($property) {
            [guid]$parsedGuid = [guid]::Empty
            if ([guid]::TryParse([string]$property.Value, [ref]$parsedGuid)) {
                return $parsedGuid.ToString()
            }
        }
    }
    throw "The $Kind cmdlet did not return a GUID identity; the resource cannot be recorded safely in the ownership inventory."
}

function Get-PurviewLabelArgument {
    param([Parameter(Mandatory)]$Label, [Parameter(Mandatory)]$Definitions)
    $parentId = $null
    if ($Label.parent) {
        $parent = $Definitions.Labels | Where-Object key -eq $Label.parent | Select-Object -First 1
        $parentId = [string]$Definitions.Inventory.labels[$parent.key]
        if (-not $parentId) { throw "Parent label '$($Label.parent)' must be created and recorded before '$($Label.key)'." }
    }
    $rights = @()
    $protectionType = 'Template'
    $promptUser = $false
    if ($Label.protection.mode -eq 'fixed-group') {
        $group = $Definitions.Environment.groups | Where-Object key -eq $Label.protection.groupKey | Select-Object -First 1
        if (-not $group) { throw "Protection group '$($Label.protection.groupKey)' is not configured." }
        $rights = @("$($group.email):$($Label.protection.rights -join ',')")
    }
    elseif ($Label.protection.mode -eq 'user-defined') {
        $protectionType = 'UserDefined'
        $promptUser = $true
    }
    $encryption = [bool]$Label.protection.encrypt
    if ($Label.key -eq 'highly-confidential-bes' -and -not $Definitions.Environment.features.encryptBes) {
        $encryption = $false
    }
    return @{
        Name = [string]$Label.name
        DisplayName = [string]$Label.name
        Tooltip = [string]$Label.description
        ContentType = @('File', 'Email')
        IsLabelGroup = [bool](@($Definitions.Labels | Where-Object parent -eq $Label.key).Count -gt 0)
        ParentId = $parentId
        Priority = [int]$Label.priority
        EncryptionEnabled = $encryption
        EncryptionProtectionType = $protectionType
        EncryptionRightsDefinitions = $rights
        EncryptionOfflineAccessDays = if ($Label.protection.offlineAccessDays) { [int]$Label.protection.offlineAccessDays } else { $null }
        EncryptionContentExpiredOnDateInDaysOrNever = if ($Label.protection.contentExpiration) { [string]$Label.protection.contentExpiration } else { 'Never' }
        EncryptionPromptUser = $promptUser
        EncryptionDoNotForward = [bool]$Label.protection.doNotForward
    }
}

function Get-PurviewLabelNameMatch {
    param(
        [Parameter(Mandatory)]$Label,
        [Parameter(Mandatory)]$Inventory,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$ExistingLabels
    )
    $nameMatches = @($ExistingLabels | Where-Object { [string]$_.DisplayName -eq [string]$Label.name })
    if (-not $Label.parent) { return @($nameMatches | Where-Object { -not $_.ParentId }) }
    $parentId = [string]$Inventory.labels[$Label.parent]
    if (-not $parentId) { return @() }
    return @($nameMatches | Where-Object { [string]$_.ParentId -eq $parentId })
}

function Test-PurviewLabelMatch {
    param([Parameter(Mandatory)]$Actual, [Parameter(Mandatory)]$Expected)
    if ($Actual.DisplayName -ne $Expected.DisplayName -or $Actual.Tooltip -ne $Expected.Tooltip -or
        [int]$Actual.Priority -ne [int]$Expected.Priority -or
        [bool]$Actual.EncryptionEnabled -ne [bool]$Expected.EncryptionEnabled -or
        [bool]$Actual.EncryptionDoNotForward -ne [bool]$Expected.EncryptionDoNotForward) {
        return $false
    }
    if ($Expected.ParentId -and [string]$Actual.ParentId -ne [string]$Expected.ParentId) { return $false }
    if (-not $Expected.ParentId -and $Actual.ParentId) { return $false }
    if ([bool]$Actual.IsLabelGroup -ne [bool]$Expected.IsLabelGroup) { return $false }
    if (($Actual.ContentType -join ',') -ne ($Expected.ContentType -join ',')) { return $false }
    if ([string]$Actual.EncryptionProtectionType -ne [string]$Expected.EncryptionProtectionType -or
        [string]$Actual.EncryptionOfflineAccessDays -ne [string]$Expected.EncryptionOfflineAccessDays -or
        [string]$Actual.EncryptionContentExpiredOnDateInDaysOrNever -ne [string]$Expected.EncryptionContentExpiredOnDateInDaysOrNever -or
        [bool]$Actual.EncryptionPromptUser -ne [bool]$Expected.EncryptionPromptUser -or
        (@($Actual.EncryptionRightsDefinitions) -join '|') -ne (@($Expected.EncryptionRightsDefinitions) -join '|')) {
        return $false
    }
    return $true
}

function Get-PurviewSensitiveInformationTypeName {
    param([Parameter(Mandatory)][string]$SitKey, [Parameter(Mandatory)]$Definitions)
    if ($SitKey -eq 'us-ssn') { return 'U.S. Social Security Number (SSN)' }
    $detector = $Definitions.Detection.detectors | Where-Object key -eq $SitKey | Select-Object -First 1
    if (-not $detector) { throw "Sensitive information type '$SitKey' is not declared in the detection configuration." }
    return [string]$detector.name
}

function Get-PurviewPropertyValue {
    param([Parameter(Mandatory)]$Object, [Parameter(Mandatory)][string]$Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Get-PurviewRulePackageById {
    param([Parameter(Mandatory)][string]$PackageId)
    $packages = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
    return $packages | Where-Object {
        $package = $_
        $identityParts = foreach ($propertyName in @('Identity', 'Guid', 'Id', 'RuleCollectionName')) {
            $value = Get-PurviewPropertyValue -Object $package -Name $propertyName
            if ($value) { [string]$value }
        }
        ($identityParts -join ' ') -match [regex]::Escape($PackageId)
    } | Select-Object -First 1
}

function Get-PurviewAutoPolicyArgument {
    param(
        [Parameter(Mandatory)]$Policy,
        [Parameter(Mandatory)]$Definitions,
        [Parameter(Mandatory)][string]$LabelId,
        [ValidateSet('TestWithoutNotifications', 'Enable')][string]$Mode = 'TestWithoutNotifications'
    )
    $targetLabel = $Definitions.Labels | Where-Object key -eq $Policy.targetLabelKey | Select-Object -First 1
    if (-not $targetLabel) { throw "Auto-label policy '$($Policy.key)' references an unknown target label." }
    $arguments = @{
        Name = [string]$Policy.name
        ApplySensitivityLabel = $LabelId
        Mode = $Mode
        Priority = [int]$targetLabel.priority
        OverwriteLabel = $false
    }
    $scopeName = switch ($Policy.workload) {
        'SharePoint' { 'sharePointLocations' }
        'OneDrive' { 'oneDriveLocations' }
        'Exchange' { 'exchangeLocations' }
        default { throw "Unsupported auto-label workload '$($Policy.workload)'." }
    }
    $locations = @($Definitions.Environment.scopes[$scopeName] | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($locations.Count -eq 0) { return $null }
    switch ($Policy.workload) {
        'SharePoint' { $arguments.SharePointLocation = $locations }
        'OneDrive' { $arguments.OneDriveLocation = $locations }
        'Exchange' { $arguments.ExchangeLocation = $locations }
    }
    return $arguments
}

function Test-PurviewAutoPolicyMatch {
    param([Parameter(Mandatory)]$Actual, [Parameter(Mandatory)]$Expected)
    if ([string]$Actual.Name -ne [string]$Expected.Name -or
        [string]$Actual.ApplySensitivityLabel -ne [string]$Expected.ApplySensitivityLabel -or
        [string]$Actual.Mode -ne [string]$Expected.Mode -or
        [int]$Actual.Priority -ne [int]$Expected.Priority -or
        [bool]$Actual.OverwriteLabel -ne [bool]$Expected.OverwriteLabel) { return $false }
    foreach ($scope in @('SharePointLocation', 'OneDriveLocation', 'ExchangeLocation')) {
        $expectedValues = @($Expected[$scope] | ForEach-Object { [string]$_ } | Sort-Object)
        $actualValues = @($Actual.$scope | ForEach-Object { [string]$_ } | Sort-Object)
        if (($expectedValues -join '|') -ne ($actualValues -join '|')) { return $false }
    }
    return $true
}

function Test-PurviewAutoRuleMatch {
    param([Parameter(Mandatory)]$Actual, [Parameter(Mandatory)]$Expected)
    if ([string]$Actual.Name -ne [string]$Expected.Name -or
        [string]$Actual.Policy -ne [string]$Expected.Policy -or
        [string]$Actual.Workload -ne [string]$Expected.Workload) { return $false }
    foreach ($propertyName in @('ContentContainsSensitiveInformation', 'ExceptIfContentContainsSensitiveInformation')) {
        $actualProperty = $Actual.PSObject.Properties[$propertyName]
        $expectedValue = if ($Expected.ContainsKey($propertyName)) { $Expected[$propertyName] } else { @() }
        $actualValue = if ($actualProperty) { $actualProperty.Value } else { @() }
        $actualItems = @($actualValue | Where-Object { $null -ne $_ } | ForEach-Object {
            '{0}|{1}|{2}' -f [string]$_.Name, [string]$_.minCount, [string]$_.minConfidence
        } | Sort-Object)
        $expectedItems = @($expectedValue | Where-Object { $null -ne $_ } | ForEach-Object {
            '{0}|{1}|{2}' -f [string]$_.Name, [string]$_.minCount, [string]$_.minConfidence
        } | Sort-Object)
        if (($actualItems -join ';') -ne ($expectedItems -join ';')) { return $false }
    }
    return $true
}

function Get-PurviewAutoRuleArgument {
    param([Parameter(Mandatory)]$Policy, [Parameter(Mandatory)]$Condition, [Parameter(Mandatory)]$Definitions)
    $sitName = Get-PurviewSensitiveInformationTypeName -SitKey $Condition.sitKey -Definitions $Definitions
    $match = @{ Name = $sitName; minCount = [string]$Condition.minCount }
    if ($Condition.minConfidence) { $match.minConfidence = [string]$Condition.minConfidence }
    $arguments = @{
        Name = "$($Policy.key)-$($Condition.sitKey)"
        Policy = [string]$Policy.name
        Workload = [string]$Policy.workload
        ContentContainsSensitiveInformation = @($match)
    }
    if ($null -ne $Condition.maxCount) {
        if ([int]$Condition.maxCount -lt [int]$Condition.minCount) { throw "Invalid count range for '$($Policy.key)'." }
        $arguments.ExceptIfContentContainsSensitiveInformation = @(@{
            Name = $sitName
            minCount = [string]([int]$Condition.maxCount + 1)
            minConfidence = [string]$Condition.minConfidence
        })
    }
    return $arguments
}

function Invoke-PurviewDeployment {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EnvironmentPath,
        [switch]$Apply,
        [string]$InventoryPath = '.purview-state\managed-inventory.json'
    )

    $plan = Get-PurviewDeploymentPlan -EnvironmentPath $EnvironmentPath
    if (-not $Apply) {
        return $plan
    }
    $validation = Test-PurviewConfiguration -EnvironmentPath $EnvironmentPath -RequireTenantValues
    if (-not $validation.Valid) {
        throw "Apply blocked by configuration validation: $($validation.Errors -join '; ')"
    }
    $definitions = Get-PurviewDefinition $EnvironmentPath
    $inventoryPath = Get-PurviewConfigPath $InventoryPath
    $inventory = Assert-PurviewInventory -InventoryPath $inventoryPath -TenantId $definitions.Environment.tenant.id
    $capabilities = Get-PurviewAdapterCapability -Adapter Service -Operation Apply
    if (-not $capabilities.ReadyForApply) {
        $missing = @($capabilities.Commands | Where-Object { -not $_.Available } | ForEach-Object { "$($_.Command): $($_.Missing -join ', ')" })
        throw "Apply blocked before mutation by missing documented runtime capabilities: $($missing -join '; ')"
    }
    Assert-PurviewTenantContext -TenantId $definitions.Environment.tenant.id
    if ($definitions.Environment.tenant.labelScheme -ne 'modern') {
        throw 'Apply requires a verified modern label scheme because the approved taxonomy uses parent label groups.'
    }
    if (@($definitions.Environment.ownership.managedLabelKeys).Count -ne @($definitions.Labels).Count -or
        @($definitions.Labels | Where-Object { $_.key -notin $definitions.Environment.ownership.managedLabelKeys }).Count -gt 0) {
        throw 'The ownership allowlist must enumerate every configured label before apply.'
    }

    foreach ($group in $definitions.Environment.groups) {
        $recipient = Get-Recipient -Identity $group.email -ErrorAction Stop
        if (-not $recipient -or [string]$recipient.PrimarySmtpAddress -ne [string]$group.email) {
            throw "Configured group '$($group.key)' did not resolve to the expected mail-enabled recipient '$($group.email)'."
        }
        if ($group.purpose -eq 'bes-authorized' -and [string]$recipient.RecipientTypeDetails -ne 'MailUniversalSecurityGroup') {
            throw "BES Authorized '$($group.email)' must resolve to an email-enabled security group."
        }
        $recipientObjectId = [string](Get-PurviewPropertyValue -Object $recipient -Name 'ExternalDirectoryObjectId')
        if ($group.id -and $recipientObjectId -ne [string]$group.id) {
            throw "Configured group '$($group.key)' ID does not match the resolved recipient."
        }
    }

    $existingLabels = @(Get-Label -ErrorAction Stop)
    foreach ($label in $definitions.Labels) {
        $ownedId = [string]$inventory.labels[$label.key]
        $sameName = @(Get-PurviewLabelNameMatch -Label $label -Inventory $inventory -ExistingLabels $existingLabels)
        if (-not $ownedId -and $sameName.Count -gt 0) {
            throw "Label name collision for '$($label.name)'; the resource is not in the ownership inventory and will not be adopted."
        }
        if ($ownedId -and $sameName.Count -gt 0 -and @($sameName | Where-Object { [string]$_.Guid -ne $ownedId }).Count -gt 0) {
            throw "Owned label '$($label.key)' collides with a different tenant label named '$($label.name)'."
        }
    }
    $policyKeys = @($definitions.Policies | ForEach-Object key)
    if (@($policyKeys | Where-Object { $_ -notin $definitions.Environment.ownership.managedPolicyKeys }).Count -gt 0 -or
        $definitions.Publishing.policyKey -notin $definitions.Environment.ownership.managedPolicyKeys) {
        throw 'The ownership allowlist must enumerate every configured auto-label policy before apply.'
    }

    $existingAutoPolicies = @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop)
    $existingAutoRules = @(Get-AutoSensitivityLabelRule -ErrorAction Stop)
    foreach ($policy in $definitions.Policies) {
        $ownedPolicy = $inventory.policies[$policy.key]
        if (-not $ownedPolicy -or -not $ownedPolicy.policyId) {
            if (@($existingAutoPolicies | Where-Object { [string]$_.Name -eq [string]$policy.name }).Count -gt 0) {
                throw "Auto-label policy name collision for '$($policy.name)'; refusing to adopt the existing policy."
            }
        }
        elseif ($ownedPolicy.policyId) {
            $actualPolicy = Get-AutoSensitivityLabelPolicy -Identity ([string]$ownedPolicy.policyId) -ErrorAction Stop
            if ($actualPolicy) {
                $targetLabelId = [string]$inventory.labels[$policy.targetLabelKey]
                if (-not $targetLabelId) { throw "Owned auto-label policy '$($policy.key)' has no inventory-owned target label." }
                $expectedMode = if ([string]$ownedPolicy.mode -eq 'Enable') { 'Enable' } else { 'TestWithoutNotifications' }
                $expectedPolicy = Get-PurviewAutoPolicyArgument -Policy $policy -Definitions $definitions -LabelId $targetLabelId -Mode $expectedMode
                if (-not $expectedPolicy -or -not (Test-PurviewAutoPolicyMatch -Actual $actualPolicy -Expected $expectedPolicy)) {
                    throw "Owned auto-label policy '$($policy.key)' has scope or behavior drift; apply stopped before any tenant mutation."
                }
            }
            elseif (@($existingAutoPolicies | Where-Object { [string]$_.Name -eq [string]$policy.name }).Count -gt 0) {
                throw "Owned auto-label policy '$($policy.key)' is missing by ID, but another policy uses its name; refusing to adopt or duplicate it."
            }
        }
        foreach ($condition in $policy.conditions) {
            $ruleName = "$($policy.key)-$($condition.sitKey)"
            $ownedRuleId = if ($ownedPolicy -and $ownedPolicy.rules) { [string]$ownedPolicy.rules[$condition.sitKey] } else { '' }
            if (-not $ownedRuleId -and @($existingAutoRules | Where-Object { [string]$_.Name -eq $ruleName }).Count -gt 0) {
                throw "Auto-label rule name collision for '$ruleName'; refusing to adopt the existing rule."
            }
            if ($ownedRuleId) {
                $actualRule = Get-AutoSensitivityLabelRule -Identity $ownedRuleId -ErrorAction Stop
                if ($actualRule) {
                    $expectedRule = Get-PurviewAutoRuleArgument -Policy $policy -Condition $condition -Definitions $definitions
                    if (-not (Test-PurviewAutoRuleMatch -Actual $actualRule -Expected $expectedRule)) {
                        throw "Owned auto-label rule '$($policy.key)/$($condition.sitKey)' has condition drift; apply stopped before any tenant mutation."
                    }
                }
                elseif (@($existingAutoRules | Where-Object { [string]$_.Name -eq $ruleName }).Count -gt 0) {
                    throw "Owned auto-label rule '$ruleName' is missing by ID, but another rule uses its name; refusing to adopt or duplicate it."
                }
            }
        }
    }
    $packageId = [string]$definitions.Detection.package.id
    $allRulePackages = @(Get-DlpSensitiveInformationTypeRulePackage -ErrorAction Stop)
    $packageById = $allRulePackages | Where-Object {
        $package = $_
        $identityParts = foreach ($propertyName in @('Identity', 'Guid', 'Id', 'RuleCollectionName')) {
            $value = Get-PurviewPropertyValue -Object $package -Name $propertyName
            if ($value) { [string]$value }
        }
        ($identityParts -join ' ') -match [regex]::Escape($packageId)
    } | Select-Object -First 1
    $packageNameCollision = @($allRulePackages | Where-Object {
        $package = $_
        $names = foreach ($propertyName in @('LocalizedName', 'Name', 'RuleCollectionName')) {
            $value = Get-PurviewPropertyValue -Object $package -Name $propertyName
            if ($value) { [string]$value }
        }
        $names -contains [string]$definitions.Detection.package.name
    })
    if ($packageNameCollision -and -not $packageById) {
        throw "Custom SIT package name collision for '$($definitions.Detection.package.name)'; refusing to adopt it."
    }
    if ($packageById -and [string]$inventory.rulePackageId -ne $packageId) {
        throw "Custom SIT package '$packageId' exists but is not recorded as inventory-owned; refusing to adopt it."
    }

    $actions = [System.Collections.Generic.List[object]]::new()
    $labelIds = @{}
    foreach ($label in $definitions.Labels) {
        $expected = Get-PurviewLabelArgument -Label $label -Definitions (@{ Labels = $definitions.Labels; Environment = $definitions.Environment; Inventory = $inventory })
        $id = [string]$inventory.labels[$label.key]
        $actual = if ($id) { Get-Label -Identity $id -ErrorAction Stop } else { $null }
        if (-not $actual) {
            if (@(Get-PurviewLabelNameMatch -Label $label -Inventory $inventory -ExistingLabels $existingLabels).Count -gt 0) {
                throw "Label '$($label.key)' already exists outside the ownership inventory and will not be adopted."
            }
            $createArgs = @{}
            foreach ($name in @('Name', 'DisplayName', 'Tooltip', 'ContentType', 'IsLabelGroup', 'ParentId', 'EncryptionEnabled', 'EncryptionProtectionType', 'EncryptionRightsDefinitions', 'EncryptionOfflineAccessDays', 'EncryptionContentExpiredOnDateInDaysOrNever', 'EncryptionPromptUser', 'EncryptionDoNotForward')) {
                if ($null -ne $expected[$name] -and -not ($name -eq 'ParentId' -and -not $expected[$name])) { $createArgs[$name] = $expected[$name] }
            }
            $created = New-Label @createArgs -ErrorAction Stop
            $id = Get-PurviewIdentityGuid -Object $created -Kind 'sensitivity label'
            $inventory.labels[$label.key] = $id
            Save-PurviewInventory -InventoryPath $inventoryPath -Inventory $inventory
            $expected.ParentId = if ($label.parent) { [string]$inventory.labels[$label.parent] } else { $null }
            Set-Label -Identity $id -Priority $expected.Priority -ErrorAction Stop | Out-Null
            $actions.Add([pscustomobject]@{ Key = $label.key; Kind = 'Label'; Status = 'Created'; Id = $id })
        }
        else {
            $id = Get-PurviewIdentityGuid -Object $actual -Kind 'sensitivity label'
            $labelIds[$label.key] = $id
            $expected.ParentId = if ($label.parent) { [string]$inventory.labels[$label.parent] } else { $null }
            if (-not (Test-PurviewLabelMatch -Actual $actual -Expected $expected)) {
                Set-Label -Identity $id -DisplayName $expected.DisplayName -Tooltip $expected.Tooltip -ContentType $expected.ContentType -ParentId $expected.ParentId -Priority $expected.Priority -EncryptionEnabled $expected.EncryptionEnabled -EncryptionProtectionType $expected.EncryptionProtectionType -EncryptionRightsDefinitions $expected.EncryptionRightsDefinitions -EncryptionOfflineAccessDays $expected.EncryptionOfflineAccessDays -EncryptionContentExpiredOnDateInDaysOrNever $expected.EncryptionContentExpiredOnDateInDaysOrNever -EncryptionPromptUser $expected.EncryptionPromptUser -EncryptionDoNotForward $expected.EncryptionDoNotForward -ErrorAction Stop | Out-Null
                $actions.Add([pscustomobject]@{ Key = $label.key; Kind = 'Label'; Status = 'Updated'; Id = $id })
            }
            else {
                $actions.Add([pscustomobject]@{ Key = $label.key; Kind = 'Label'; Status = 'NoChange'; Id = $id })
            }
            $inventory.labels[$label.key] = $id
            Save-PurviewInventory -InventoryPath $inventoryPath -Inventory $inventory
        }
        if (-not $labelIds.ContainsKey($label.key)) { $labelIds[$label.key] = $id }
    }

    $rulePackagePath = Join-Path $script:RepositoryRoot 'config\generated\bcsi-rule-package.xml'
    if (-not (Test-Path -LiteralPath $rulePackagePath -PathType Leaf)) {
        [void](Build-PurviewRulePackage -OutputPath $rulePackagePath)
    }
    $packageBytes = [System.IO.File]::ReadAllBytes($rulePackagePath)
    $package = $packageById
    if (-not $package) {
        $package = New-DlpSensitiveInformationTypeRulePackage -FileData $packageBytes -ErrorAction Stop
        $inventory.rulePackageId = $packageId
        Save-PurviewInventory -InventoryPath $inventoryPath -Inventory $inventory
        $actions.Add([pscustomobject]@{ Key = 'bcsi-rule-package'; Kind = 'SensitiveInformationTypePackage'; Status = 'Created'; Id = $packageId })
    }
    else {
        if ([string]$inventory.rulePackageId -ne $packageId) {
            throw "Custom SIT package '$packageId' exists but is not recorded as inventory-owned; refusing to adopt it."
        }
        if ([string]$inventory.rulePackageId -ne $packageId) {
            throw "Custom SIT package '$packageId' exists but is not recorded as inventory-owned; refusing to adopt it."
        }
        $version = [string]$package.Version
        if ($version -ne [string]$definitions.Detection.package.version) {
            Set-DlpSensitiveInformationTypeRulePackage -FileData $packageBytes -ErrorAction Stop | Out-Null
            $actions.Add([pscustomobject]@{ Key = 'bcsi-rule-package'; Kind = 'SensitiveInformationTypePackage'; Status = 'Updated'; Id = $packageId })
        }
        else { $actions.Add([pscustomobject]@{ Key = 'bcsi-rule-package'; Kind = 'SensitiveInformationTypePackage'; Status = 'NoChange'; Id = $packageId }) }
        $inventory.rulePackageId = $packageId
        Save-PurviewInventory -InventoryPath $inventoryPath -Inventory $inventory
    }

    foreach ($policy in $definitions.Policies) {
        $targetLabelId = [string]$labelIds[$policy.targetLabelKey]
        $policyArguments = Get-PurviewAutoPolicyArgument -Policy $policy -Definitions $definitions -LabelId $targetLabelId
        if (-not $policyArguments) {
            $actions.Add([pscustomobject]@{ Key = $policy.key; Kind = 'AutoLabelPolicy'; Status = 'Blocked'; Reason = "No explicit $($policy.workload) locations are configured." })
            continue
        }
        $ownedPolicy = $inventory.policies[$policy.key]
        $existingPolicy = if ($ownedPolicy -and $ownedPolicy.policyId) { Get-AutoSensitivityLabelPolicy -Identity ([string]$ownedPolicy.policyId) -ErrorAction Stop } else { $null }
        if (-not $existingPolicy) {
            $existingPolicy = New-AutoSensitivityLabelPolicy @policyArguments -ErrorAction Stop
            $policyId = Get-PurviewIdentityGuid -Object $existingPolicy -Kind 'auto-label policy'
            $inventory.policies[$policy.key] = [ordered]@{ kind = 'AutoLabel'; policyId = $policyId; mode = 'TestWithoutNotifications'; rules = [ordered]@{} }
            Save-PurviewInventory -InventoryPath $inventoryPath -Inventory $inventory
            $actions.Add([pscustomobject]@{ Key = $policy.key; Kind = 'AutoLabelPolicy'; Status = 'Created'; Id = $policyId })
        }
        else {
            $policyId = Get-PurviewIdentityGuid -Object $existingPolicy -Kind 'auto-label policy'
            $expectedMode = if ([string]$ownedPolicy.mode -eq 'Enable') { 'Enable' } else { 'TestWithoutNotifications' }
            $expectedForState = Get-PurviewAutoPolicyArgument -Policy $policy -Definitions $definitions -LabelId $targetLabelId -Mode $expectedMode
            if (-not (Test-PurviewAutoPolicyMatch -Actual $existingPolicy -Expected $expectedForState)) {
                throw "Owned auto-label policy '$($policy.key)' has drift in its label, mode, or overwrite behavior. Automatic repair is blocked until live tenant behavior is reviewed."
            }
            $inventory.policies[$policy.key].policyId = $policyId
            if (-not $inventory.policies[$policy.key].rules) { $inventory.policies[$policy.key].rules = [ordered]@{} }
            Save-PurviewInventory -InventoryPath $inventoryPath -Inventory $inventory
        }

        foreach ($condition in $policy.conditions) {
            $ruleArguments = Get-PurviewAutoRuleArgument -Policy $policy -Condition $condition -Definitions $definitions
            $ruleKey = "$($condition.sitKey)"
            $ownedRuleId = [string]$inventory.policies[$policy.key].rules[$ruleKey]
            $actualRule = if ($ownedRuleId) { Get-AutoSensitivityLabelRule -Identity $ownedRuleId -ErrorAction Stop } else { $null }
            if (-not $actualRule) {
                $actualRule = New-AutoSensitivityLabelRule @ruleArguments -ErrorAction Stop
                $ruleId = Get-PurviewIdentityGuid -Object $actualRule -Kind 'auto-label rule'
                $inventory.policies[$policy.key].rules[$ruleKey] = $ruleId
                Save-PurviewInventory -InventoryPath $inventoryPath -Inventory $inventory
                $actions.Add([pscustomobject]@{ Key = "$($policy.key)/$ruleKey"; Kind = 'AutoLabelRule'; Status = 'Created'; Id = $ruleId })
            }
            else {
                $ruleId = Get-PurviewIdentityGuid -Object $actualRule -Kind 'auto-label rule'
                if (-not (Test-PurviewAutoRuleMatch -Actual $actualRule -Expected $ruleArguments)) {
                    throw "Owned auto-label rule '$($policy.key)/$ruleKey' has condition drift; automatic repair is blocked pending tenant review."
                }
                $inventory.policies[$policy.key].rules[$ruleKey] = $ruleId
                Save-PurviewInventory -InventoryPath $inventoryPath -Inventory $inventory
                $actions.Add([pscustomobject]@{ Key = "$($policy.key)/$ruleKey"; Kind = 'AutoLabelRule'; Status = 'NoChange'; Id = $ruleId })
            }
        }
    }

    $publishing = if ($definitions.Environment.features.publishingPolicy) {
        [pscustomobject]@{
            Key = $definitions.Publishing.policyKey
            Kind = 'LabelPublishingPolicy'
            Status = 'Blocked'
            Reason = 'The documented New-LabelPolicy cmdlet has no recipient-user/group audience parameter. Creating a policy without an enforceable audience could publish labels tenant-wide, so no publishing policy was created.'
        }
    } else { $null }
    return [pscustomobject]@{
        Status = if ($publishing -or @($actions | Where-Object Status -eq 'Blocked').Count -gt 0) { 'PartiallyApplied' } else { 'Applied' }
        Tenant = $definitions.Environment.tenant.id
        Actions = @($actions)
        Limitations = @($publishing)
        InventoryPath = $inventoryPath
    }
}

function Get-PurviewDriftReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EnvironmentPath,
        [string]$InventoryPath = '.purview-state\managed-inventory.json'
    )
    $definitions = Get-PurviewDefinition $EnvironmentPath
    $inventory = Assert-PurviewInventory -InventoryPath (Get-PurviewConfigPath $InventoryPath) -TenantId $definitions.Environment.tenant.id
    Assert-PurviewTenantContext -TenantId $definitions.Environment.tenant.id
    $readCommand = Get-Command Get-Label -ErrorAction SilentlyContinue
    if (-not $readCommand -or 'Identity' -notin $readCommand.Parameters.Keys) {
        throw 'Drift export requires a connected Security & Compliance PowerShell session with Get-Label -Identity.'
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($label in $definitions.Labels) {
        $id = [string]$inventory.labels[$label.key]
        if (-not $id) {
            $rows.Add([pscustomobject]@{ Key = $label.key; Kind = 'Label'; Status = 'NotInInventory'; Expected = $label.name; Actual = $null })
            continue
        }
        $actual = Get-Label -Identity $id -ErrorAction Stop
        if (-not $actual) {
            $rows.Add([pscustomobject]@{ Key = $label.key; Kind = 'Label'; Status = 'Missing'; Expected = $label.name; Actual = $null })
            continue
        }
        $expected = Get-PurviewLabelArgument -Label $label -Definitions (@{ Labels = $definitions.Labels; Environment = $definitions.Environment; Inventory = $inventory })
        $rows.Add([pscustomobject]@{
            Key = $label.key
            Kind = 'Label'
            Status = if (Test-PurviewLabelMatch -Actual $actual -Expected $expected) { 'NoChange' } else { 'Drift' }
            Expected = $label.name
            Actual = $actual.DisplayName
        })
    }
    foreach ($policy in $definitions.Policies) {
        $owned = $inventory.policies[$policy.key]
        if (-not $owned -or -not $owned.policyId) {
            $rows.Add([pscustomobject]@{ Key = $policy.key; Kind = 'AutoLabelPolicy'; Status = 'NotInInventory'; Expected = $policy.name; Actual = $null })
            continue
        }
        $actual = Get-AutoSensitivityLabelPolicy -Identity ([string]$owned.policyId) -ErrorAction Stop
        if (-not $actual) {
            $rows.Add([pscustomobject]@{ Key = $policy.key; Kind = 'AutoLabelPolicy'; Status = 'Missing'; Expected = $policy.name; Actual = $null })
            continue
        }
        $targetId = [string]$inventory.labels[$policy.targetLabelKey]
        $expectedMode = if ([string]$owned.mode -eq 'Enable') { 'Enable' } else { 'TestWithoutNotifications' }
        $expected = if ($targetId) { Get-PurviewAutoPolicyArgument -Policy $policy -Definitions $definitions -LabelId $targetId -Mode $expectedMode } else { $null }
        $rows.Add([pscustomobject]@{
            Key = $policy.key
            Kind = 'AutoLabelPolicy'
            Status = if ($expected -and (Test-PurviewAutoPolicyMatch -Actual $actual -Expected $expected)) { 'NoChange' } else { 'Drift' }
            Expected = $policy.name
            Actual = $actual.Name
        })
        foreach ($condition in $policy.conditions) {
            $ruleId = if ($owned.rules) { [string]$owned.rules[$condition.sitKey] } else { '' }
            if (-not $ruleId) {
                $rows.Add([pscustomobject]@{ Key = "$($policy.key)/$($condition.sitKey)"; Kind = 'AutoLabelRule'; Status = 'NotInInventory'; Expected = $condition.sitKey; Actual = $null })
                continue
            }
            $actualRule = Get-AutoSensitivityLabelRule -Identity $ruleId -ErrorAction Stop
            if (-not $actualRule) {
                $rows.Add([pscustomobject]@{ Key = "$($policy.key)/$($condition.sitKey)"; Kind = 'AutoLabelRule'; Status = 'Missing'; Expected = $condition.sitKey; Actual = $null })
                continue
            }
            $expectedRule = Get-PurviewAutoRuleArgument -Policy $policy -Condition $condition -Definitions $definitions
            $rows.Add([pscustomobject]@{
                Key = "$($policy.key)/$($condition.sitKey)"
                Kind = 'AutoLabelRule'
                Status = if (Test-PurviewAutoRuleMatch -Actual $actualRule -Expected $expectedRule) { 'NoChange' } else { 'Drift' }
                Expected = $condition.sitKey
                Actual = $actualRule.Name
            })
        }
    }
    if ($inventory.rulePackageId) {
        $package = Get-PurviewRulePackageById -PackageId ([string]$inventory.rulePackageId)
        $rows.Add([pscustomobject]@{
            Key = 'bcsi-rule-package'
            Kind = 'SensitiveInformationTypePackage'
            Status = if (-not $package) { 'Missing' } elseif ([string]$package.Version -eq [string]$definitions.Detection.package.version) { 'NoChange' } else { 'Drift' }
            Expected = [string]$definitions.Detection.package.version
            Actual = if ($package) { [string]$package.Version } else { $null }
        })
    }
    else {
        $rows.Add([pscustomobject]@{ Key = 'bcsi-rule-package'; Kind = 'SensitiveInformationTypePackage'; Status = 'NotInInventory'; Expected = [string]$definitions.Detection.package.version; Actual = $null })
    }
    $rows.Add([pscustomobject]@{
        Key = $definitions.Publishing.policyKey
        Kind = 'LabelPublishingPolicy'
        Status = 'Blocked'
        Expected = $definitions.Publishing.name
        Actual = $null
        Limitation = 'Recipient-user/group audience is not expressible through the documented New-LabelPolicy cmdlet surface.'
    })
    return [pscustomobject]@{
        Tenant = $definitions.Environment.tenant.id
        GeneratedAtUtc = [datetime]::UtcNow.ToString('o')
        Results = @($rows.ToArray())
        RemovalProposals = @()
        Limitations = @('Only inventory-owned GUIDs are queried. Name-based matches are never adopted. Publishing policy remains blocked due to the missing documented recipient audience parameter.')
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
    if (-not $approval.ContainsKey('manualLabelPreservationVerified') -or $approval.manualLabelPreservationVerified -ne $true) {
        throw 'Activation requires manualLabelPreservationVerified=true in the approval record, backed by review of the named simulation run.'
    }
    $definitions = Get-PurviewDefinition $EnvironmentPath
    $inventoryPath = Get-PurviewConfigPath $InventoryPath
    $inventory = Assert-PurviewInventory -InventoryPath $inventoryPath -TenantId $definitions.Environment.tenant.id
    $capabilities = Get-PurviewAdapterCapability -Adapter Service -Operation Activation
    if (-not $capabilities.ReadyForApply) {
        throw 'Activation is blocked because the connected Security & Compliance session lacks the documented auto-label policy update command surface.'
    }
    Assert-PurviewTenantContext -TenantId $definitions.Environment.tenant.id
    $policies = foreach ($policy in $definitions.Policies) {
        $targetLabelId = [string]$inventory.labels[$policy.targetLabelKey]
        if (-not $targetLabelId) { throw "Activation blocked: target label for '$($policy.key)' is not inventory-owned." }
        $expectedPolicy = Get-PurviewAutoPolicyArgument -Policy $policy -Definitions $definitions -LabelId $targetLabelId
        if (-not $expectedPolicy) { continue }
        $owned = $inventory.policies[$policy.key]
        if (-not $owned -or $owned.kind -ne 'AutoLabel' -or -not $owned.policyId) {
            throw "Activation blocked: policy '$($policy.key)' is not recorded as managed in the tenant inventory."
        }
        $actual = Get-AutoSensitivityLabelPolicy -Identity ([string]$owned.policyId) -ErrorAction Stop
        if (-not $actual -or [string]$actual.Mode -ne 'TestWithoutNotifications') {
            throw "Activation blocked: policy '$($policy.key)' is missing or is not in TestWithoutNotifications mode."
        }
        if (-not $expectedPolicy -or -not (Test-PurviewAutoPolicyMatch -Actual $actual -Expected $expectedPolicy)) {
            throw "Activation blocked: policy '$($policy.key)' no longer matches the reviewed simulation configuration."
        }
        foreach ($condition in $policy.conditions) {
            $ruleKey = [string]$condition.sitKey
            $ruleId = if ($owned.rules) { [string]$owned.rules[$ruleKey] } else { '' }
            if (-not $ruleId) { throw "Activation blocked: rule '$($policy.key)/$ruleKey' is not inventory-owned." }
            $actualRule = Get-AutoSensitivityLabelRule -Identity $ruleId -ErrorAction Stop
            $expectedRule = Get-PurviewAutoRuleArgument -Policy $policy -Condition $condition -Definitions $definitions
            if (-not $actualRule -or -not (Test-PurviewAutoRuleMatch -Actual $actualRule -Expected $expectedRule)) {
                throw "Activation blocked: rule '$($policy.key)/$ruleKey' no longer matches the reviewed simulation configuration."
            }
        }
        [pscustomobject]@{ Key = $policy.key; Id = [string]$owned.policyId }
    }
    if (@($policies).Count -eq 0) {
        throw 'Activation blocked: no configured, inventory-owned workload policies are available to enable.'
    }
    foreach ($policy in $policies) {
        Set-AutoSensitivityLabelPolicy -Identity $policy.Id -Mode Enable -ErrorAction Stop | Out-Null
        $inventory.policies[$policy.Key].mode = 'Enable'
        Save-PurviewInventory -InventoryPath $inventoryPath -Inventory $inventory
    }
    return [pscustomobject]@{
        Status = 'Enabled'
        Tenant = $definitions.Environment.tenant.id
        Policies = @($policies)
        ApprovalRunId = [string]$approval.simulationRunId
        ApprovedBy = [string]$approval.approvedBy
        Limitation = 'The cmdlet activation was performed after the operator attested to simulation and manual-label preservation evidence; tenant runtime behavior was not independently validated by this script.'
    }
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
