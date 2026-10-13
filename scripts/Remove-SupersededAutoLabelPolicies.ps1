[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory)][string]$EnvironmentPath,
    [Parameter(Mandatory)][string]$InventoryPath,
    [Parameter(Mandatory)][string]$BackupPath,
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\PurviewIPAsCode\PurviewIPAsCode.psd1')
$inventory = Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json -AsHashtable
$environment = Get-Content -LiteralPath $EnvironmentPath -Raw | ConvertFrom-Json -AsHashtable
if ($inventory.tenantId -ne $environment.tenant.id) { throw 'Inventory and environment tenants differ.' }
& (Get-Module PurviewIPAsCode) { param($id) Assert-PurviewTenantContext -TenantId $id } $inventory.tenantId
$expectedKeys = @('bcsi-high', 'pii-low', 'pii-high-files', 'pii-exchange-high')
$definitions = Get-Content (Join-Path $PSScriptRoot '..\config\auto-labeling-policies.json') -Raw | ConvertFrom-Json
if (@($definitions).Count -ne 4 -or @($definitions | Where-Object { $_.key -notin $expectedKeys }).Count -gt 0) {
    throw 'This migration requires the reviewed four-policy layout.'
}
$drift = Get-PurviewDriftReport -EnvironmentPath $EnvironmentPath -InventoryPath $InventoryPath
$managedRows = @($drift.Results | Where-Object Kind -in @('AutoLabelPolicy', 'AutoLabelRule'))
$expectedRuleCount = & (Get-Module PurviewIPAsCode) {
    param($path)
    $configuration = Get-PurviewDefinition $path
    @($configuration.Policies | ForEach-Object { Get-PurviewAutoRuleDefinition -Policy $_ -Definitions $configuration }).Count
} $EnvironmentPath
if (@($managedRows | Where-Object Status -ne 'NoChange').Count -gt 0 -or
    @($managedRows | Where-Object Kind -eq 'AutoLabelPolicy').Count -ne 4 -or
    @($managedRows | Where-Object Kind -eq 'AutoLabelRule').Count -ne $expectedRuleCount) {
    throw 'All four replacement policies and their rules must match the canonical configuration before retiring anything.'
}
foreach ($key in $expectedKeys) {
    $policy = Get-AutoSensitivityLabelPolicy -Identity $inventory.policies[$key].policyId -ErrorAction Stop
    if ([string]$policy.Mode -ne 'TestWithoutNotifications') { throw 'Replacement policies must remain in simulation during migration.' }
}
$legacyKeys = @('bcsi-spo-high', 'bcsi-od-high', 'bcsi-exchange-high', 'pii-spo-low', 'pii-spo-high', 'pii-od-low', 'pii-od-high', 'pii-exchange-low')
$legacyNames = @(
    'Purview IP as code - BCSI SharePoint (simulation)',
    'Purview IP as code - BCSI OneDrive (simulation)',
    'Purview IP as code - BCSI Exchange (simulation)',
    'Purview IP as code - PII SharePoint 1-199 (simulation)',
    'Purview IP as code - PII SharePoint 200+ (simulation)',
    'Purview IP as code - PII OneDrive 1-199 (simulation)',
    'Purview IP as code - PII OneDrive 200+ (simulation)',
    'Purview IP as code - PII Exchange 1-199 (simulation)'
)
$replacementIds = @($expectedKeys | ForEach-Object { [string]$inventory.policies[$_].policyId })
$initialWarnings = @()
$allRules = @(Get-AutoSensitivityLabelRule -ErrorAction Stop -WarningVariable initialWarnings)
if ($initialWarnings.Count -gt 0) { throw 'Rule enumeration returned warnings and may be incomplete; resolve them before retirement.' }
$allPolicies = @(Get-AutoSensitivityLabelPolicy -ErrorAction Stop)
$candidates = @(foreach ($key in $legacyKeys) {
    if (-not $inventory.policies.ContainsKey($key)) { continue }
    $owned = $inventory.policies[$key]
    if ($owned.kind -ne 'AutoLabel' -or -not $owned.policyId) { throw "Legacy entry '$key' has no valid ownership record." }
    $parsedId = [guid]::Empty
    if (-not [guid]::TryParse([string]$owned.policyId, [ref]$parsedId) -or $parsedId -eq [guid]::Empty -or
        [string]$owned.policyId -in $replacementIds) { throw "Legacy entry '$key' has an unsafe policy ID." }
    $policy = $allPolicies | Where-Object { [string]$_.Guid -eq [string]$owned.policyId } | Select-Object -First 1
    $policyRules = @($allRules | Where-Object { [string]$_.Policy -eq [string]$owned.policyId })
    if (-not $policy) {
        if ($policyRules.Count -gt 0) { throw "Missing legacy policy '$key' still has rules; wait for deletion propagation before retrying." }
        [pscustomobject]@{Key = $key; Id = [string]$owned.policyId; Policy = $null; AlreadyAbsent = $true}
        continue
    }
    if ([string]$policy.Guid -ne [string]$owned.policyId -or
        [string]$policy.Mode -ne 'TestWithoutNotifications' -or
        [string]$policy.Name -ne $legacyNames[[array]::IndexOf($legacyKeys, $key)]) {
        throw "Legacy policy '$key' is missing, active, or outside the reviewed naming boundary."
    }
    if (-not $owned.rules -or @($policyRules | Where-Object { [string]$_.Guid -notin @($owned.rules.Values) }).Count -gt 0) {
        throw "Legacy policy '$key' contains rules outside the ownership inventory."
    }
    [pscustomobject]@{Key = $key; Id = [string]$owned.policyId; Policy = $policy; AlreadyAbsent = $false}
})
if ($candidates.Count -eq 0) { return }
if (@($candidates.Id | Sort-Object -Unique).Count -ne @($candidates).Count) { throw 'Duplicate legacy ownership IDs; refusing retirement.' }
if (-not $Apply) {
    $candidates | Select-Object Key, Id, @{Name = 'Action'; Expression = { if ($_.AlreadyAbsent) { 'ReconcileAbsentLegacyInventory' } else { 'RetireAfterReplacementValidation' } }}
    return
}
if (Test-Path -LiteralPath $BackupPath) { throw 'Backup already exists; choose a new path rather than overwriting recovery evidence.' }
if ($PSCmdlet.ShouldProcess($inventory.tenantId, "Back up and retire $(@($candidates).Count) superseded inventory-owned simulation policies")) {
    @{
        Inventory = $inventory
        Policies = @($candidates | ForEach-Object Policy)
        Rules = @($allRules | Where-Object { [string]$_.Policy -in @($candidates.Id) })
        CreatedAtUtc = [datetime]::UtcNow.ToString('o')
    } | Export-Clixml -LiteralPath $BackupPath
    foreach ($candidate in $candidates) {
        if (-not $candidate.AlreadyAbsent) {
            Remove-AutoSensitivityLabelPolicy -Identity $candidate.Id -Confirm:$false -ErrorAction Stop
            for ($attempt = 0; $attempt -lt 12; $attempt++) {
                $readWarnings = @()
                $remainingRules = @(Get-AutoSensitivityLabelRule -ErrorAction Stop -WarningVariable readWarnings | Where-Object { [string]$_.Policy -eq $candidate.Id })
                if ($remainingRules.Count -eq 0 -and $readWarnings.Count -eq 0) { break }
                if ($attempt -lt 11) { Start-Sleep -Seconds 10 }
            }
            if ($remainingRules.Count -gt 0 -or $readWarnings.Count -gt 0) { throw "Retired policy '$($candidate.Key)' still has rules or unresolved rule-read warnings; keep its inventory and investigate using the recovery snapshot." }
        }
        $inventory.policies.Remove($candidate.Key)
        & (Get-Module PurviewIPAsCode) {
            param($path, $state)
            Save-PurviewInventory -InventoryPath $path -Inventory $state
        } $InventoryPath $inventory
        [pscustomobject]@{Key = $candidate.Key; Id = $candidate.Id; Status = if ($candidate.AlreadyAbsent) { 'InventoryReconciled' } else { 'Retired' }}
    }
}
