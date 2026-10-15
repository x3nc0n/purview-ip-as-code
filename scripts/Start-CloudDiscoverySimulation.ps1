[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$EnvironmentPath,
    [string]$InventoryPath = '.purview-state\managed-inventory.json',
    [Parameter(Mandatory)][string]$BackupPath,
    [switch]$Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\PurviewIPAsCode\PurviewIPAsCode.psd1')
$environment = Get-Content -LiteralPath $EnvironmentPath -Raw | ConvertFrom-Json -AsHashtable
$inventory = Get-Content -LiteralPath $InventoryPath -Raw | ConvertFrom-Json -AsHashtable
if ($inventory.tenantId -ne $environment.tenant.id) { throw 'Inventory and environment tenants differ.' }
& (Get-Module PurviewIPAsCode) { param($id) Assert-PurviewTenantContext -TenantId $id } $inventory.tenantId
foreach ($scope in @('sharePointLocations', 'oneDriveLocations', 'exchangeLocations')) {
    if (@($environment.scopes[$scope]).Count -ne 1 -or $environment.scopes[$scope][0] -ne 'All') {
        throw "Tenant-wide discovery requires the explicit All value in '$scope'."
    }
}
$definitions = Get-Content (Join-Path $PSScriptRoot '..\config\auto-labeling-policies.json') -Raw | ConvertFrom-Json
$policies = @(foreach ($definition in $definitions) {
    if ($definition.key -notin $environment.ownership.managedPolicyKeys -or
        -not $inventory.policies.ContainsKey($definition.key)) { throw "Missing ownership for '$($definition.key)'." }
    $owned = $inventory.policies[$definition.key]
    if ($owned.kind -ne 'AutoLabel' -or -not $owned.policyId) { throw 'Invalid auto-label policy ownership.' }
    $policy = Get-AutoSensitivityLabelPolicy -Identity $owned.policyId -DistributionDetail -ErrorAction Stop
    if ([string]$policy.Guid -ne [string]$owned.policyId -or
        [string]$policy.Name -ne $definition.name -or
        [string]$policy.Mode -ne 'TestWithoutNotifications' -or -not $policy.Enabled) {
        throw "Policy '$($definition.key)' is not the enabled, inventory-owned simulation."
    }
    if ($policy.AutoEnableAfter) { throw "Policy '$($definition.key)' has automatic enforcement scheduled." }
    foreach ($workload in @('SharePoint', 'OneDrive')) {
        $exceptionProperty = "${workload}LocationException"
        if (@($policy.$exceptionProperty).Count -gt 0) { throw "Remove or review '$exceptionProperty' exclusions before tenant-wide discovery." }
    }
    [pscustomobject]@{ Definition = $definition; Policy = $policy }
})
if (-not $Apply) {
    $policies | ForEach-Object {
        [pscustomobject]@{ Name = $_.Policy.Name; Workloads = $_.Definition.workload -join ','; Scope = 'All'; Action = 'RestartSimulationOnly' }
    }
    return
}
if (Test-Path -LiteralPath $BackupPath) { throw 'Backup exists; choose a new path.' }
if ($PSCmdlet.ShouldProcess($inventory.tenantId, 'Expand owned simulation scopes to All and restart discovery without enforcement')) {
    $policies.Policy | Export-Clixml -LiteralPath $BackupPath
    foreach ($entry in $policies) {
        $arguments = @{ Identity = [string]$entry.Policy.Guid; ErrorAction = 'Stop' }
        foreach ($workload in @('SharePoint', 'OneDrive', 'Exchange')) {
            if ($workload -notin $entry.Definition.workload) { continue }
            $current = @($entry.Policy."${workload}Location" | ForEach-Object { [string]$_.Name })
            if ('All' -notin $current) {
                $arguments["Add${workload}Location"] = @('All')
                if ($current.Count -gt 0) { $arguments["Remove${workload}Location"] = $current }
            }
        }
        if ($arguments.Count -gt 2) { Set-AutoSensitivityLabelPolicy @arguments -Confirm:$false }
        $verified = Get-AutoSensitivityLabelPolicy -Identity $entry.Policy.Guid -ErrorAction Stop
        foreach ($workload in $entry.Definition.workload) {
            $locations = @($verified."${workload}Location" | ForEach-Object { [string]$_.Name })
            if ($locations.Count -ne 1 -or $locations[0] -ne 'All') { throw "Scope read-back failed for '$($entry.Policy.Name)' / '$workload'." }
        }
        if ([string]$verified.Mode -ne 'TestWithoutNotifications' -or $verified.AutoEnableAfter) {
            throw 'Simulation-only safety read-back failed.'
        }
        Set-AutoSensitivityLabelPolicy -Identity $entry.Policy.Guid -StartSimulation $true -Confirm:$false -ErrorAction Stop
        [pscustomobject]@{
            Name = $entry.Policy.Name
            Id = [string]$entry.Policy.Guid
            Scope = 'All'
            Mode = [string]$verified.Mode
            RestartAcceptedAtUtc = [datetime]::UtcNow.ToString('o')
        }
    }
}
