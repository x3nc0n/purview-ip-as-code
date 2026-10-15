BeforeAll {
    $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $scriptPath = Join-Path $root 'scripts\Start-CloudDiscoverySimulation.ps1'
    Import-Module (Join-Path $root 'src\PurviewIPAsCode\PurviewIPAsCode.psd1')
    function global:Get-OrganizationConfig {}
    function global:Get-AutoSensitivityLabelPolicy {
        param($Identity, [switch]$DistributionDetail)
    }
    function global:Set-AutoSensitivityLabelPolicy {
        [CmdletBinding(SupportsShouldProcess)]
        param($Identity, $AddSharePointLocation, $RemoveSharePointLocation,
            $AddOneDriveLocation, $RemoveOneDriveLocation, $AddExchangeLocation,
            $RemoveExchangeLocation, [bool]$StartSimulation)
    }

    AfterAll {
        foreach ($name in @('Get-OrganizationConfig', 'Get-AutoSensitivityLabelPolicy', 'Set-AutoSensitivityLabelPolicy')) {
            Remove-Item "Function:\global:$name" -ErrorAction SilentlyContinue
        }
        Remove-Variable CloudDiscoveryTestPolicies -Scope Global -ErrorAction SilentlyContinue
    }
}

Describe 'Tenant-wide cloud discovery remains simulation-only' {
    BeforeEach {
        $tenant = 'd12fb61e-6f2f-4809-9e8d-f9581ceb4fee'
        $environmentPath = Join-Path $TestDrive 'environment.json'
        $inventoryPath = Join-Path $TestDrive 'inventory.json'
        $backupPath = Join-Path $TestDrive ([guid]::NewGuid().ToString('N') + '.xml')
        $environment = Get-Content (Join-Path $root 'config\environments\diax18655663.json') -Raw | ConvertFrom-Json -AsHashtable
        $definitions = Get-Content (Join-Path $root 'config\auto-labeling-policies.json') -Raw | ConvertFrom-Json
        $inventory = @{ tenantId = $tenant; policies = @{} }
        $global:CloudDiscoveryTestPolicies = @{}
        foreach ($definition in $definitions) {
            $id = [guid]::NewGuid().ToString()
            $inventory.policies[$definition.key] = @{ kind = 'AutoLabel'; policyId = $id }
            $global:CloudDiscoveryTestPolicies[$id] = [pscustomobject]@{
                Guid = $id; Name = $definition.name; Mode = 'TestWithoutNotifications'
                Enabled = $true; AutoEnableAfter = $null
                SharePointLocation = @(); OneDriveLocation = @(); ExchangeLocation = @()
                SharePointLocationException = @(); OneDriveLocationException = @()
            }
            foreach ($workload in $definition.workload) {
                $global:CloudDiscoveryTestPolicies[$id]."${workload}Location" = @([pscustomobject]@{ Name = 'All' })
            }
        }
        $environment | ConvertTo-Json -Depth 10 | Set-Content $environmentPath
        $inventory | ConvertTo-Json -Depth 10 | Set-Content $inventoryPath
        $arguments = @{ EnvironmentPath = $environmentPath; InventoryPath = $inventoryPath; BackupPath = $backupPath }
        Mock Get-OrganizationConfig -ModuleName PurviewIPAsCode { [pscustomobject]@{ ExternalDirectoryOrganizationId = 'd12fb61e-6f2f-4809-9e8d-f9581ceb4fee' } }
        Mock Get-AutoSensitivityLabelPolicy { param($Identity) $global:CloudDiscoveryTestPolicies[[string]$Identity] }
        Mock Set-AutoSensitivityLabelPolicy {}
    }

    It 'plans four simulations without writes or backups' {
        @(& $scriptPath @arguments).Count | Should -Be 4
        Test-Path $backupPath | Should -BeFalse
        Should -Invoke Set-AutoSensitivityLabelPolicy -Times 0
    }

    It 'backs up and restarts all four simulations without enabling enforcement' {
        @(& $scriptPath @arguments -Apply -Confirm:$false).Count | Should -Be 4
        Test-Path $backupPath | Should -BeTrue
        Should -Invoke Set-AutoSensitivityLabelPolicy -Times 4 -Exactly -ParameterFilter { $StartSimulation -eq $true }
    }

    It 'honors WhatIf before any writes' {
        & $scriptPath @arguments -Apply -WhatIf
        Test-Path $backupPath | Should -BeFalse
        Should -Invoke Set-AutoSensitivityLabelPolicy -Times 0
    }

    It 'replaces an explicit site scope and reads it back before restarting' {
        $policy = $global:CloudDiscoveryTestPolicies.Values | Where-Object Name -eq 'Purview IP as code - BCSI (simulation)'
        $policy.SharePointLocation = @([pscustomobject]@{ Name = 'https://example.sharepoint.com/sites/pilot' })
        Mock Set-AutoSensitivityLabelPolicy {
            param($Identity, $AddSharePointLocation)
            if ($AddSharePointLocation) {
                $global:CloudDiscoveryTestPolicies[[string]$Identity].SharePointLocation = @([pscustomobject]@{ Name = 'All' })
            }
        }
        @(& $scriptPath @arguments -Apply -Confirm:$false).Count | Should -Be 4
        Should -Invoke Set-AutoSensitivityLabelPolicy -Times 1 -Exactly -ParameterFilter {
            $AddSharePointLocation -contains 'All' -and $RemoveSharePointLocation -contains 'https://example.sharepoint.com/sites/pilot'
        }
        Should -Invoke Set-AutoSensitivityLabelPolicy -Times 4 -Exactly -ParameterFilter { $StartSimulation -eq $true }
    }

    It 'stops before restarting when the updated scope fails read-back' {
        $policy = $global:CloudDiscoveryTestPolicies.Values | Where-Object Name -eq 'Purview IP as code - BCSI (simulation)'
        $policy.SharePointLocation = @([pscustomobject]@{ Name = 'https://example.sharepoint.com/sites/pilot' })
        { & $scriptPath @arguments -Apply -Confirm:$false } | Should -Throw '*Scope read-back failed*'
        Should -Invoke Set-AutoSensitivityLabelPolicy -Times 1 -Exactly -ParameterFilter { $AddSharePointLocation -contains 'All' }
        Should -Invoke Set-AutoSensitivityLabelPolicy -Times 0 -ParameterFilter { $StartSimulation -eq $true }
    }

    It 'rejects active enforcement before any writes' {
        ($global:CloudDiscoveryTestPolicies.Values | Select-Object -First 1).Mode = 'Enable'
        { & $scriptPath @arguments -Apply -Confirm:$false } | Should -Throw '*inventory-owned simulation*'
        Should -Invoke Set-AutoSensitivityLabelPolicy -Times 0
    }

    It 'rejects automatic enforcement and excluded sites' {
        $policy = $global:CloudDiscoveryTestPolicies.Values | Select-Object -First 1
        $policy.AutoEnableAfter = [datetime]::UtcNow.AddDays(1)
        { & $scriptPath @arguments -Apply -Confirm:$false } | Should -Throw '*automatic enforcement*'
        $policy.AutoEnableAfter = $null
        $policy.SharePointLocationException = @('https://example.invalid')
        { & $scriptPath @arguments -Apply -Confirm:$false } | Should -Throw '*exclusions*'
        Should -Invoke Set-AutoSensitivityLabelPolicy -Times 0
    }

    It 'rejects a tenant mismatch and non-tenant-wide scope' {
        $inventory.tenantId = [guid]::NewGuid().ToString()
        $inventory | ConvertTo-Json -Depth 10 | Set-Content $inventoryPath
        { & $scriptPath @arguments } | Should -Throw '*tenants differ*'
        $inventory.tenantId = $tenant
        $inventory | ConvertTo-Json -Depth 10 | Set-Content $inventoryPath
        $environment.scopes.sharePointLocations = @('https://example.invalid')
        $environment | ConvertTo-Json -Depth 10 | Set-Content $environmentPath
        { & $scriptPath @arguments } | Should -Throw '*explicit All*'
        Should -Invoke Set-AutoSensitivityLabelPolicy -Times 0
    }
}
