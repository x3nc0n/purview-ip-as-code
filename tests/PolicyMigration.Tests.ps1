BeforeAll {
    $repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    Import-Module (Join-Path $repositoryRoot 'src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
    $scriptPath = Join-Path $repositoryRoot 'scripts\Remove-SupersededAutoLabelPolicies.ps1'
    function global:Connect-ExchangeOnline {}
    function global:Get-OrganizationConfig {
        [CmdletBinding()]
        param()
        [pscustomobject]@{ ExternalDirectoryOrganizationId = '11111111-1111-4111-8111-111111111111' }
    }
    function global:Get-AutoSensitivityLabelPolicy {
        [CmdletBinding()]
        param([string]$Identity)
        $global:MigrationState.Policies | Where-Object { -not $Identity -or $_.Guid -eq $Identity }
    }
    function global:Get-AutoSensitivityLabelRule {
        [CmdletBinding()]
        param()
        @($global:MigrationState.Rules)
    }
    function global:Remove-AutoSensitivityLabelPolicy {
        [CmdletBinding(SupportsShouldProcess)]
        param([string]$Identity)
        if (-not (Test-Path -LiteralPath $global:MigrationState.Backup)) { throw 'Backup must exist before deletion.' }
        $global:MigrationState.Removed += $Identity
        if (-not $global:MigrationState.LeaveRules) {
            $global:MigrationState.Rules = @($global:MigrationState.Rules | Where-Object Policy -ne $Identity)
        }
    }
}

Describe 'Explicit policy retirement safety' {
    BeforeEach {
        $environment = Get-Content (Join-Path $repositoryRoot 'config\environments\demo.example.json') -Raw | ConvertFrom-Json
        $environment.tenant.id = '11111111-1111-4111-8111-111111111111'
        $environment.scopes.sharePointLocations = @('https://example.sharepoint.com/sites/pilot')
        $environment.scopes.oneDriveLocations = @('https://example-my.sharepoint.com/personal/pilot')
        $environment.scopes.exchangeLocations = @('pilot@example.com')
        $environmentPath = Join-Path $TestDrive 'environment.json'
        $inventoryPath = Join-Path $TestDrive 'inventory.json'
        $backupPath = Join-Path $TestDrive "$([guid]::NewGuid()).clixml"
        $environment | ConvertTo-Json -Depth 10 | Set-Content $environmentPath
        $inventory = @{ tenantId = $environment.tenant.id; policies = @{} }
        $global:MigrationState = @{ Policies = @(); Rules = @(); Rows = @(); Removed = @(); Backup = $backupPath; LeaveRules = $false }
        foreach ($key in @('bcsi-high', 'pii-low', 'pii-high-files', 'pii-exchange-high')) {
            $id = [guid]::NewGuid().ToString()
            $inventory.policies[$key] = @{ policyId = $id; kind = 'AutoLabel'; rules = @{} }
            $global:MigrationState.Policies += [pscustomobject]@{ Guid = $id; Name = $key; Mode = 'TestWithoutNotifications' }
            $global:MigrationState.Rows += [pscustomobject]@{ Key = $key; Kind = 'AutoLabelPolicy'; Status = 'NoChange' }
        }
        1..15 | ForEach-Object { $global:MigrationState.Rows += [pscustomobject]@{ Key = "rule-$_"; Kind = 'AutoLabelRule'; Status = 'NoChange' } }
        $legacyId = [guid]::NewGuid().ToString()
        $ruleId = [guid]::NewGuid().ToString()
        $inventory.policies['bcsi-spo-high'] = @{ policyId = $legacyId; kind = 'AutoLabel'; rules = @{ detector = $ruleId } }
        $global:MigrationState.Policies += [pscustomobject]@{ Guid = $legacyId; Name = 'Purview IP as code - BCSI SharePoint (simulation)'; Mode = 'TestWithoutNotifications' }
        $global:MigrationState.Rules += [pscustomobject]@{ Guid = $ruleId; Policy = $legacyId }
        $inventory | ConvertTo-Json -Depth 10 | Set-Content $inventoryPath
        Mock Get-PurviewDriftReport { [pscustomobject]@{ Results = $global:MigrationState.Rows } }
        Mock Start-Sleep {}
    }

    It 'plans by default without creating backups or deleting policies' {
        $plan = & $scriptPath -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -BackupPath $backupPath
        $plan.Key | Should -Be 'bcsi-spo-high'
        $global:MigrationState.Removed | Should -HaveCount 0
        Test-Path $backupPath | Should -BeFalse
    }

    It 'honors WhatIf at the local write boundary' {
        & $scriptPath -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -BackupPath $backupPath -Apply -WhatIf
        $global:MigrationState.Removed | Should -HaveCount 0
        Test-Path $backupPath | Should -BeFalse
    }

    It 'backs up before deletion and removes only the legacy inventory entry' {
        & $scriptPath -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -BackupPath $backupPath -Apply -Confirm:$false
        $global:MigrationState.Removed | Should -Be @($legacyId)
        (Import-Clixml $backupPath).Inventory.policies.ContainsKey('bcsi-spo-high') | Should -BeTrue
        $remaining = Get-Content $inventoryPath -Raw | ConvertFrom-Json -AsHashtable
        $remaining.policies.ContainsKey('bcsi-spo-high') | Should -BeFalse
        $remaining.policies.Count | Should -Be 4
    }

    It 'blocks deletion if replacement drift is reported' {
        $global:MigrationState.Rows[0].Status = 'Drift'
        { & $scriptPath -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -BackupPath $backupPath -Apply -Confirm:$false } |
            Should -Throw '*must match*'
        $global:MigrationState.Removed | Should -HaveCount 0
    }

    It 'blocks retirement when a legacy policy has an unowned rule' {
        $global:MigrationState.Rules += [pscustomobject]@{ Guid = [guid]::NewGuid().ToString(); Policy = $legacyId }
        { & $scriptPath -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -BackupPath $backupPath -Apply -Confirm:$false } |
            Should -Throw '*outside the ownership inventory*'
        $global:MigrationState.Removed | Should -HaveCount 0
    }

    It 'retains inventory when remote deletion leaves rules behind' {
        $global:MigrationState.LeaveRules = $true
        { & $scriptPath -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -BackupPath $backupPath -Apply -Confirm:$false } |
            Should -Throw '*still has rules*'
        (Get-Content $inventoryPath -Raw | ConvertFrom-Json -AsHashtable).policies.ContainsKey('bcsi-spo-high') | Should -BeTrue
    }

    It 'rejects legacy IDs that point at a replacement' {
        $inventory.policies['bcsi-spo-high'].policyId = $inventory.policies['bcsi-high'].policyId
        $inventory | ConvertTo-Json -Depth 10 | Set-Content $inventoryPath
        { & $scriptPath -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -BackupPath $backupPath -Apply -Confirm:$false } |
            Should -Throw '*unsafe policy ID*'
        $global:MigrationState.Removed | Should -HaveCount 0
    }

    It 'rejects an active replacement policy' {
        $global:MigrationState.Policies[0].Mode = 'Enable'
        { & $scriptPath -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -BackupPath $backupPath -Apply -Confirm:$false } |
            Should -Throw '*must remain in simulation*'
        $global:MigrationState.Removed | Should -HaveCount 0
    }

    It 'refuses to overwrite an existing backup' {
        Set-Content $backupPath 'existing evidence'
        { & $scriptPath -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -BackupPath $backupPath -Apply -Confirm:$false } |
            Should -Throw '*Backup already exists*'
        $global:MigrationState.Removed | Should -HaveCount 0
        Get-Content $backupPath | Should -Be 'existing evidence'
    }

    It 'is a no-op after all legacy inventory entries have been retired' {
        $inventory.policies.Remove('bcsi-spo-high')
        $inventory | ConvertTo-Json -Depth 10 | Set-Content $inventoryPath
        & $scriptPath -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -BackupPath $backupPath -Apply -Confirm:$false
        $global:MigrationState.Removed | Should -HaveCount 0
        Test-Path $backupPath | Should -BeFalse
    }

    It 'safely reconciles an already deleted legacy policy with no remaining rules' {
        $global:MigrationState.Policies = @($global:MigrationState.Policies | Where-Object Guid -ne $legacyId)
        $global:MigrationState.Rules = @()
        $result = & $scriptPath -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -BackupPath $backupPath -Apply -Confirm:$false
        $result.Status | Should -Be 'InventoryReconciled'
        $global:MigrationState.Removed | Should -HaveCount 0
        (Get-Content $inventoryPath -Raw | ConvertFrom-Json -AsHashtable).policies.ContainsKey('bcsi-spo-high') | Should -BeFalse
    }

    It 'blocks reconciliation when a deleted policy still has propagating rules' {
        $global:MigrationState.Policies = @($global:MigrationState.Policies | Where-Object Guid -ne $legacyId)
        { & $scriptPath -EnvironmentPath $environmentPath -InventoryPath $inventoryPath -BackupPath $backupPath -Apply -Confirm:$false } |
            Should -Throw '*wait for deletion propagation*'
        $global:MigrationState.Removed | Should -HaveCount 0
        (Get-Content $inventoryPath -Raw | ConvertFrom-Json -AsHashtable).policies.ContainsKey('bcsi-spo-high') | Should -BeTrue
    }
}

AfterAll {
    foreach ($name in @('Connect-ExchangeOnline', 'Get-OrganizationConfig', 'Get-AutoSensitivityLabelPolicy', 'Get-AutoSensitivityLabelRule', 'Remove-AutoSensitivityLabelPolicy')) {
        Remove-Item "Function:\global:$name" -ErrorAction SilentlyContinue
    }
    Remove-Variable MigrationState -Scope Global -ErrorAction SilentlyContinue
}
