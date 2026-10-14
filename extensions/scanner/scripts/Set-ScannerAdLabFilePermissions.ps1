[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$StorageResourceGroup,
    [Parameter(Mandatory)][string]$ScannerResourceGroup,
    [Parameter(Mandatory)][string]$ScannerVmName,
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9]{3,24}$')][string]$StorageAccountName,
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')][string]$ShareName,
    [Parameter(Mandatory)][string]$IdentityClientId,
    [Parameter(Mandatory)][string]$IdentityPrincipalId,
    [ValidatePattern('^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$')][string]$DomainName = 'corp.tiny.local',
    [ValidatePattern('^[a-zA-Z0-9-]{1,15}$')][string]$NetBiosName = 'CORP'
)

$ErrorActionPreference = 'Stop'
$scope = "/subscriptions/$SubscriptionId/resourceGroups/$StorageResourceGroup/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/fileServices/default/fileshares/$ShareName"
$role = 'Storage File Data Privileged Contributor'
$scriptPath = Join-Path $PSScriptRoot 'Invoke-ScannerAdLab.ps1'
if (-not $PSCmdlet.ShouldProcess($scope, 'Temporarily grant FilesREST ACL administration, configure fixture ACLs, then remove only the new grant')) { return }

$existingJson = az role assignment list --subscription $SubscriptionId --scope $scope --include-inherited -o json
if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect existing FilesREST role assignments.' }
$existing = @($existingJson | ConvertFrom-Json | Where-Object { $_.principalId -eq $IdentityPrincipalId -and $_.roleDefinitionName -eq $role })
$createdAssignment = $null
try {
    if ($existing.Count -eq 0) {
        $createdAssignment = az role assignment create --subscription $SubscriptionId --assignee-object-id $IdentityPrincipalId --assignee-principal-type ServicePrincipal --role $role --scope $scope --query id -o tsv
        if ($LASTEXITCODE -ne 0 -or -not $createdAssignment) { throw 'Temporary share-scoped FilesREST grant failed.' }
        Start-Sleep -Seconds 60
    }
    $resultJson = az vm run-command invoke --subscription $SubscriptionId -g $ScannerResourceGroup -n $ScannerVmName --command-id RunPowerShellScript --scripts "@$scriptPath" --parameters Stage=FilePermissions "StorageAccountName=$StorageAccountName" "ShareName=$ShareName" "IdentityClientId=$IdentityClientId" "DomainName=$DomainName" "NetBiosName=$NetBiosName" -o json
    if ($LASTEXITCODE -ne 0) { throw 'FilesREST ACL guest invocation failed.' }
    $result = $resultJson | ConvertFrom-Json
    $stdout = @($result.value | Where-Object code -match 'StdOut')
    $stderr = @($result.value | Where-Object { $_.code -match 'StdErr' -and -not [string]::IsNullOrWhiteSpace($_.message) })
    if ($stderr.Count) { throw "FilesREST ACL guest failure: $($stderr.message -join [Environment]::NewLine)" }
    if ($stdout.Count -ne 1) { throw 'Expected one guest ACL result.' }
    $evidence = $stdout[0].message | ConvertFrom-Json
    if ($evidence.ScannerAccess -ne 'ReadAndExecute' -or $evidence.FixtureFiles -lt 1) {
        throw 'Guest did not confirm restrictive ACL application to a populated fixture corpus.'
    }
    $evidence
}
finally {
    if ($createdAssignment) {
        az role assignment delete --subscription $SubscriptionId --ids $createdAssignment -o none
        if ($LASTEXITCODE -ne 0) { throw "Temporary FilesREST privilege cleanup failed; remove role assignment $createdAssignment immediately." }
    }
}
