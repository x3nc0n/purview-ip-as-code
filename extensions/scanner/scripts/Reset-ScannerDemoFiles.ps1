[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$SubscriptionId = '0e53bb5d-b0db-44cf-960f-e58d0f7fe5f7',
    [string]$StorageResourceGroup = 'rg-purview-scanner-demo-westus2',
    [string]$ScannerResourceGroup = 'rg-purview-scanner-lab-westus2',
    [string]$ScannerVmName = 'pipascodelab-scanner-vm',
    [ValidatePattern('^[a-z0-9]{3,24}$')][string]$StorageAccountName = 'stscannerdemod12f',
    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')][string]$ShareName = 'scanner-demo',
    [string]$IdentityClientId = 'ee77d47c-820d-487c-8503-b28ac881f054',
    [string]$IdentityPrincipalId = 'f95657be-3e10-442f-b339-861a7a6b5913',
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
$repository = "\\$StorageAccountName.file.core.windows.net\$ShareName\fixtures"
$scope = "/subscriptions/$SubscriptionId/resourceGroups/$StorageResourceGroup/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/fileServices/default/fileshares/$ShareName"
$role = 'Storage File Data Privileged Contributor'
$worker = Join-Path $PSScriptRoot 'Reset-ScannerDemoFilesWorker.ps1'
$commit = git -C $root rev-parse HEAD
if ($LASTEXITCODE -ne 0) { throw 'Cannot resolve the committed fixture source.' }
if (-not $Apply) {
    [pscustomobject]@{ Repository = $repository; SourceCommit = $commit; Action = 'Plan only: replace files directly inside fixtures; preserve the share, directory and ACLs.' }
    return
}
if (-not $PSCmdlet.ShouldProcess($repository, "Delete ALL files directly inside fixtures and restore pristine files from commit $commit")) { return }

$archivePath = Join-Path ([IO.Path]::GetTempPath()) "scanner-demo-reset-$([guid]::NewGuid().ToString('N')).zip"
$guestScriptPath = [IO.Path]::ChangeExtension($archivePath, '.ps1')
$createdAssignment = $null
try {
    git -C $root archive --format=zip "--output=$archivePath" $commit -- demo/content/generated demo/manifests/fixtures.json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot package pristine committed fixtures.' }
    $payload = [Convert]::ToBase64String([IO.File]::ReadAllBytes($archivePath))
    if ($payload.Length -gt 262144) { throw 'Fixture archive exceeds the inline Run Command payload budget; refusing to truncate it.' }
    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    $workerArguments = @{
        StorageAccountName = $StorageAccountName; ShareName = $ShareName
        IdentityClientId = $IdentityClientId; ArchiveBase64 = $payload
        ArchiveSha256 = $hash; SourceCommit = $commit
    }
    $encodedArguments = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($workerArguments | ConvertTo-Json -Compress)))
    $guestScript = @'
$argumentObject = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__ARGUMENTS__')) | ConvertFrom-Json
$resetArguments = @{}
foreach ($property in $argumentObject.PSObject.Properties) { $resetArguments[$property.Name] = $property.Value }
& {
__WORKER__
} @resetArguments
'@
    $guestScript = $guestScript.Replace('__ARGUMENTS__', $encodedArguments).Replace('__WORKER__', [IO.File]::ReadAllText($worker))
    [IO.File]::WriteAllText($guestScriptPath, $guestScript, [Text.UTF8Encoding]::new($false))
    $identityJson = az vm identity show --subscription $SubscriptionId -g $ScannerResourceGroup -n $ScannerVmName -o json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect the scanner VM identity.' }
    $identities = ($identityJson | ConvertFrom-Json).userAssignedIdentities.PSObject.Properties.Value
    if (@($identities | Where-Object { $_.clientId -eq $IdentityClientId -and $_.principalId -eq $IdentityPrincipalId }).Count -ne 1) {
        throw 'The requested managed identity is not attached to the scanner VM.'
    }
    $existingJson = az role assignment list --subscription $SubscriptionId --scope $scope --include-inherited -o json
    if ($LASTEXITCODE -ne 0) { throw 'Cannot inspect existing FilesREST privileges.' }
    $existing = @($existingJson | ConvertFrom-Json | Where-Object { $_.principalId -eq $IdentityPrincipalId -and $_.roleDefinitionName -eq $role })
    if ($existing.Count -eq 0) {
        $createdAssignment = az role assignment create --subscription $SubscriptionId --assignee-object-id $IdentityPrincipalId --assignee-principal-type ServicePrincipal --role $role --scope $scope --query id -o tsv
        if ($LASTEXITCODE -ne 0 -or -not $createdAssignment) { throw 'Temporary share-scoped FilesREST grant failed.' }
        Start-Sleep -Seconds 60
    }
    $json = az vm run-command invoke --subscription $SubscriptionId -g $ScannerResourceGroup -n $ScannerVmName --command-id RunPowerShellScript --scripts "@$guestScriptPath" -o json
    if ($LASTEXITCODE -ne 0) { throw 'Demo reset guest invocation failed.' }
    $result = $json | ConvertFrom-Json
    $stderr = @($result.value | Where-Object { $_.code -match 'StdErr' -and -not [string]::IsNullOrWhiteSpace($_.message) })
    if ($stderr.Count) { throw "Demo reset failed: $($stderr.message -join [Environment]::NewLine)" }
    $stdout = @($result.value | Where-Object code -match 'StdOut')
    if ($stdout.Count -ne 1) { throw 'Expected one guest reset result.' }
    $evidence = $stdout[0].message | ConvertFrom-Json
    if ($evidence.ResetComplete -ne $true -or $evidence.VerifiedFiles -ne 29 -or $evidence.SourceCommit -ne $commit) {
        throw 'Guest did not verify the complete pristine demo corpus.'
    }
    $evidence
}
finally {
    try {
        if ($createdAssignment) {
            az role assignment delete --subscription $SubscriptionId --ids $createdAssignment -o none
            if ($LASTEXITCODE -ne 0) { throw "Temporary privilege cleanup failed; remove role assignment $createdAssignment immediately." }
        }
    }
    finally {
        if (Test-Path -LiteralPath $archivePath) { Remove-Item -LiteralPath $archivePath -Force }
        if (Test-Path -LiteralPath $guestScriptPath) { Remove-Item -LiteralPath $guestScriptPath -Force }
    }
}
