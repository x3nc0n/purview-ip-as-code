[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$EnvironmentPath,
    [string]$InventoryPath = '.purview-state\managed-inventory.json',
    [Parameter(Mandatory)][string]$AppId,
    [Parameter(Mandatory)][string]$CertificateThumbprint,
    [Parameter(Mandatory)][string]$Organization,
    [switch]$Apply,
    [switch]$UpdateDetectionPackage
)

$ErrorActionPreference = 'Stop'
Import-Module ExchangeOnlineManagement -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '..\src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
$connection = @{
    AppId = $AppId
    CertificateThumbprint = $CertificateThumbprint
    Organization = $Organization
    ShowBanner = $false
}
try {
    Connect-ExchangeOnline @connection
    Connect-IPPSSession @connection
    $validation = Test-PurviewConfiguration -EnvironmentPath $EnvironmentPath -RequireTenantValues:$Apply
    if (-not $validation.Valid) { throw "Configuration validation failed: $($validation.Errors -join '; ')" }
    if ($UpdateDetectionPackage) {
        $root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
        $detectionPath = Join-Path $root 'config\detection.json'
        $definition = Get-Content -LiteralPath $detectionPath -Raw | ConvertFrom-Json
        $environment = Get-Content -LiteralPath $EnvironmentPath -Raw | ConvertFrom-Json
        $inventory = & (Get-Module PurviewIPAsCode) {
            param($Path, $TenantId)
            Assert-PurviewTenantContext -TenantId $TenantId
            Assert-PurviewInventory -InventoryPath (Get-PurviewConfigPath $Path) -TenantId $TenantId
        } $InventoryPath $environment.tenant.id
        if ([string]$inventory.rulePackageId -ne [string]$definition.package.id) {
            throw 'SIT package update requires inventory ownership.'
        }
        $package = & (Get-Module PurviewIPAsCode) { param($Id) Get-PurviewRulePackageById -PackageId $Id } $definition.package.id
        if (-not $package) { throw 'The inventory-owned SIT package is missing.' }
        if ([string]$package.Version -ne [string]$definition.package.version) {
            if ($Apply -and $PSCmdlet.ShouldProcess($definition.package.id, 'Update inventory-owned BCSI SIT package')) {
                $package | Export-Clixml -LiteralPath "$InventoryPath.sit-backup-$([datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')).xml"
                $path = Build-PurviewRulePackage -DetectionPath $detectionPath
                Write-Information "Updating owned SIT package '$($definition.package.id)' to '$($definition.package.version)'." -InformationAction Continue
                Set-DlpSensitiveInformationTypeRulePackage -FileData ([IO.File]::ReadAllBytes($path)) -Confirm:$false -ErrorAction Stop
                $verified = & (Get-Module PurviewIPAsCode) { param($Id) Get-PurviewRulePackageById -PackageId $Id } $definition.package.id
                if ([string]$verified.Version -ne [string]$definition.package.version) { throw 'SIT package version read-back failed.' }
            }
        }
        $current = & (Get-Module PurviewIPAsCode) { param($Id) Get-PurviewRulePackageById -PackageId $Id } $definition.package.id
        [pscustomobject]@{ Kind = 'SensitiveInformationTypePackage'; Id = $definition.package.id; DesiredVersion = $definition.package.version; ActualVersion = [string]$current.Version }
    }
    Invoke-PurviewLabelConfiguration -EnvironmentPath $EnvironmentPath -InventoryPath $InventoryPath -Apply:$Apply -WhatIf:$WhatIfPreference
    if ($Apply -and -not $WhatIfPreference) {
        Execute-AzureAdLabelSync -ErrorAction Stop
    }
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
}
