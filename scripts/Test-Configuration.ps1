[CmdletBinding()]
param(
    [string]$EnvironmentPath = 'config\environments\demo.example.json',
    [switch]$RequireTenantValues
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
$result = Test-PurviewConfiguration -EnvironmentPath $EnvironmentPath -RequireTenantValues:$RequireTenantValues
$result.Warnings | ForEach-Object { Write-Warning $_ }
if ($result.Errors.Count -gt 0) {
    $result.Errors | ForEach-Object { Write-Error $_ -ErrorAction Continue }
    exit 1
}
Write-Information "Configuration is valid for offline use. Warnings: $($result.Warnings.Count)" -InformationAction Continue
