[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EnvironmentPath,
    [string]$InventoryPath = '.purview-state\managed-inventory.json',
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
$report = Get-PurviewDriftReport -EnvironmentPath $EnvironmentPath -InventoryPath $InventoryPath
if ($OutputPath) {
    $report | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $OutputPath -Encoding utf8
}
$report
