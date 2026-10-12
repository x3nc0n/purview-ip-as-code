[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EnvironmentPath,
    [string]$InventoryPath = '.purview-state\managed-inventory.json'
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
Initialize-PurviewInventory -EnvironmentPath $EnvironmentPath -InventoryPath $InventoryPath
