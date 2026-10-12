[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EnvironmentPath,
    [Parameter(Mandatory)][string]$ApprovalRecordPath,
    [string]$InventoryPath = '.purview-state\managed-inventory.json'
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
Enable-PurviewAutoLabeling -EnvironmentPath $EnvironmentPath -ApprovalRecordPath $ApprovalRecordPath -InventoryPath $InventoryPath
