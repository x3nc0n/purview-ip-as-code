[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$EnvironmentPath,
    [string]$InventoryPath = '.purview-state\managed-inventory.json',
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
Invoke-PurviewLabelConfiguration -EnvironmentPath $EnvironmentPath -InventoryPath $InventoryPath -Apply:$Apply -WhatIf:$WhatIfPreference
