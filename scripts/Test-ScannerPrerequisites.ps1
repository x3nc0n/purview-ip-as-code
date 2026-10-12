[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
$capabilities = Get-PurviewAdapterCapability -Adapter Scanner
$capabilities | ConvertTo-Json -Depth 8
if (-not $capabilities.Supported) {
    exit 2
}
Write-Warning 'Cmdlet presence is not proof that a scanner label-condition adapter or real scan is configured.'
