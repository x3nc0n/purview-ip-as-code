[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$EnvironmentPath,
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
Invoke-PurviewDeployment -EnvironmentPath $EnvironmentPath -Apply:$Apply
