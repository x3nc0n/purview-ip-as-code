[CmdletBinding()]
param(
    [string]$EnvironmentPath = 'config\environments\demo.example.json',
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
$plan = Get-PurviewDeploymentPlan -EnvironmentPath $EnvironmentPath
if ($OutputPath) {
    $destination = [System.IO.Path]::GetFullPath($OutputPath)
    $directory = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $directory)) { [void](New-Item -ItemType Directory -Path $directory -Force) }
    $plan | ConvertTo-Json -Depth 16 | Set-Content -LiteralPath $destination -Encoding utf8
    Write-Information "Deployment plan written to $destination" -InformationAction Continue
}
$plan
