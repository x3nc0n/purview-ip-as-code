[CmdletBinding()]
param(
    [string]$DetectionPath = 'config\detection.json',
    [string]$OutputPath = 'config\generated\bcsi-rule-package.xml'
)

$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..\src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
$path = Build-PurviewRulePackage -DetectionPath $DetectionPath -OutputPath $OutputPath
Write-Information "Wrote deterministic Unicode SIT package: $path" -InformationAction Continue
