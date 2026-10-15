[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$AppId,
    [Parameter(Mandatory)][string]$CertificateThumbprint,
    [Parameter(Mandatory)][string]$Organization,
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][guid]$PolicyIdentity,
    [string]$BackupDirectory = '.purview-state',
    [switch]$Apply
)

$ErrorActionPreference = 'Stop'

function ConvertFrom-ScannerPolicySettingMap {
    param([object[]]$Settings)
    $result = @{}
    foreach ($entry in $Settings) {
        if ($entry -is [string]) {
            if ($entry -notmatch '^\[([^,\]]+),\s?(.*)\]$') { throw 'Unrecognized publishing setting serialization.' }
            $result[$Matches[1]] = $Matches[2]
        }
        elseif ($entry.PSObject.Properties.Name -contains 'Key' -and $entry.PSObject.Properties.Name -contains 'Value') {
            $result[[string]$entry.Key] = [string]$entry.Value
        }
        else { throw 'Unsupported publishing setting object.' }
    }
    return $result
}

Import-Module ExchangeOnlineManagement -ErrorAction Stop
Import-Module (Join-Path $PSScriptRoot '..\..\..\src\PurviewIPAsCode\PurviewIPAsCode.psd1') -Force
try {
    $connection = @{
        AppId=$AppId; CertificateThumbprint=$CertificateThumbprint
        Organization=$Organization; ShowBanner=$false
    }
    Connect-ExchangeOnline @connection
    Connect-IPPSSession @connection
    & (Get-Module PurviewIPAsCode) { param($Id) Assert-PurviewTenantContext -TenantId $Id } ([string]$TenantId)
    $policy = Get-LabelPolicy -Identity ([string]$PolicyIdentity) -ErrorAction Stop
    if ([guid]$policy.Guid -ne $PolicyIdentity) { throw 'Publishing policy identity read-back failed.' }
    $settings = @{ EnableAudit='True'; PFileSupportedExtensions=(ConvertTo-Json -InputObject @('.txt') -Compress) }
    if ($Apply -and $PSCmdlet.ShouldProcess([string]$PolicyIdentity, 'Enable client audit and scanner TXT protection; preserve policy audience and other settings')) {
        [void](New-Item -ItemType Directory -Path $BackupDirectory -Force)
        $policy | Export-Clixml -LiteralPath (Join-Path $BackupDirectory "scanner-publishing-$([datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ')).xml")
        Set-LabelPolicy -Identity ([string]$PolicyIdentity) -AdvancedSettings (@{} + $settings) -ErrorAction Stop
        $policy = Get-LabelPolicy -Identity ([string]$PolicyIdentity) -ErrorAction Stop
        $actual = ConvertFrom-ScannerPolicySettingMap -Settings $policy.Settings
        foreach ($key in $settings.Keys) {
            if ($actual[$key.ToLowerInvariant()] -ine $settings[$key]) { throw "Publishing setting '$key' read-back failed." }
        }
    }
    [pscustomobject]@{
        PolicyId=[string]$PolicyIdentity; PolicyName=$policy.Name
        DesiredSettings=$settings; DistributionStatus=[string]$policy.DistributionStatus
        Applied=([bool]$Apply -and -not $WhatIfPreference)
    }
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop
}
