[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ClusterName,
    [Parameter(Mandatory)][pscredential]$ServiceUserCredentials,
    [string]$SqlServerInstance = "$env:COMPUTERNAME\SQLEXPRESS"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
Import-Module PurviewInformationProtection -ErrorAction Stop

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Cluster connection must run in elevated Windows PowerShell on the scanner node.'
}
$configuration = Get-ScannerConfiguration -ErrorAction Stop
if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Connect scanner to portal cluster '$ClusterName' using online configuration")) {
    if ([string]$configuration.Cluster -cne $ClusterName -or [string]$configuration.SqlInstance -ine $SqlServerInstance) {
        Stop-Service -Name MIPScanner -ErrorAction Stop
        Set-ScannerDatabase -SqlServerInstance $SqlServerInstance -Cluster $ClusterName -ServiceUserCredentials $ServiceUserCredentials -Force -ErrorAction Stop | Out-Null
    }
    Set-ScannerConfiguration -OnlineConfiguration On -ErrorAction Stop | Out-Null
    Restart-Service -Name MIPScanner -ErrorAction Stop
    $configuration = Get-ScannerConfiguration -ErrorAction Stop
    if ([string]$configuration.Cluster -cne $ClusterName -or [string]$configuration.OnlineConfiguration -ne 'On') {
        throw 'Scanner configuration did not confirm the requested cluster and online mode.'
    }
    $statePath = Join-Path $env:ProgramData 'PurviewIPAsCode\readiness.json'
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        $state | Add-Member -NotePropertyName clusterName -NotePropertyValue $ClusterName -Force
        $state | Add-Member -NotePropertyName configurationMode -NotePropertyValue 'Online' -Force
        $state.discoveryComplete = $false
        $state.readyForEnforcement = $false
        foreach ($name in @('diagnosticCode', 'failedStage', 'summaryPath', 'detailedReportPath', 'scannedFileCount')) {
            $state.PSObject.Properties.Remove($name)
        }
        $state.blockingLimitation = 'Cluster connection is configured; portal job assignment and a new report-backed discovery run are still required.'
        $state.updatedAtUtc = [datetime]::UtcNow.ToString('o')
        $temporary = "$statePath.tmp"
        [System.IO.File]::WriteAllText($temporary, ($state | ConvertTo-Json -Depth 8), [System.Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $statePath -Force
    }
    $configuration
}
