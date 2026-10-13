[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$computer = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
$service = Get-CimInstance Win32_Service -Filter "Name='MIPScanner'" -ErrorAction Stop
if (-not $service -or $service.State -ne 'Running' -or $service.ProcessId -eq 0) {
    throw 'MIPScanner must be running to inspect its actual Windows logon session.'
}
$callerProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
$scannerProcess = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)" -ErrorAction Stop
if (-not $callerProcess -or -not $scannerProcess) { throw 'Could not resolve the caller and scanner processes.' }
$callerLogons = @(Get-CimAssociatedInstance -InputObject $callerProcess -Association Win32_SessionProcess -ResultClassName Win32_LogonSession -ErrorAction Stop |
    ForEach-Object { [string]$_.LogonId } | Sort-Object -Unique)
$scannerLogons = @(Get-CimAssociatedInstance -InputObject $scannerProcess -Association Win32_SessionProcess -ResultClassName Win32_LogonSession -ErrorAction Stop |
    ForEach-Object { [string]$_.LogonId } | Sort-Object -Unique)
if ($callerLogons.Count -ne 1 -or $scannerLogons.Count -ne 1) {
    throw 'Could not unambiguously identify both process logon sessions; do not infer shared credentials from account names.'
}
$sameSession = $callerLogons[0] -eq $scannerLogons[0]
$blockers = @()
if ($computer.PartOfDomain) {
    $blockers += 'Microsoft managed-identity SMB client requires a non-domain-joined Windows client.'
}
if (-not $sameSession) {
    $blockers += 'Caller and scanner use different logon sessions. Tickets acquired by this caller do not authenticate the running scanner.'
}
$blockers += 'No ticket-refresh integration inside the scanner service logon session has been implemented or validated.'
Write-Warning ($blockers -join ' ')
[pscustomobject]@{
    ComputerName = $computer.Name
    DomainJoined = [bool]$computer.PartOfDomain
    ScannerAccount = $service.StartName
    ScannerProcessId = $service.ProcessId
    CallerLogonId = $callerLogons[0]
    ScannerLogonId = $scannerLogons[0]
    SameLogonSession = $sameSession
    Status = 'BlockedPendingServiceSessionIntegration'
    AuthenticationConfigured = $false
    ChangesMade = $false
    Blockers = $blockers
    Limitation = 'Read-only context check; does not obtain tokens, install a client, grant RBAC, alter the service or test authenticated share access.'
}
