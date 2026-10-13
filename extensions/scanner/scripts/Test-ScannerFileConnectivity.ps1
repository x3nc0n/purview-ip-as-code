[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[a-z0-9]{3,24}$')]
    [string]$StorageAccountName,
    [Parameter(Mandatory)]
    [string]$ExpectedPrivateEndpointIp
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$expected = [System.Net.IPAddress]::Parse($ExpectedPrivateEndpointIp)
if ($expected.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'Supply the approved file private endpoint IPv4 address.'
}
$octets = $expected.GetAddressBytes()
if (-not ($octets[0] -eq 10 -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
    ($octets[0] -eq 192 -and $octets[1] -eq 168))) {
    throw 'Expected endpoint address must be private (RFC1918).'
}
$hostname = "$StorageAccountName.file.core.windows.net"
$resolved = @(Resolve-DnsName -Name $hostname -Type A -DnsOnly -ErrorAction Stop |
    Where-Object Type -eq 'A' | ForEach-Object IPAddress | Sort-Object -Unique)
if ($resolved.Count -ne 1 -or $resolved[0] -ne $expected.ToString()) {
    throw "DNS for '$hostname' returned '$($resolved -join ', ')', not the expected private endpoint '$expected'."
}
$connection = Test-NetConnection -ComputerName $hostname -Port 445 -WarningAction Continue
if (-not $connection.TcpTestSucceeded -or $connection.RemoteAddress.ToString() -ne $expected.ToString()) {
    throw "TCP 445 to the expected private endpoint for '$hostname' failed."
}
[pscustomobject]@{
    Hostname = $hostname
    PrivateEndpointIp = $expected.ToString()
    DnsVerified = $true
    Tcp445Verified = $true
    AuthenticatedSmbVerified = $false
    Limitation = 'Network-only check. Run as the scanner service identity separately to verify authenticated share access.'
}
