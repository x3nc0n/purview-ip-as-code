[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9]{3,24}$')][string]$StorageAccountName,
    [Parameter(Mandatory)][ValidatePattern('^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')][string]$ShareName,
    [Parameter(Mandatory)][string]$IdentityClientId,
    [Parameter(Mandatory)][string]$ArchiveBase64,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ArchiveSha256,
    [Parameter(Mandatory)][ValidatePattern('^[a-fA-F0-9]{40}$')][string]$SourceCommit
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
$repository = "\\$StorageAccountName.file.core.windows.net\$ShareName\fixtures"
$baseUri = "https://$StorageAccountName.file.core.windows.net/$ShareName/fixtures"
$bytes = [Convert]::FromBase64String($ArchiveBase64)
$sha = [Security.Cryptography.SHA256]::Create()
try { $actualHash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '') }
finally { $sha.Dispose() }
if ($actualHash -ne $ArchiveSha256) { throw 'Fixture archive checksum mismatch.' }
$stream = [IO.MemoryStream]::new($bytes, $false)
$archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read)
$files = @{}
try {
    foreach ($entry in $archive.Entries) {
        if ($entry.FullName.EndsWith('/')) { continue }
        if ($entry.FullName -eq 'demo/manifests/fixtures.json') { $name = 'fixtures.json' }
        elseif ($entry.FullName -match '^demo/content/generated/([a-z0-9-]+\.(?:txt|docx|pdf))$') { $name = $Matches[1] }
        else { throw "Unexpected archive entry '$($entry.FullName)'." }
        if ($files.ContainsKey($name) -or $entry.Length -gt 4MB) { throw 'Duplicate or oversized fixture.' }
        $inputStream = $entry.Open()
        $outputStream = [IO.MemoryStream]::new()
        try { $inputStream.CopyTo($outputStream); $files[$name] = $outputStream.ToArray() }
        finally { $inputStream.Dispose(); $outputStream.Dispose() }
    }
}
finally { $archive.Dispose(); $stream.Dispose() }
if ($files.Count -ne 29 -or -not $files.ContainsKey('fixtures.json')) { throw 'Expected the complete 29-file demo corpus.' }
$manifest = [Text.Encoding]::UTF8.GetString($files['fixtures.json']) | ConvertFrom-Json
if ($manifest.syntheticOnly -ne $true) { throw 'Fixture manifest is not synthetic.' }

$env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
Import-Module PurviewInformationProtection -ErrorAction Stop
if ([string](Get-ScanStatus).ClusterStatus -ne 'Idle') { throw 'Wait for the current scan to finish before resetting demo files.' }
$job = @(Get-ScannerContentScan | Where-Object { $_.PSObject.Properties.Name -contains 'Schedule' })
if ($job.Count -ne 1 -or [string]$job[0].Schedule -ne 'Manual') { throw 'Set the content scan job schedule to Manual before resetting demo files.' }
$service = Get-Service MIPScanner -ErrorAction Stop
if ($service.Status -ne 'Running') { throw 'Start the scanner service before requesting a demo reset.' }
$readinessPath = Join-Path $env:ProgramData 'PurviewIPAsCode\readiness.json'
$readiness = [IO.File]::ReadAllText($readinessPath) | ConvertFrom-Json
if ([string]$readiness.repositoryPath -ine $repository) { throw 'Readiness belongs to another scanner repository.' }
$resource = [uri]::EscapeDataString('https://storage.azure.com/')
$token = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$resource&client_id=$IdentityClientId" -Headers @{ Metadata = 'true' } -UseBasicParsing
$headers = @{
    Authorization = "Bearer $($token.access_token)"
    'x-ms-version' = '2023-11-03'
    'x-ms-file-request-intent' = 'backup'
}

function Get-DemoDirectoryEntry {
    $names = @()
    $marker = ''
    do {
        $headers['x-ms-date'] = [datetime]::UtcNow.ToString('R')
        $uri = "${baseUri}?restype=directory&comp=list"
        if ($marker) { $uri += "&marker=$([uri]::EscapeDataString($marker))" }
        $response = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing
        $listing = [xml]::new()
        $response.RawContentStream.Position = 0
        $listing.Load($response.RawContentStream)
        if ($listing.SelectNodes('/EnumerationResults/Entries/Directory').Count) {
            throw 'Unexpected subdirectory in fixtures; refusing recursive deletion.'
        }
        foreach ($node in $listing.SelectNodes('/EnumerationResults/Entries/File/Name')) {
            if ($node.InnerText -notmatch '^[a-zA-Z0-9][a-zA-Z0-9._-]*$') { throw 'Unsafe file name in fixtures.' }
            $names += $node.InnerText
        }
        $marker = [string]$listing.EnumerationResults.NextMarker
    } while ($marker)
    return $names
}

$existing = @(Get-DemoDirectoryEntry)
if (-not $PSCmdlet.ShouldProcess($repository, 'Replace demo files with verified committed originals')) { return }
Stop-Service MIPScanner -ErrorAction Stop
try {
    $readiness | Add-Member -NotePropertyMembers @{
        discoveryComplete = $false; readyForEnforcement = $false
        summaryPath = $null; detailedReportPath = $null; scannedFileCount = 0
        demoResetAtUtc = [datetime]::UtcNow.ToString('o'); demoSourceCommit = $SourceCommit
    } -Force
    $readiness | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $readinessPath -Encoding UTF8
    $stateDirectory = Join-Path $env:ProgramData 'PurviewIPAsCode-AdLab'
    foreach ($name in @('scan-result.json', 'bcsi-native-evidence.json', 'enforcement-result.json', 'enforcement-file-status.json', 'enforcement-evidence.json')) {
        $previous = Join-Path $stateDirectory $name
        if (Test-Path -LiteralPath $previous) {
            Move-Item -LiteralPath $previous -Destination (Join-Path $stateDirectory "$([datetime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ'))-before-reset-$name") -ErrorAction Stop
        }
    }
    foreach ($name in $existing) {
        $headers['x-ms-date'] = [datetime]::UtcNow.ToString('R')
        Invoke-WebRequest -Uri "$baseUri/$([uri]::EscapeDataString($name))" -Method Delete -Headers $headers -UseBasicParsing | Out-Null
    }
    foreach ($name in ($files.Keys | Sort-Object)) {
        $uri = "$baseUri/$([uri]::EscapeDataString($name))"
        $createHeaders = $headers.Clone()
        $createHeaders['x-ms-date'] = [datetime]::UtcNow.ToString('R')
        $createHeaders['x-ms-type'] = 'file'
        $createHeaders['x-ms-content-length'] = [string]$files[$name].Length
        $createHeaders['x-ms-file-permission'] = 'inherit'
        $createHeaders['x-ms-file-attributes'] = 'None'
        $createHeaders['x-ms-file-creation-time'] = 'now'
        $createHeaders['x-ms-file-last-write-time'] = 'now'
        Invoke-WebRequest -Uri $uri -Method Put -Headers $createHeaders -UseBasicParsing | Out-Null
        if ($files[$name].Length -gt 0) {
            $rangeHeaders = $headers.Clone()
            $rangeHeaders['x-ms-date'] = [datetime]::UtcNow.ToString('R')
            $rangeHeaders['x-ms-write'] = 'update'
            $rangeHeaders['x-ms-range'] = "bytes=0-$($files[$name].Length - 1)"
            Invoke-WebRequest -Uri "${uri}?comp=range" -Method Put -Headers $rangeHeaders -Body $files[$name] -ContentType 'application/octet-stream' -UseBasicParsing | Out-Null
        }
        $download = [IO.MemoryStream]::new()
        try {
            $headers['x-ms-date'] = [datetime]::UtcNow.ToString('R')
            $response = Invoke-WebRequest -Uri $uri -Headers $headers -UseBasicParsing
            $response.RawContentStream.Position = 0
            $response.RawContentStream.CopyTo($download)
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                if ([Convert]::ToBase64String($sha.ComputeHash($download.ToArray())) -ne
                    [Convert]::ToBase64String($sha.ComputeHash($files[$name]))) { throw "Restored file checksum mismatch: $name" }
            }
            finally { $sha.Dispose() }
        }
        finally { $download.Dispose() }
    }
    $restored = @(Get-DemoDirectoryEntry)
    if ($restored.Count -ne $files.Count -or @($restored | Where-Object { -not $files.ContainsKey($_) }).Count) {
        throw 'Restored directory does not match the pristine corpus.'
    }
    $evidence = [pscustomobject]@{
        ResetComplete = $true; Repository = $repository; DeletedFiles = $existing.Count
        VerifiedFiles = $files.Count; SourceCommit = $SourceCommit
        CompletedAtUtc = [datetime]::UtcNow.ToString('o')
        NextStep = 'Start a new full scan with Start-Scan -Reset under the scanner service-account context.'
    }
    $evidence | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $env:ProgramData 'PurviewIPAsCode-AdLab\demo-reset.json') -Encoding UTF8
}
finally {
    $headers = $null
    $token = $null
    Start-Service MIPScanner -ErrorAction Stop
    if ((Get-Service MIPScanner).Status -ne 'Running') { throw 'Scanner service did not restart after demo reset.' }
}
$evidence | ConvertTo-Json
