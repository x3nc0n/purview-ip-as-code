[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Prepare', 'Promote', 'Directory', 'StorageIdentity', 'Join', 'FilePermissions', 'Migrate', 'Authenticate', 'StartDiscovery', 'VerifyDiscovery', 'PersistDiscovery', 'Status', 'Worker')]
    [string]$Stage,
    [ValidatePattern('^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+$')][string]$DomainName = 'corp.tiny.local',
    [ValidatePattern('^[a-zA-Z0-9-]{1,15}$')][string]$NetBiosName = 'CORP',
    [ValidatePattern('^[a-z0-9]{3,24}$')][string]$StorageAccountName = 'stscannerdemod12f',
    [ValidatePattern('^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$')][string]$ShareName = 'scanner-demo',
    [ValidatePattern('^[a-zA-Z0-9-]{1,64}$')][string]$ClusterName = 'Az-Demo',
    [string]$EnvelopeBase64,
    [string]$RecipientCertificateBase64,
    [string]$WorkerOperation,
    [string]$TenantId,
    [string]$AppId,
    [string]$DelegatedUser,
    [string]$VaultUri,
    [string]$IdentityClientId,
    [ValidateSet('On', 'Off')][string]$StopExistingScan = 'Off'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$stateDirectory = Join-Path $env:ProgramData 'PurviewIPAsCode-AdLab'
$serviceUser = "$NetBiosName\PurviewScannerSvc"
$repositoryPath = "\\$StorageAccountName.file.core.windows.net\$ShareName\fixtures"
$certificateSubject = "CN=PurviewIPAsCode-AdLab-$env:COMPUTERNAME"

function Initialize-LabState {
    [void](New-Item -ItemType Directory -Path $stateDirectory -Force)
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($sid),
            'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'
        ))
    }
    Set-Acl -LiteralPath $stateDirectory -AclObject $acl
}

function Get-LabRandomPassword {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    'Lab!9' + [Convert]::ToBase64String($bytes)
}

function ConvertTo-LabSecureString {
    param([Parameter(Mandatory)][string]$Value)
    $secure = [Security.SecureString]::new()
    foreach ($character in $Value.ToCharArray()) { $secure.AppendChar($character) }
    $secure.MakeReadOnly()
    $secure
}

function Save-LabSecret {
    param([string]$Name, [string]$Value)
    Add-Type -AssemblyName System.Security
    $protected = [System.Security.Cryptography.ProtectedData]::Protect(
        [Text.Encoding]::UTF8.GetBytes($Value), $null,
        [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    [IO.File]::WriteAllText((Join-Path $stateDirectory $Name), [Convert]::ToBase64String($protected))
}

function Read-LabSecret {
    param([string]$Name)
    Add-Type -AssemblyName System.Security
    $protected = [Convert]::FromBase64String([IO.File]::ReadAllText((Join-Path $stateDirectory $Name)))
    [Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect(
        $protected, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine
    ))
}

function Get-LabCredential {
    [pscredential]::new($serviceUser, (ConvertTo-LabSecureString (Read-LabSecret 'service-password.dpapi')))
}

function Open-LabEnvelope {
    param([Parameter(Mandatory)][string]$Envelope)
    $cms = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Envelope))
    $certificate = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq $certificateSubject)
    if ($certificate.Count -ne 1 -or -not $certificate[0].HasPrivateKey) { throw 'Expected one receiver certificate with a local private key.' }
    Unprotect-CmsMessage -Content $cms -To $certificate[0] | ConvertFrom-Json
}

function Protect-LabEnvelope {
    param([object]$Payload, [Parameter(Mandatory)][string]$Recipient)
    $certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new(
        [Convert]::FromBase64String($Recipient)
    )
    $cms = Protect-CmsMessage -Content ($Payload | ConvertTo-Json -Compress) -To $certificate
    [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($cms))
}

function Import-ScannerModule {
    $env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
    Import-Module PurviewInformationProtection -ErrorAction Stop
}

function Assert-DiscoveryJob {
    $job = @(Get-ScannerContentScan | Where-Object { $_.PSObject.Properties.Name -contains 'Enforce' })
    if ($job.Count -ne 1) { throw 'Expected one configured content scan job.' }
    foreach ($name in 'Enforce', 'RelabelFiles', 'EnforceDefaultLabel') {
        if ([string]$job[0].$name -notin @('Off', 'False')) { throw "Unsafe content scan setting: $name must be Off." }
    }
    if ([string]$job[0].LabelFilesByContent -notin @('On', 'True')) { throw 'Content inspection requires LabelFilesByContent On; Enforce Off prevents label writes.' }
}

function Set-LabReadiness {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][hashtable]$Values)
    $path = Join-Path $env:ProgramData 'PurviewIPAsCode\readiness.json'
    if (-not $PSCmdlet.ShouldProcess($path, 'Update scanner lab readiness')) { return }
    if (-not (Test-Path -LiteralPath $path)) { throw 'Existing scanner bootstrap readiness file is required.' }
    $previous = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $state = @{}
    foreach ($property in $previous.PSObject.Properties) { $state[$property.Name] = $property.Value }
    foreach ($key in $Values.Keys) { $state[$key] = $Values[$key] }
    $state.updatedAtUtc = [datetime]::UtcNow.ToString('o')
    $temporary = "$path.adlab.tmp"
    $state | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $path -Force
}

function Save-LabDiscoveryReadiness {
    $result = Get-Content -LiteralPath (Join-Path $stateDirectory 'scan-result.json') -Raw | ConvertFrom-Json
    $service = Get-CimInstance Win32_Service -Filter "Name='MIPScanner'"
    if ($service.StartName -ine $serviceUser -or $service.State -ne 'Running') {
        throw 'Current scanner service does not confirm the domain identity.'
    }
    if ($result.ServiceAccount -ine $serviceUser -or $result.Repository -ine $repositoryPath -or $result.EnforcementEnabled -ne $false -or $result.ScannerWriteDenied -ne $true -or $result.RestrictiveAclsValidated -ne $true -or $result.FixtureCount -lt 1) {
        throw 'Discovery evidence does not match the approved domain account/read-only repository.'
    }
    $started = [datetime]::Parse((Get-Content (Join-Path $stateDirectory 'scan-started-utc.txt') -Raw)).ToUniversalTime()
    foreach ($path in @($result.SummaryPath, $result.DetailedReportPath)) {
        if ((Get-Item -LiteralPath $path).LastWriteTimeUtc -lt $started) { throw 'Persisted report predates the requested scan.' }
    }
    Set-LabReadiness @{
        serviceAccount=$serviceUser; repositoryPath=$repositoryPath; cluster=$ClusterName
        configurationMode='Offline'; tenantConnected=$true; discoveryComplete=$true
        enforcementEnabled=$false; readyForEnforcement=$false; scannerLabelConditionsSupported=$false
        expectedDetectionsValidated=$false; clusterStatus=$null; lastScanStatus='Completed'; scannedFileCount=$result.FixtureCount
        summaryPath=$result.SummaryPath; detailedReportPath=$result.DetailedReportPath
        scannerWriteDenied=$true; restrictiveAclsValidated=$true
        failedStage=$null; diagnosticCode=$null
        blockingLimitation='Azure Files discovery is complete. Expected SIT detections and labeling/protection behavior are not validated; enforcement remains disabled.'
    }
}

function Invoke-LabWorker {
    param([string]$Operation, [pscredential]$Credential = (Get-LabCredential))
    $taskName = 'PurviewIPAsCode-AdLab-Worker'
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        if ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running') { throw 'A lab worker is already running.' }
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
    $scriptPath = Join-Path $stateDirectory 'Invoke-ScannerAdLab.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $scriptPath -Force
    $arguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Stage Worker -WorkerOperation $Operation -DomainName $DomainName -NetBiosName $NetBiosName -StorageAccountName $StorageAccountName -ShareName $ShareName -ClusterName $ClusterName"
    if ($Operation -eq 'Authenticate') {
        foreach ($id in @($TenantId,$AppId,$IdentityClientId)) {
            if ($id -notmatch '^[a-fA-F0-9-]{36}$') { throw 'Explicit tenant/app/identity GUIDs are required.' }
        }
        if ($DelegatedUser -notmatch '^[a-zA-Z0-9._+-]+@[a-zA-Z0-9.-]+$' -or $VaultUri -notmatch '^https://[a-z0-9-]+\.vault\.azure\.net/?$') { throw 'Invalid delegated user or Key Vault URI.' }
        $arguments += " -TenantId $TenantId -AppId $AppId -IdentityClientId $IdentityClientId -DelegatedUser $DelegatedUser -VaultUri $VaultUri"
    }
    $command = "/c `"`"$PSHOME\powershell.exe`" $arguments > `"$stateDirectory\worker.log`" 2>&1`""
    $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument $command
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 2)
    $adminGroup = Get-LocalGroup -SID 'S-1-5-32-544'
    $temporaryAdministrator = $Credential.UserName -ieq $serviceUser
    if ($temporaryAdministrator) {
        if (@(Get-LocalGroupMember -Group $adminGroup | Where-Object Name -ieq $serviceUser).Count) {
            throw 'The scanner account must not have permanent local administrator membership.'
        }
        Add-LocalGroupMember -Group $adminGroup -Member $serviceUser
    }
    try {
        Register-ScheduledTask -TaskName $taskName -Action $action -Settings $settings -RunLevel Highest -User $Credential.UserName -Password $Credential.GetNetworkCredential().Password -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        Start-Sleep -Seconds 3
        $deadline = [datetime]::UtcNow.AddMinutes(100)
        while ((Get-ScheduledTask -TaskName $taskName).State -eq 'Running') {
            if ([datetime]::UtcNow -gt $deadline) { throw 'Scanner service-account worker timed out.' }
            Start-Sleep -Seconds 10
        }
        if ((Get-ScheduledTaskInfo -TaskName $taskName).LastTaskResult -ne 0) {
            throw "Scanner worker failed. Inspect restricted $stateDirectory\worker.log."
        }
    }
    finally {
        try {
            if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
                Stop-ScheduledTask -TaskName $taskName -ErrorAction Stop
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
            }
        }
        finally {
            if ($temporaryAdministrator) {
                Remove-LocalGroupMember -Group $adminGroup -Member $serviceUser -ErrorAction Stop
            }
        }
    }
}

if ($Stage -ne 'Worker') {
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Use elevated Windows PowerShell 5.1 on the target VM.'
    }
    if (-not $PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Execute AD lab stage '$Stage'")) { return }
    Initialize-LabState
}

switch ($Stage) {
    'Prepare' {
        $certificate = @(Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq $certificateSubject)
        if ($certificate.Count -eq 0) {
            $certificate = @(New-SelfSignedCertificate -Subject $certificateSubject -Type DocumentEncryptionCert -CertStoreLocation Cert:\LocalMachine\My -KeyLength 3072 -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddMonths(3))
        }
        if ($certificate.Count -ne 1) { throw 'Ambiguous envelope certificate.' }
        [pscustomobject]@{
            ComputerName = $env:COMPUTERNAME
            CertificateBase64 = [Convert]::ToBase64String($certificate[0].RawData)
            Thumbprint = $certificate[0].Thumbprint
        } | ConvertTo-Json
    }
    'Promote' {
        $computer = Get-CimInstance Win32_ComputerSystem
        if ($computer.DomainRole -ge 4) {
            if ($computer.Domain -ine $DomainName) { throw 'Existing controller belongs to a different domain.' }
            Write-Output 'ControllerAlreadyPromoted'
            break
        }
        if ($computer.PartOfDomain) { throw 'Refusing to replace membership in an existing domain.' }
        $disk = @(Get-Disk | Where-Object { $_.Location -match 'LUN 0' -and [math]::Round($_.Size / 1GB) -eq 32 })
        if ($disk.Count -ne 1) { throw 'Expected exactly one 32 GiB LUN 0 AD data disk.' }
        if ($disk[0].PartitionStyle -eq 'RAW') {
            Initialize-Disk -Number $disk[0].Number -PartitionStyle GPT | Out-Null
            New-Partition -DiskNumber $disk[0].Number -UseMaximumSize -DriveLetter F |
                Format-Volume -FileSystem NTFS -NewFileSystemLabel 'AD-Lab-Data' -Confirm:$false | Out-Null
        }
        $volume = Get-Volume -DriveLetter F
        if ($volume.FileSystemLabel -ne 'AD-Lab-Data') { throw 'F: is not the dedicated AD lab data volume.' }
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
        if (-not (Test-Path (Join-Path $stateDirectory 'dsrm-password.dpapi'))) {
            Save-LabSecret 'dsrm-password.dpapi' (Get-LabRandomPassword)
        }
        Import-Module ADDSDeployment
        Install-ADDSForest -DomainName $DomainName -DomainNetbiosName $NetBiosName -InstallDns -DatabasePath 'F:\NTDS' -LogPath 'F:\Logs' -SysvolPath 'F:\SYSVOL' -SafeModeAdministratorPassword (ConvertTo-LabSecureString (Read-LabSecret 'dsrm-password.dpapi')) -NoRebootOnCompletion -Force | Out-Null
        Write-Output 'ForestPromotionComplete; RebootRequired=true'
    }
    'Directory' {
        Import-Module ActiveDirectory
        $domain = Get-ADDomain
        if ($domain.DNSRoot -ine $DomainName -or $domain.NetBIOSName -ine $NetBiosName) { throw 'Unexpected AD domain.' }
        Set-DnsServerForwarder -IPAddress 168.63.129.16 -UseRootHint $false
        $ou = "OU=ScannerLab,$($domain.DistinguishedName)"
        if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ou'")) {
            New-ADOrganizationalUnit -Name ScannerLab -Path $domain.DistinguishedName | Out-Null
        }
        $user = Get-ADUser -Filter "SamAccountName -eq 'PurviewScannerSvc'"
        $secretPath = Join-Path $stateDirectory 'service-password.dpapi'
        if (-not $user) {
            if (-not (Test-Path $secretPath)) { Save-LabSecret 'service-password.dpapi' (Get-LabRandomPassword) }
            New-ADUser -Name PurviewScannerSvc -SamAccountName PurviewScannerSvc -UserPrincipalName "PurviewScannerSvc@$DomainName" -Path $ou -AccountPassword (ConvertTo-LabSecureString (Read-LabSecret 'service-password.dpapi')) -Enabled $true -PasswordNeverExpires $true -CannotChangePassword $true -KerberosEncryptionType AES256 | Out-Null
        }
        elseif (-not (Test-Path $secretPath)) { throw 'Existing domain service identity has no protected lab credential; refusing to reset it.' }
        $user = Get-ADUser PurviewScannerSvc
        if (@(Get-ADPrincipalGroupMembership $user | Where-Object { $_.SID.Value -match '-(512|519)$' }).Count) { throw 'Scanner identity unexpectedly has domain administrative rights.' }
        [pscustomobject]@{
            DomainName = $domain.DNSRoot
            NetBiosName = $domain.NetBIOSName
            DomainGuid = $domain.ObjectGUID.ToString()
            DomainSid = $domain.DomainSID.Value
            ServiceSid = $user.SID.Value
            ServiceEnvelope = Protect-LabEnvelope -Payload @{ password = Read-LabSecret 'service-password.dpapi' } -Recipient $RecipientCertificateBase64
        } | ConvertTo-Json
    }
    'StorageIdentity' {
        Import-Module ActiveDirectory
        $payload = Open-LabEnvelope -Envelope $EnvelopeBase64
        $domain = Get-ADDomain
        if ($domain.DNSRoot -ine $DomainName) { throw 'Unexpected domain for storage registration.' }
        $spn = "cifs/$StorageAccountName.file.core.windows.net"
        $sam = 'azfilesdemo'
        $computer = Get-ADComputer -Filter "SamAccountName -eq '$sam`$'" -Properties ServicePrincipalName
        $conflict = @(Get-ADObject -Filter "ServicePrincipalName -eq '$spn'")
        if ($conflict.Count -gt 0 -and (-not $computer -or $conflict[0].DistinguishedName -ne $computer.DistinguishedName)) { throw 'Storage SPN is owned by another AD identity.' }
        if (-not $computer) {
            New-ADComputer -Name $sam -SamAccountName "$sam`$" -Path "OU=ScannerLab,$($domain.DistinguishedName)" -Enabled $true -ServicePrincipalNames $spn -KerberosEncryptionType AES256 | Out-Null
        }
        Set-ADComputer -Identity $sam -KerberosEncryptionType AES256
        Set-ADAccountPassword -Identity "$sam`$" -Reset -NewPassword (ConvertTo-LabSecureString $payload.kerberosKey)
        $payload = $null
        $computer = Get-ADComputer $sam -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes
        [pscustomobject]@{
            DomainName = $domain.DNSRoot
            NetBiosName = $domain.NetBIOSName
            ForestName = $domain.Forest
            DomainGuid = $domain.ObjectGUID.ToString()
            DomainSid = $domain.DomainSID.Value
            StorageSid = $computer.SID.Value
            SamAccountName = $sam
            Spn = $computer.ServicePrincipalName
            EncryptionTypes = $computer.'msDS-SupportedEncryptionTypes'
        } | ConvertTo-Json
    }
    'Join' {
        $computer = Get-CimInstance Win32_ComputerSystem
        if ($computer.PartOfDomain) {
            if ($computer.Domain -ine $DomainName) { throw 'Scanner belongs to a different domain.' }
            if (-not (Test-ComputerSecureChannel)) { throw 'Domain secure channel is unhealthy.' }
            Write-Output 'ScannerAlreadyJoined'
            break
        }
        $payload = Open-LabEnvelope -Envelope $EnvelopeBase64
        $credential = [pscredential]::new($payload.userName, (ConvertTo-LabSecureString $payload.password))
        Add-Computer -DomainName $DomainName -Credential $credential -OUPath "OU=ScannerLab,DC=$($DomainName.Replace('.',',DC='))" -Force | Out-Null
        $payload = $null
        $credential = $null
        Write-Output 'DomainJoinComplete; RebootRequired=true'
    }
    'Migrate' {
        if (-not (Test-ComputerSecureChannel)) { throw 'Domain secure channel is unhealthy.' }
        Import-ScannerModule
        $payload = Open-LabEnvelope -Envelope $EnvelopeBase64
        Save-LabSecret 'service-password.dpapi' $payload.password
        $payload = $null
        $credential = Get-LabCredential
        $configuration = Get-ScannerConfiguration
        if ([string]$configuration.Cluster -cne $ClusterName) { throw 'Refusing to change scanner cluster during account migration.' }
        Set-LabReadiness @{
            serviceAccount=$serviceUser; repositoryPath=$repositoryPath; configurationMode='Offline'
            discoveryComplete=$false; tenantConnected=$false; enforcementEnabled=$false; readyForEnforcement=$false
            summaryPath=$null; detailedReportPath=$null; scannedFileCount=0
            diagnosticCode='AwaitingDomainAuthenticationAndUncReport'
        }
        $oldResult = Join-Path $stateDirectory 'scan-result.json'
        if (Test-Path $oldResult) { Move-Item $oldResult (Join-Path $stateDirectory 'prior-scan-result.json') -Force }
        $service = Get-CimInstance Win32_Service -Filter "Name='MIPScanner'"
        if ($service.StartName -ine $serviceUser) {
            Stop-Service MIPScanner
            Set-ScannerDatabase -SqlServerInstance "$env:COMPUTERNAME\SQLEXPRESS" -Cluster $ClusterName -ServiceUserCredentials $credential -Force | Out-Null
        }
        if ((Get-Service MIPScanner).Status -ne 'Running') { Start-Service MIPScanner }
        Set-ScannerConfiguration -OnlineConfiguration Off | Out-Null
        $jobMarker = Join-Path $stateDirectory 'local-discovery-job.json'
        if (-not (Test-Path $jobMarker)) {
            $backup = Join-Path $stateDirectory 'scanner-before-local-discovery.json'
            if (-not (Test-Path $backup)) {
                [pscustomobject]@{
                    Configuration = $configuration
                    ContentScan = @(Get-ScannerContentScan)
                    Repositories = (Get-ScannerRepository | Out-String)
                } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $backup
            }
            Remove-ScannerContentScan -Confirm:$false | Out-Null
        }
        Set-ScannerContentScan -Schedule Manual -Enforce Off -DiscoverInformationTypes All -EnableDlp Off -LabelFilesByContent On -RelabelFiles Off -EnforceDefaultLabel Off -Confirm:$false | Out-Null
        if (-not (Test-Path $jobMarker)) {
            Add-ScannerRepository -Path $repositoryPath -Confirm:$false | Out-Null
        }
        else {
            $previous = Get-Content -LiteralPath $jobMarker -Raw | ConvertFrom-Json
            if ($previous.Repository -ine $repositoryPath -or $previous.Cluster -cne $ClusterName) { throw 'Local discovery marker belongs to another repository/cluster.' }
            Get-ScannerRepository -Path $repositoryPath | Out-Null
        }
        Assert-DiscoveryJob
        [pscustomobject]@{ Repository=$repositoryPath; Cluster=$ClusterName } | ConvertTo-Json | Set-Content -LiteralPath $jobMarker
        Start-Service MIPScanner
        $service = Get-CimInstance Win32_Service -Filter "Name='MIPScanner'"
        if ($service.StartName -ine $serviceUser -or $service.State -ne 'Running') { throw 'Scanner service migration was not confirmed.' }
        [pscustomobject]@{ ServiceAccount = $service.StartName; State = $service.State; Cluster = $ClusterName; OnlineConfiguration = 'Off'; Repository = $repositoryPath } | ConvertTo-Json
    }
    'FilePermissions' {
        if (-not (Test-ComputerSecureChannel)) { throw 'Domain secure channel is unhealthy.' }
        if (-not $IdentityClientId) { throw 'Explicit managed identity client ID is required for FilesREST ACL administration.' }
        $rootPath = "\\$StorageAccountName.file.core.windows.net\$ShareName"
        $inventoryPath = Join-Path $stateDirectory 'files-acl-inventory.json'
        if (Test-Path $inventoryPath) {
            $paths = Get-Content -LiteralPath $inventoryPath -Raw | ConvertFrom-Json
        }
        else {
            $fixtures = Get-Item -LiteralPath $repositoryPath -ErrorAction Stop
            $paths = @((Get-Item -LiteralPath $rootPath)) + @($fixtures) + @(Get-ChildItem -LiteralPath $repositoryPath -Recurse -Force)
            @($paths | Select-Object FullName,PSIsContainer) | ConvertTo-Json | Set-Content -LiteralPath $inventoryPath
        }
        foreach ($item in $paths) {
            if ($item.FullName -ine $rootPath -and $item.FullName -ine $repositoryPath -and -not $item.FullName.StartsWith("$repositoryPath\", [StringComparison]::OrdinalIgnoreCase)) {
                throw 'ACL inventory contains a path outside the approved fixture repository.'
            }
        }
        $fileCount = @($paths | Where-Object { -not $_.PSIsContainer }).Count
        if ($fileCount -eq 0) { throw 'Refusing ACL changes on an empty fixture corpus.' }
        $backupPath = Join-Path $stateDirectory 'files-acl-before.json'
        if (-not (Test-Path $backupPath)) {
            @($paths | ForEach-Object {
                [pscustomobject]@{ Path=$_.FullName; Sddl=(Get-Acl -LiteralPath $_.FullName).Sddl }
            }) | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $backupPath
        }
        $serviceSid = ([Security.Principal.NTAccount]::new($serviceUser)).Translate([Security.Principal.SecurityIdentifier]).Value
        $adminSid = ([Security.Principal.NTAccount]::new("$NetBiosName\Domain Admins")).Translate([Security.Principal.SecurityIdentifier]).Value
        $resource = [uri]::EscapeDataString('https://storage.azure.com/')
        $token = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$resource&client_id=$IdentityClientId" -Headers @{Metadata='true'} -UseBasicParsing
        foreach ($item in $paths) {
            $inheritance = if ($item.PSIsContainer) { 'OICI' } else { '' }
            $sddl = "O:${adminSid}G:${adminSid}D:P(A;${inheritance};FA;;;SY)(A;${inheritance};FA;;;${adminSid})(A;${inheritance};0x1200a9;;;${serviceSid})"
            $relative = $item.FullName.Substring($rootPath.Length).Trim('\')
            $encoded = (@($relative.Split('\') | ForEach-Object { [uri]::EscapeDataString($_) }) -join '/')
            $url = "https://$StorageAccountName.file.core.windows.net/$ShareName"
            if ($encoded) { $url += "/$encoded" }
            $query = if ($item.PSIsContainer) { '?restype=directory&comp=properties' } else { '?comp=properties' }
            $headers = @{
                Authorization = "Bearer $($token.access_token)"
                'x-ms-version' = '2023-11-03'
                'x-ms-date' = [datetime]::UtcNow.ToString('R')
                'x-ms-file-request-intent' = 'backup'
                'x-ms-file-permission' = $sddl
                'x-ms-file-attributes' = 'preserve'
                'x-ms-file-creation-time' = 'preserve'
                'x-ms-file-last-write-time' = 'preserve'
            }
            Invoke-WebRequest -Uri "$url$query" -Method Put -Headers $headers -UseBasicParsing | Out-Null
        }
        $token = $null
        [pscustomobject]@{ Repository=$repositoryPath; FixtureFiles=$fileCount; ScannerAccess='ReadAndExecute'; AclBackup=$backupPath } | ConvertTo-Json
    }
    'Authenticate' {
        Invoke-LabWorker 'Authenticate'
        Restart-Service MIPScanner
        Set-LabReadiness @{ tenantConnected=$true; serviceAccount=$serviceUser; discoveryComplete=$false }
        Get-Content -LiteralPath (Join-Path $stateDirectory 'authentication-result.json') -Raw
    }
    'StartDiscovery' {
        Import-ScannerModule
        Assert-DiscoveryJob
        Set-LabReadiness @{ discoveryComplete=$false; readyForEnforcement=$false; enforcementEnabled=$false; summaryPath=$null; detailedReportPath=$null }
        if ([string](Get-ScanStatus).ClusterStatus -eq 'Scanning') {
            if ($StopExistingScan -ne 'On') { throw 'A scan cycle is already active. Wait for completion, or explicitly approve cancellation with -StopExistingScan On.' }
            Stop-Scan | Out-Null
            $stopDeadline = [datetime]::UtcNow.AddMinutes(10)
            while ([string](Get-ScanStatus).ClusterStatus -ne 'Idle') {
                if ([datetime]::UtcNow -gt $stopDeadline) { throw 'Existing scan did not reach Idle after cancellation.' }
                Start-Sleep -Seconds 15
            }
        }
        Invoke-LabWorker 'Scan'
        Save-LabDiscoveryReadiness
        Get-Content -LiteralPath (Join-Path $stateDirectory 'scan-result.json') -Raw
    }
    'PersistDiscovery' {
        Save-LabDiscoveryReadiness
        Write-Output 'DomainAzureFilesDiscoveryReadinessUpdated'
    }
    'VerifyDiscovery' {
        Invoke-LabWorker 'Verify'
        Save-LabDiscoveryReadiness
        Get-Content -LiteralPath (Join-Path $stateDirectory 'scan-result.json') -Raw
    }
    'Worker' {
        Import-ScannerModule
        if ([Security.Principal.WindowsIdentity]::GetCurrent().Name -ine $serviceUser) { throw 'Worker must run as the domain scanner account.' }
        if ($WorkerOperation -eq 'Authenticate') {
            $resource = [uri]::EscapeDataString('https://vault.azure.net')
            $token = Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$resource&client_id=$IdentityClientId" -Headers @{Metadata='true'} -UseBasicParsing
            $secret = Invoke-RestMethod -Uri "$($VaultUri.TrimEnd('/'))/secrets/scanner-app-secret?api-version=7.4" -Headers @{Authorization="Bearer $($token.access_token)"} -UseBasicParsing
            $credential = Get-LabCredential
            Set-Authentication -AppId $AppId -AppSecret $secret.value -TenantId $TenantId -DelegatedUser $DelegatedUser -OnBehalfOf $credential | Out-Null
            $credential = $null
            $secret = $null
            $token = $null
            [pscustomobject]@{ ServiceAccount=$serviceUser; Profile=$env:USERPROFILE; AuthenticationConfigured=$true } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $stateDirectory 'authentication-result.json')
            break
        }
        if ($WorkerOperation -notin @('Scan', 'Verify')) { throw 'Unsupported worker operation.' }
        Assert-DiscoveryJob
        $files = @(Get-ChildItem -LiteralPath $repositoryPath -File -Recurse -ErrorAction Stop)
        if ($files.Count -eq 0) { throw 'Azure Files fixture repository is empty.' }
        $scannerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $adminSid = ([Security.Principal.NTAccount]::new("$NetBiosName\Domain Admins")).Translate([Security.Principal.SecurityIdentifier]).Value
        $aclPaths = @("\\$StorageAccountName.file.core.windows.net\$ShareName", $repositoryPath) + @($files.FullName)
        foreach ($path in $aclPaths) {
            $acl = Get-Acl -LiteralPath $path
            if (-not $acl.AreAccessRulesProtected) { throw "Unexpected inherited ACL on $path." }
            $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
            if ($rules.Count -ne 3) { throw "Unexpected ACL entries on $path." }
            foreach ($rule in $rules) {
                $sid = $rule.IdentityReference.Value
                $expectedRights = if ($sid -eq $scannerSid) {
                    [Security.AccessControl.FileSystemRights]([int][Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [int][Security.AccessControl.FileSystemRights]::Synchronize)
                } else { [Security.AccessControl.FileSystemRights]::FullControl }
                if ($sid -notin @($scannerSid, $adminSid, 'S-1-5-18') -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne $expectedRights) {
                    throw "Unexpected permissions on $path."
                }
            }
        }
        foreach ($file in $files) {
            $stream = [IO.File]::OpenRead($file.FullName)
            $stream.Dispose()
        }
        $probe = Join-Path $repositoryPath ('.scanner-write-probe-' + [guid]::NewGuid().ToString('N'))
        $writeDenied = $false
        try {
            $stream = [IO.File]::Open($probe, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
            $stream.Dispose()
            Remove-Item -LiteralPath $probe -ErrorAction Stop
        }
        catch [UnauthorizedAccessException] { $writeDenied = $true }
        if (-not $writeDenied) { throw 'Scanner unexpectedly has write access to the discovery repository.' }
        if ($WorkerOperation -eq 'Scan') {
            $started = [datetime]::UtcNow
            [IO.File]::WriteAllText((Join-Path $stateDirectory 'scan-started-utc.txt'), $started.ToString('o'))
            Start-Scan -Reset -Force | Out-Null
        }
        else {
            $started = [datetime]::Parse((Get-Content (Join-Path $stateDirectory 'scan-started-utc.txt') -Raw)).ToUniversalTime()
        }
        $reportDirectory = Join-Path $env:LOCALAPPDATA 'Microsoft\MSIP\Scanner\Reports'
        $deadline = [datetime]::UtcNow.AddMinutes($(if ($WorkerOperation -eq 'Verify') { 5 } else { 90 }))
        $result = $null
        while ([datetime]::UtcNow -lt $deadline) {
            Start-Sleep -Seconds 15
            $summaries = @(Get-ChildItem -LiteralPath $reportDirectory -Filter Summary_*.txt -File -ErrorAction SilentlyContinue | Where-Object LastWriteTimeUtc -ge $started | Sort-Object LastWriteTimeUtc -Descending)
            $details = @(Get-ChildItem -LiteralPath $reportDirectory -Filter DetailedReport_*.csv -File -ErrorAction SilentlyContinue | Where-Object LastWriteTimeUtc -ge $started | Sort-Object LastWriteTimeUtc -Descending)
            if ($summaries.Count -eq 0 -or $details.Count -eq 0) { continue }
            $summary = [IO.File]::ReadAllText($summaries[0].FullName)
            if ($summary -notmatch '(?m)^Failed:\s*(\d+)\s*$') { continue }
            if ([int]$Matches[1] -gt 0) { throw 'Scan report contains failed files.' }
            if ($summary -notmatch '(?m)^Scan ended at:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}Z)\s*$') { continue }
            $ended = [datetime]::ParseExact($Matches[1], "yyyy-MM-dd HH:mm:ss'Z'", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AssumeUniversal,AdjustToUniversal')
            if ($ended -lt $started) { throw 'Summary belongs to a scan that ended before this request.' }
            $rows = @(Import-Csv -LiteralPath $details[0].FullName)
            $covered = $true
            foreach ($file in $files) {
                $matching = @($rows | Where-Object { $_.'File Name' -ieq $file.FullName })
                if ($matching.Count -eq 0) { $covered = $false; break }
                if (@($matching | Where-Object Status -ne 'Success').Count) { throw 'An Azure Files fixture was not scanned successfully.' }
            }
            if (-not $covered) { continue }
            $result = [pscustomobject]@{
                Repository = $repositoryPath
                ServiceAccount = $serviceUser
                FixtureCount = $files.Count
                ReportRowCount = $rows.Count
                SummaryPath = $summaries[0].FullName
                DetailedReportPath = $details[0].FullName
                Summary = $summary
                EnforcementEnabled = $false
                ExpectedDetectionsValidated = $false
                ScannerWriteDenied = $writeDenied
                RestrictiveAclsValidated = $true
                CompletedAtUtc = [datetime]::UtcNow.ToString('o')
                StartedAtUtc = $started.ToString('o')
                ScanEndedAtUtc = $ended.ToString('o')
            }
            break
        }
        if (-not $result) { throw 'No fresh successful report covers every Azure Files fixture before the deadline.' }
        $result | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $stateDirectory 'scan-result.json')
    }
    'Status' {
        $task = Get-ScheduledTask -TaskName 'PurviewIPAsCode-AdLab-Worker' -ErrorAction SilentlyContinue
        if ($task) { $task | Select-Object TaskName,State }
        if (Test-Path (Join-Path $stateDirectory 'worker.log')) { Get-Content (Join-Path $stateDirectory 'worker.log') -Tail 20 }
        if (Test-Path (Join-Path $stateDirectory 'scan-result.json')) { Get-Content (Join-Path $stateDirectory 'scan-result.json') -Raw }
    }
}
