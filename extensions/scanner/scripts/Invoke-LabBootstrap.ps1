[CmdletBinding()]
param(
    [string]$TenantId,
    [string]$AppId,
    [string]$DelegatedUser,
    [string]$VaultUri,
    [string]$StorageAccountName,
    [string]$ShareName,
    [string]$SqlExpressUri,
    [string]$SqlExpressSha256,
    [string]$ClientUri,
    [string]$ClientSha256,
    [string]$FixtureUri,
    [string]$FixtureSha256,
    [string]$BootstrapParametersBase64,
    [string]$VerifyBootstrapSha256,
    [switch]$Resume,
    [switch]$ServiceContext
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$stateDirectory = Join-Path $env:ProgramData 'PurviewIPAsCode'
$statePath = Join-Path $stateDirectory 'readiness.json'
$parameterPath = Join-Path $stateDirectory 'bootstrap-parameters.json'
$passwordPath = Join-Path $stateDirectory 'scanner-service-password.dpapi'
$packageDirectory = Join-Path $stateDirectory 'packages'
$serviceName = 'PurviewScannerSvc'
$clusterName = 'PurviewIPAsCodeDemo'

[void](New-Item -ItemType Directory -Path $stateDirectory, $packageDirectory -Force)

function Get-ReadinessState {
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        $parsed = Get-Content -LiteralPath $statePath -Raw -Encoding utf8 | ConvertFrom-Json
        return ConvertTo-Hashtable -InputObject $parsed
    }
    return [ordered]@{
        schemaVersion = 1
        azureProvisioned = $true
        softwareInstalled = $false
        tenantConnected = $false
        demoContentSeeded = $false
        discoveryComplete = $false
        enforcementEnabled = $false
        scannerLabelConditionsSupported = $false
        readyForEnforcement = $false
        updatedAtUtc = [datetime]::UtcNow.ToString('o')
    }
}
$onBehalfParameter = (Get-Command Set-Authentication).Parameters['OnBehalfOf']
if ($onBehalfParameter.ParameterType -ne [pscredential]) {
    throw "Installed Set-Authentication expects OnBehalfOf type '$($onBehalfParameter.ParameterType.FullName)', not PSCredential; service-context authentication is unsupported by this runtime."
}

function ConvertTo-Hashtable {
    param([AllowNull()][object]$InputObject)
    if ($null -eq $InputObject) {
        return $null
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $result = @{}
        foreach ($property in $InputObject.PSObject.Properties) {
            $result[$property.Name] = ConvertTo-Hashtable -InputObject $property.Value
        }
        return ,$result
    }
    if ($InputObject -is [System.Collections.IDictionary]) {
        $result = @{}
        foreach ($key in $InputObject.Keys) {
            $result[$key] = ConvertTo-Hashtable -InputObject $InputObject[$key]
        }
        return ,$result
    }
    if ($InputObject -is [System.Collections.IList] -and $InputObject -isnot [string]) {
        $result = @()
        foreach ($item in $InputObject) {
            $result += ,(ConvertTo-Hashtable -InputObject $item)
        }
        return ,$result
    }
    return $InputObject
}

function Save-ReadinessState {
    param([Parameter(Mandatory)][System.Collections.IDictionary]$State)
    $State.updatedAtUtc = [datetime]::UtcNow.ToString('o')
    $temporary = "$statePath.tmp"
    [System.IO.File]::WriteAllText($temporary, (($State | ConvertTo-Json -Depth 8) + "`n"), [System.Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $statePath -Force
}

function Update-ReadinessEntry {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)]$Value)
    if ($PSCmdlet.ShouldProcess($statePath, "Update readiness value '$Name'")) {
        $current = Get-ReadinessState
        $current[$Name] = $Value
        Save-ReadinessState -State $current
    }
}

function Initialize-CredentialStore {
    if ('PurviewIPAsCode.CredentialStore' -as [type]) {
        return
    }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace PurviewIPAsCode {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct NativeCredential {
        public int Flags;
        public int Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public int CredentialBlobSize;
        public IntPtr CredentialBlob;
        public int Persist;
        public int AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct DataBlob {
        public int Size;
        public IntPtr Data;
    }

    public static class CredentialStore {
        [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CredWrite(ref NativeCredential credential, uint flags);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptProtectData(ref DataBlob input, string description, IntPtr optionalEntropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);

        [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool CryptUnprotectData(ref DataBlob input, IntPtr description, IntPtr optionalEntropy, IntPtr reserved, IntPtr prompt, int flags, out DataBlob output);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static SecureString ToSecureString(string value) {
            var secure = new SecureString();
            foreach (char character in value) secure.AppendChar(character);
            secure.MakeReadOnly();
            return secure;
        }

        public static void WriteFileShare(string target, string userName, SecureString password) {
            IntPtr targetPtr = IntPtr.Zero;
            IntPtr userPtr = IntPtr.Zero;
            IntPtr secretPtr = IntPtr.Zero;
            try {
                targetPtr = Marshal.StringToCoTaskMemUni(target);
                userPtr = Marshal.StringToCoTaskMemUni(userName);
                secretPtr = Marshal.SecureStringToGlobalAllocUnicode(password);
                var credential = new NativeCredential {
                    Type = 2,
                    TargetName = targetPtr,
                    UserName = userPtr,
                    CredentialBlob = secretPtr,
                    CredentialBlobSize = password.Length * 2,
                    Persist = 2
                };
                if (!CredWrite(ref credential, 0)) {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Windows Credential Manager write failed.");
                }
            } finally {
                if (targetPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(targetPtr);
                if (userPtr != IntPtr.Zero) Marshal.FreeCoTaskMem(userPtr);
                if (secretPtr != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(secretPtr);
            }
        }

        public static string ProtectMachineSecret(string value) {
            byte[] bytes = Encoding.UTF8.GetBytes(value);
            var input = new DataBlob { Size = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) };
            Marshal.Copy(bytes, 0, input.Data, bytes.Length);
            try {
                DataBlob output;
                if (!CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 4, out output)) {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Machine-scope DPAPI protection failed.");
                }
                try {
                    byte[] encrypted = new byte[output.Size];
                    Marshal.Copy(output.Data, encrypted, 0, output.Size);
                    return Convert.ToBase64String(encrypted);
                } finally {
                    LocalFree(output.Data);
                }
            } finally {
                Array.Clear(bytes, 0, bytes.Length);
                Marshal.FreeHGlobal(input.Data);
            }
        }

        public static string UnprotectMachineSecret(string encryptedValue) {
            byte[] bytes = Convert.FromBase64String(encryptedValue);
            var input = new DataBlob { Size = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) };
            Marshal.Copy(bytes, 0, input.Data, bytes.Length);
            try {
                DataBlob output;
                if (!CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, out output)) {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Machine-scope DPAPI decryption failed.");
                }
                try {
                    byte[] clear = new byte[output.Size];
                    Marshal.Copy(output.Data, clear, 0, output.Size);
                    try {
                        return Encoding.UTF8.GetString(clear);
                    } finally {
                        Array.Clear(clear, 0, clear.Length);
                    }
                } finally {
                    LocalFree(output.Data);
                }
            } finally {
                Array.Clear(bytes, 0, bytes.Length);
                Marshal.FreeHGlobal(input.Data);
            }
        }
    }
}
'@
}

function Write-SanitizedFailure {
    param([Parameter(Mandatory)][string]$Stage, [Parameter(Mandatory)][string]$Code)
    $current = Get-ReadinessState
    $current.failedStage = $Stage
    $current.diagnosticCode = $Code
    $current.readyForEnforcement = $false
    Save-ReadinessState -State $current
}

function Assert-Hash {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Label)
    if ($Value -notmatch '^[A-Fa-f0-9]{64}$') {
        throw "$Label must be an exact 64-character SHA-256 value."
    }
}

function Assert-HttpsUri {
    param([Parameter(Mandatory)][string]$Value, [Parameter(Mandatory)][string]$Label)
    $uri = $null
    if (-not [uri]::TryCreate($Value, [System.UriKind]::Absolute, [ref]$uri) -or $uri.Scheme -ne 'https') {
        throw "$Label must be an absolute HTTPS URL."
    }
}

function Import-BootstrapParameter {
    if (-not (Test-Path -LiteralPath $parameterPath -PathType Leaf)) {
        throw 'Resume state is missing its non-secret bootstrap parameters.'
    }
    $parameters = ConvertTo-Hashtable -InputObject (Get-Content -LiteralPath $parameterPath -Raw -Encoding utf8 | ConvertFrom-Json)
    $script:TenantId = [string]$parameters.tenantId
    $script:AppId = [string]$parameters.appId
    $script:DelegatedUser = [string]$parameters.delegatedUser
    $script:VaultUri = [string]$parameters.vaultUri
    $script:StorageAccountName = [string]$parameters.storageAccountName
    $script:ShareName = [string]$parameters.shareName
    $script:SqlExpressUri = [string]$parameters.sqlExpressUri
    $script:SqlExpressSha256 = [string]$parameters.sqlExpressSha256
    $script:ClientUri = [string]$parameters.clientUri
    $script:ClientSha256 = [string]$parameters.clientSha256
    $script:FixtureUri = [string]$parameters.fixtureUri
    $script:FixtureSha256 = [string]$parameters.fixtureSha256
    $script:VerifyBootstrapSha256 = [string]$parameters.bootstrapSha256
}

function Get-ManagedIdentityToken {
    param([Parameter(Mandatory)][string]$Resource)
    $identityEndpoint = 'http://169.254.169.254/metadata/identity/oauth2/token'
    $query = "api-version=2018-02-01&resource=$([uri]::EscapeDataString($Resource))"
    $response = Invoke-RestMethod -Method Get -Uri "$identityEndpoint`?$query" -Headers @{ Metadata = 'true' } -TimeoutSec 30
    if ([string]::IsNullOrWhiteSpace([string]$response.access_token)) {
        throw 'Managed identity did not return an access token.'
    }
    return [string]$response.access_token
}

function Get-KeyVaultScannerSecret {
    $token = Get-ManagedIdentityToken -Resource 'https://vault.azure.net'
    $vaultBase = $VaultUri.TrimEnd('/')
    $uri = "$vaultBase/secrets/scanner-app-secret?api-version=7.4"
    $response = Invoke-RestMethod -Method Get -Uri $uri -Headers @{ Authorization = "Bearer $token" } -TimeoutSec 30
    if ([string]::IsNullOrWhiteSpace([string]$response.value)) {
        throw 'Key Vault returned an empty scanner app credential.'
    }
    return [string]$response.value
}

function Get-StorageAccountKey {
    $instance = Invoke-RestMethod -Method Get -Uri 'http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01' -Headers @{ Metadata = 'true' } -TimeoutSec 30
    $subscriptionId = [string]$instance.subscriptionId
    $resourceGroupName = [string]$instance.resourceGroupName
    if (-not $subscriptionId -or -not $resourceGroupName) {
        throw 'VM instance metadata did not include the Azure scope needed for the lab storage account.'
    }
    $token = Get-ManagedIdentityToken -Resource 'https://management.azure.com/'
    $uri = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Storage/storageAccounts/$StorageAccountName/listKeys?api-version=2023-05-01"
    $response = Invoke-RestMethod -Method Post -Uri $uri -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body '{}' -TimeoutSec 60
    $key = [string](@($response.keys | Where-Object keyName -eq 'key1' | Select-Object -First 1 -ExpandProperty value))
    if ([string]::IsNullOrWhiteSpace($key)) {
        throw 'The VM identity could not retrieve the dedicated demo storage key.'
    }
    return $key
}

function Save-FileShareCredential {
    param([Parameter(Mandatory)][securestring]$Password)
    Initialize-CredentialStore
    $hostName = "$StorageAccountName.file.core.windows.net"
    $credentialTarget = $hostName
    $userName = "AZURE\$StorageAccountName"
    [PurviewIPAsCode.CredentialStore]::WriteFileShare($credentialTarget, $userName, $Password)
}

function Protect-LabStateDirectory {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Account)
    if ($PSCmdlet.ShouldProcess($stateDirectory, 'Restrict bootstrap state directory access')) {
        $acl = Get-Acl -LiteralPath $stateDirectory
        $acl.SetAccessRuleProtection($true, $false)
        $acl.Access | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
        foreach ($entry in @(
                @('SYSTEM', 'FullControl'),
                @('BUILTIN\Administrators', 'FullControl'),
                @($Account, 'Modify')
            )) {
            $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                $entry[0],
                [System.Security.AccessControl.FileSystemRights]$entry[1],
                [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
                [System.Security.AccessControl.PropagationFlags]::None,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $stateDirectory -AclObject $acl
    }
}

function Get-OrCreateScannerCredential {
    Initialize-CredentialStore
    $localUser = Get-LocalUser -Name $serviceName -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $passwordPath -PathType Leaf) {
        $encrypted = Get-Content -LiteralPath $passwordPath -Raw -Encoding utf8
        $plain = [PurviewIPAsCode.CredentialStore]::UnprotectMachineSecret($encrypted)
        $securePassword = [PurviewIPAsCode.CredentialStore]::ToSecureString($plain)
        $plain = $null
    }
    else {
        if ($localUser) {
            throw 'The scanner service account exists but its protected bootstrap password is missing; refusing to reset or guess its credentials.'
        }
        $random = New-Object byte[] 48
        $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $generator.GetBytes($random)
        $generator.Dispose()
        $plain = [Convert]::ToBase64String($random).Replace('/', 'x').Replace('+', 'y').TrimEnd('=')
        [Array]::Clear($random, 0, $random.Length)
        $securePassword = [PurviewIPAsCode.CredentialStore]::ToSecureString($plain)
        $passwordPointer = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($securePassword)
        try {
            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($passwordPointer)
            $protected = [PurviewIPAsCode.CredentialStore]::ProtectMachineSecret($plain)
            [System.IO.File]::WriteAllText($passwordPath, $protected, [System.Text.UTF8Encoding]::new($false))
        }
        finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($passwordPointer)
            $plain = $null
        }
    }
    if (-not $localUser) {
        New-LocalUser -Name $serviceName -Password $securePassword -PasswordNeverExpires -UserMayNotChangePassword -Description 'Microsoft Purview Information Protection scanner service account' | Out-Null
    }
    $qualifiedName = "$env:COMPUTERNAME\$serviceName"
    return [pscredential]::new($qualifiedName, $securePassword)
}

function Get-PinnedPackage {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][string]$Sha256,
        [Parameter(Mandatory)][string]$FileName,
        [switch]$RequireMicrosoftSignature
    )
    Assert-HttpsUri -Value $Uri -Label $FileName
    Assert-Hash -Value $Sha256 -Label $FileName
    $destination = Join-Path $packageDirectory $FileName
    if (Test-Path -LiteralPath $destination -PathType Leaf) {
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ieq $Sha256) {
            return $destination
        }
        Remove-Item -LiteralPath $destination -Force
    }
    $download = Invoke-WebRequest -Uri $Uri -OutFile $destination -MaximumRedirection 3 -TimeoutSec 900
    $baseResponse = if ($download) { $download.BaseResponse } else { $null }
    $requestMessage = if ($baseResponse) { $baseResponse.PSObject.Properties['RequestMessage'] } else { $null }
    $responseUri = if ($baseResponse) { $baseResponse.PSObject.Properties['ResponseUri'] } else { $null }
    $finalUri = if ($requestMessage -and $requestMessage.Value) {
        $requestMessage.Value.RequestUri
    }
    elseif ($responseUri) {
        $responseUri.Value
    }
    else {
        $null
    }
    if (-not $finalUri -or $finalUri.Scheme -ne 'https') {
        Remove-Item -LiteralPath $destination -Force
        throw "Package download '$FileName' did not complete over HTTPS."
    }
    $actual = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash
    if ($actual -ine $Sha256) {
        Remove-Item -LiteralPath $destination -Force
        throw "SHA-256 verification failed for pinned package '$FileName'."
    }
    if ($RequireMicrosoftSignature) {
        $signature = Get-AuthenticodeSignature -FilePath $destination
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') {
            Remove-Item -LiteralPath $destination -Force
            throw "The package '$FileName' does not have a valid Microsoft Authenticode signature."
        }
    }
    return $destination
}

function Register-BootstrapResume {
    $action = New-ScheduledTaskAction -Execute "$PSHOME\powershell.exe" -Argument '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "C:\ProgramData\PurviewIPAsCode\Invoke-LabBootstrap.ps1" -Resume'
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName 'PurviewIPAsCode-ResumeBootstrap' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}

function Invoke-PinnedInstaller {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Arguments,
        [Parameter(Mandatory)][string]$Name
    )
    $process = Start-Process -FilePath $Path -ArgumentList $Arguments -PassThru -Wait -WindowStyle Hidden
    if ($process.ExitCode -eq 3010) {
        Register-BootstrapResume
        Restart-Computer -Force
        exit 0
    }
    if ($process.ExitCode -ne 0) {
        throw "$Name installer failed with exit code $($process.ExitCode)."
    }
}

function Test-ScannerRuntimeCommand {
    $required = @{
        'Install-Scanner' = @('SqlServerInstance', 'Cluster', 'ServiceUserCredentials')
        'Set-ScannerContentScan' = @('Enforce', 'DiscoverInformationTypes', 'EnableDlp', 'LabelFilesByContent', 'RelabelFiles', 'EnforceDefaultLabel')
        'Get-ScannerRepository' = @()
        'Add-ScannerRepository' = @('Path')
        'Start-Scan' = @()
        'Get-ScanStatus' = @()
        'Set-Authentication' = @('AppId', 'AppSecret', 'TenantId', 'DelegatedUser', 'OnBehalfOf')
    }
    foreach ($name in $required.Keys) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if (-not $command) {
            throw "Required Purview command '$name' is not available in the installed, loaded scanner client."
        }
        $missing = @($required[$name] | Where-Object { $_ -notin $command.Parameters.Keys })
        if ($missing.Count -gt 0) {
            throw "Installed '$name' does not expose required documented parameters: $($missing -join ', ')."
        }
    }
    $onBehalfParameter = (Get-Command Set-Authentication).Parameters['OnBehalfOf']
    if ($onBehalfParameter.ParameterType -ne [pscredential]) {
        throw "Installed Set-Authentication expects OnBehalfOf type '$($onBehalfParameter.ParameterType.FullName)', not PSCredential; service-context authentication is unsupported by this runtime."
    }
}

function Invoke-ServiceContextConfiguration {
    Import-Module PurviewInformationProtection -ErrorAction Stop
    Test-ScannerRuntimeCommand

    $appSecret = Get-KeyVaultScannerSecret
    $storageKey = Get-StorageAccountKey
    $uncPath = "\\$StorageAccountName.file.core.windows.net\$ShareName"
    $resolved = Resolve-DnsName "$StorageAccountName.file.core.windows.net" -ErrorAction Stop
    if (-not ($resolved | Where-Object { $_.IPAddress -match '^10\.' -or $_.IPAddress -match '^172\.(1[6-9]|2\d|3[01])\.' -or $_.IPAddress -match '^192\.168\.' })) {
        throw 'Azure Files DNS did not resolve to a private IP address from the scanner service account.'
    }
    if (-not (Test-NetConnection -ComputerName "$StorageAccountName.file.core.windows.net" -Port 445 -InformationLevel Quiet)) {
        throw 'Azure Files SMB port 445 is not reachable through the private endpoint from the scanner service account.'
    }
    $storageSecureKey = [PurviewIPAsCode.CredentialStore]::ToSecureString($storageKey)
    Save-FileShareCredential -Password $storageSecureKey

    $protected = Get-Content -LiteralPath $passwordPath -Raw -Encoding utf8
    $servicePassword = [PurviewIPAsCode.CredentialStore]::UnprotectMachineSecret($protected)
    $serviceSecurePassword = [PurviewIPAsCode.CredentialStore]::ToSecureString($servicePassword)
    $servicePassword = $null
    $serviceCredential = [pscredential]::new("$env:COMPUTERNAME\$serviceName", $serviceSecurePassword)
    Set-Authentication -AppId $AppId -AppSecret $appSecret -TenantId $TenantId -DelegatedUser $DelegatedUser -OnBehalfOf $serviceCredential -ErrorAction Stop | Out-Null
    $appSecret = $null
    $storageKey = $null

    if (-not (Test-Path -LiteralPath $uncPath -PathType Container)) {
        throw 'The scanner service account could not open the configured Azure Files UNC path after credential provisioning.'
    }
    $probePath = Join-Path $uncPath '.pipascode-write-test'
    [System.IO.File]::WriteAllText($probePath, 'Synthetic scanner connectivity probe.')
    [System.IO.File]::Delete($probePath)

    $fixturePackage = Get-PinnedPackage -Uri $FixtureUri -Sha256 $FixtureSha256 -FileName 'demo-content.zip'
    $fixtureExtract = Join-Path $packageDirectory 'demo-content'
    $destination = Join-Path $uncPath 'fixtures'
    $fixtureMarker = Join-Path $destination '.purview-ip-as-code-fixture-sha256'
    if (Test-Path -LiteralPath $fixtureMarker -PathType Leaf) {
        $seededHash = (Get-Content -LiteralPath $fixtureMarker -Raw -Encoding utf8).Trim()
        if ($seededHash -ine $FixtureSha256) {
            throw 'Azure Files already contains a synthetic fixture release with a different SHA-256; refusing to overwrite it.'
        }
    }
    else {
        if ((Test-Path -LiteralPath $destination -PathType Container) -and @(Get-ChildItem -LiteralPath $destination -Force).Count -gt 0) {
            throw 'Azure Files fixture destination is nonempty but has no matching seed marker; refusing to overwrite or adopt unknown files.'
        }
        if (Test-Path -LiteralPath $fixtureExtract) {
            Remove-Item -LiteralPath $fixtureExtract -Recurse -Force
        }
        Expand-Archive -LiteralPath $fixturePackage -DestinationPath $fixtureExtract -Force
        $fixtureSource = Join-Path $fixtureExtract 'generated'
        $manifestSource = Join-Path $fixtureExtract 'fixtures.json'
        if (-not (Test-Path -LiteralPath $fixtureSource -PathType Container) -or -not (Test-Path -LiteralPath $manifestSource -PathType Leaf)) {
            throw 'The pinned fixture archive has no expected generated-content and manifest layout.'
        }
        [void](New-Item -ItemType Directory -Path $destination -Force)
        Copy-Item -Path (Join-Path $fixtureSource '*') -Destination $destination -Recurse -Force
        Copy-Item -LiteralPath $manifestSource -Destination (Join-Path $destination 'fixtures.json') -Force
        [System.IO.File]::WriteAllText($fixtureMarker, $FixtureSha256, [System.Text.UTF8Encoding]::new($false))
    }
    $fixtureCount = @(Get-ChildItem -LiteralPath (Join-Path $uncPath 'fixtures') -File -Recurse | Where-Object Extension -in @('.txt', '.docx', '.pdf')).Count
    Update-ReadinessEntry -Name 'tenantConnected' -Value $true
    Update-ReadinessEntry -Name 'demoContentSeeded' -Value $true
    Update-ReadinessEntry -Name 'repositoryPath' -Value $uncPath
    Update-ReadinessEntry -Name 'fixtureFileCount' -Value $fixtureCount

    $repository = Get-ScannerRepository -ErrorAction Stop | Where-Object { [string]$_.Path -eq "$uncPath\fixtures" }
    if (-not $repository) {
        Add-ScannerRepository -Path "$uncPath\fixtures" -ErrorAction Stop | Out-Null
    }
    Set-ScannerContentScan -Enforce Off -DiscoverInformationTypes All -EnableDlp On -LabelFilesByContent Off -RelabelFiles Off -EnforceDefaultLabel Off -ErrorAction Stop | Out-Null

    $before = Get-ScanStatus -ErrorAction Stop
    Start-Scan -ErrorAction Stop | Out-Null
    $deadline = [datetime]::UtcNow.AddMinutes(90)
    $observedScan = $false
    $lastStatus = $null
    $status = $before
    $statusProperty = @('ClusterStatus', 'Status') | Where-Object { $_ -in $status.PSObject.Properties.Name } | Select-Object -First 1
    $startProperty = @('ScanStartTime', 'StartTime') | Where-Object { $_ -in $status.PSObject.Properties.Name } | Select-Object -First 1
    if (-not $statusProperty -or -not $startProperty) {
        throw 'Get-ScanStatus output did not contain documented cluster-status and scan-start fields.'
    }
    while ([datetime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds 15
        $status = Get-ScanStatus -ErrorAction Stop
        if ($statusProperty -notin $status.PSObject.Properties.Name -or $startProperty -notin $status.PSObject.Properties.Name) {
            throw 'Get-ScanStatus output changed shape while a discovery cycle was running.'
        }
        $lastStatus = [string]$status.$statusProperty
        if ($lastStatus -eq 'Error') {
            throw 'Purview scanner returned Error. Inspect the scanner event log and its restricted local diagnostics.'
        }
        if ($lastStatus -eq 'Scanning') {
            $observedScan = $true
        }
        $startChanged = $status.$startProperty -and $status.$startProperty -ne $before.$startProperty
        if ($lastStatus -eq 'Idle' -and ($observedScan -or $startChanged)) {
            break
        }
    }
    if ($lastStatus -ne 'Idle' -or (-not $observedScan -and $status.$startProperty -eq $before.$startProperty)) {
        throw 'No completed scanner discovery cycle was observed within the bounded 90-minute window.'
    }
    $state = Get-ReadinessState
    $state.discoveryComplete = $true
    $state.enforcementEnabled = $false
    $state.scannerLabelConditionsSupported = $false
    $state.readyForEnforcement = $false
    $state.blockingLimitation = 'Discovery is complete. Label-level BCSI/PII condition mapping and manual-label behavior require a verified supported scanner adapter; no labeling or relabeling was enabled.'
    $state.clusterStatus = $lastStatus
    Save-ReadinessState -State $state
    Unregister-ScheduledTask -TaskName 'PurviewIPAsCode-ResumeBootstrap' -Confirm:$false -ErrorAction SilentlyContinue
    return [pscustomobject]@{
        TenantConnected = $true
        ContentSeeded = $true
        DiscoveryComplete = $true
    }
}

try {
    if ($Resume) {
        Import-BootstrapParameter
        $scriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
        if ($scriptHash -ine $VerifyBootstrapSha256) {
            throw 'Resumed bootstrap script SHA-256 does not match the original verified release asset.'
        }
    }
    else {
        if ([string]::IsNullOrWhiteSpace($BootstrapParametersBase64) -or [string]::IsNullOrWhiteSpace($VerifyBootstrapSha256)) {
            throw 'Initial bootstrap requires base64-encoded parameters and the expected script SHA-256.'
        }
        Assert-Hash -Value $VerifyBootstrapSha256 -Label 'bootstrap script'
        $scriptHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
        if ($scriptHash -ine $VerifyBootstrapSha256) {
            throw 'Bootstrap script SHA-256 verification failed.'
        }
        $decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($BootstrapParametersBase64))
        $parsedParameters = ConvertTo-Hashtable -InputObject ($decoded | ConvertFrom-Json)
        $parsedParameters.bootstrapSha256 = $VerifyBootstrapSha256
        [System.IO.File]::WriteAllText($parameterPath, (($parsedParameters | ConvertTo-Json -Depth 5) + "`n"), [System.Text.UTF8Encoding]::new($false))
        $script:TenantId = [string]$parsedParameters.tenantId
        $script:AppId = [string]$parsedParameters.appId
        $script:DelegatedUser = [string]$parsedParameters.delegatedUser
        $script:VaultUri = [string]$parsedParameters.vaultUri
        $script:StorageAccountName = [string]$parsedParameters.storageAccountName
        $script:ShareName = [string]$parsedParameters.shareName
        $script:SqlExpressUri = [string]$parsedParameters.sqlExpressUri
        $script:SqlExpressSha256 = [string]$parsedParameters.sqlExpressSha256
        $script:ClientUri = [string]$parsedParameters.clientUri
        $script:ClientSha256 = [string]$parsedParameters.clientSha256
        $script:FixtureUri = [string]$parsedParameters.fixtureUri
        $script:FixtureSha256 = [string]$parsedParameters.fixtureSha256
        Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $stateDirectory 'Invoke-LabBootstrap.ps1') -Force
    }
    foreach ($parameter in @(
            @('TenantId', $TenantId),
            @('AppId', $AppId),
            @('DelegatedUser', $DelegatedUser),
            @('VaultUri', $VaultUri),
            @('StorageAccountName', $StorageAccountName),
            @('ShareName', $ShareName),
            @('SqlExpressUri', $SqlExpressUri),
            @('ClientUri', $ClientUri),
            @('FixtureUri', $FixtureUri)
        )) {
        if ([string]::IsNullOrWhiteSpace([string]$parameter[1])) {
            throw "Required bootstrap setting '$($parameter[0])' is empty."
        }
    }
    foreach ($parameter in @(
            @('SQL Express', $SqlExpressSha256),
            @('Information Protection client', $ClientSha256),
            @('synthetic fixture archive', $FixtureSha256)
        )) {
        Assert-Hash -Value $parameter[1] -Label $parameter[0]
    }

    if ($ServiceContext) {
        Invoke-ServiceContextConfiguration | Out-Null
        exit 0
    }
    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Bootstrap must run elevated as LocalSystem or a local administrator.'
    }
    $operatingSystem = Get-CimInstance Win32_OperatingSystem
    $installationType = [string](Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallationType).InstallationType
    if ([Environment]::OSVersion.Version.Major -lt 10 -or $operatingSystem.ProductType -ne 3 -or $installationType -ne 'Server') {
        throw "Scanner host must use a supported Windows Server Desktop Experience image; detected product type '$($operatingSystem.ProductType)' and installation type '$installationType'."
    }
    Update-ReadinessEntry -Name 'azureProvisioned' -Value $true

    $sqlService = Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue
    if (-not $sqlService) {
        $sqlPackage = Get-PinnedPackage -Uri $SqlExpressUri -Sha256 $SqlExpressSha256 -FileName 'sql-express.exe' -RequireMicrosoftSignature
        Invoke-PinnedInstaller -Path $sqlPackage -Name 'SQL Server Express' -Arguments @(
            '/Q',
            '/ACTION=Install',
            '/FEATURES=SQLENGINE',
            '/INSTANCENAME=SQLEXPRESS',
            '/SQLSYSADMINACCOUNTS=BUILTIN\Administrators',
            '/TCPENABLED=1',
            '/IACCEPTSQLSERVERLICENSETERMS'
        )
        $sqlService = Get-Service -Name 'MSSQL$SQLEXPRESS' -ErrorAction SilentlyContinue
        if (-not $sqlService) {
            throw 'SQL Express setup returned success but the named SQLEXPRESS service is absent.'
        }
    }
    if ($sqlService.Status -ne 'Running') {
        Start-Service -Name $sqlService.Name
    }

    $clientModule = Get-Module -ListAvailable PurviewInformationProtection | Select-Object -First 1
    if (-not $clientModule) {
        $clientPackage = Get-PinnedPackage -Uri $ClientUri -Sha256 $ClientSha256 -FileName 'information-protection-client.exe' -RequireMicrosoftSignature
        Invoke-PinnedInstaller -Path $clientPackage -Name 'Microsoft Purview Information Protection client' -Arguments @('/quiet', '/norestart')
        $clientModule = Get-Module -ListAvailable PurviewInformationProtection | Select-Object -First 1
        if (-not $clientModule) {
            throw 'The signed client installer completed but the PurviewInformationProtection module is unavailable.'
        }
    }

    $serviceCredential = Get-OrCreateScannerCredential
    Protect-LabStateDirectory -Account $serviceCredential.UserName
    Import-Module PurviewInformationProtection -ErrorAction Stop
    Test-ScannerRuntimeCommand
    $installedScanner = Get-Service -DisplayName 'Microsoft Purview Information Protection Scanner' -ErrorAction SilentlyContinue
    if (-not $installedScanner) {
        Install-Scanner -SqlServerInstance "$env:COMPUTERNAME\SQLEXPRESS" -Cluster $clusterName -ServiceUserCredentials $serviceCredential -ErrorAction Stop | Out-Null
        $installedScanner = Get-Service -DisplayName 'Microsoft Purview Information Protection Scanner' -ErrorAction SilentlyContinue
        if (-not $installedScanner) {
            throw 'Install-Scanner returned success but its Windows service was not created.'
        }
    }
    $installedScannerInfo = Get-CimInstance Win32_Service -Filter "Name='$($installedScanner.Name)'"
    if ($installedScannerInfo.StartName -notmatch [regex]::Escape($serviceName)) {
        throw 'The scanner Windows service is not running under the configured local service account.'
    }
    if ($installedScanner.Status -ne 'Running') {
        Start-Service -Name $installedScanner.Name
    }
    Update-ReadinessEntry -Name 'softwareInstalled' -Value $true

    $workerArguments = "-NoLogo -NoProfile -ExecutionPolicy Bypass -File `"$stateDirectory\Invoke-LabBootstrap.ps1`" -Resume -ServiceContext"
    $workerProcess = Start-Process -FilePath "$PSHOME\powershell.exe" -Credential $serviceCredential -LoadUserProfile -ArgumentList $workerArguments -PassThru -Wait -WindowStyle Hidden
    if ($workerProcess.ExitCode -ne 0) {
        throw "Service-context credential setup, tenant connection, or synthetic content seeding failed with exit code $($workerProcess.ExitCode)."
    }

    $state = Get-ReadinessState
    if (-not $state.discoveryComplete) {
        throw 'Service-context run did not record completion of a scanner discovery cycle.'
    }
    Write-Output 'DiscoveryComplete; EnforcementEnabled=false; ReadyForEnforcement=false'
}
catch {
    $stage = if ($ServiceContext) { 'service-context-configuration' } elseif (-not (Get-ReadinessState).softwareInstalled) { 'software-installation' } elseif (-not (Get-ReadinessState).tenantConnected) { 'tenant-connection-and-seeding' } else { 'discovery' }
    Write-SanitizedFailure -Stage $stage -Code 'BootstrapStepFailed'
    throw
}
