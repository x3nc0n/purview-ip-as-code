param location string
param labName string
param vmSize string
param vmAdminUsername string
@secure()
param vmAdminPassword string
param vmSubnetId string
param storageAccountName string
param fileShareName string
param keyVaultUri string
param scannerTenantId string
param scannerAppId string
param scannerDelegatedUser string
param scannerClusterName string
param scannerConfigurationMode string
param identityResourceId string
param identityClientId string
param bootstrapArtifactUri string
param bootstrapSha256 string
param sqlExpressInstallerUri string
param sqlExpressInstallerSha256 string
param informationProtectionClientInstallerUri string
param informationProtectionClientInstallerSha256 string
param visualCppInstallerUri string
param visualCppInstallerSha256 string
param demoContentUri string
param demoContentSha256 string
param tags object

var bootstrapParametersBase64 = base64(string({
  tenantId: scannerTenantId
  appId: scannerAppId
  delegatedUser: scannerDelegatedUser
  clusterName: scannerClusterName
  configurationMode: scannerConfigurationMode
  vaultUri: keyVaultUri
  managedIdentityClientId: identityClientId
  storageAccountName: storageAccountName
  shareName: fileShareName
  sqlExpressUri: sqlExpressInstallerUri
  sqlExpressSha256: sqlExpressInstallerSha256
  clientUri: informationProtectionClientInstallerUri
  clientSha256: informationProtectionClientInstallerSha256
  visualCppUri: visualCppInstallerUri
  visualCppSha256: visualCppInstallerSha256
  fixtureUri: demoContentUri
  fixtureSha256: demoContentSha256
}))
var bootstrapSha256Base64 = base64(bootstrapSha256)
var bootstrapCommand = 'powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference=\'Stop\';$expected=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(\'${bootstrapSha256Base64}\'));if((Get-FileHash -LiteralPath .\\Invoke-LabBootstrap.ps1 -Algorithm SHA256).Hash -ne $expected){throw \'Bootstrap SHA-256 verification failed.\'};& .\\Invoke-LabBootstrap.ps1 -BootstrapParametersBase64 \'${bootstrapParametersBase64}\' -VerifyBootstrapSha256 $expected"'

resource nic 'Microsoft.Network/networkInterfaces@2023-09-01' = {
  name: '${labName}-scanner-nic'
  location: location
  tags: tags
  properties: {
    ipConfigurations: [
      {
        name: 'scanner-ip'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: vmSubnetId
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: '${labName}-scanner-vm'
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${identityResourceId}': {}
    }
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: take('${labName}-scanner', 15)
      adminUsername: vmAdminUsername
      adminPassword: vmAdminPassword
      windowsConfiguration: {
        provisionVMAgent: true
        enableAutomaticUpdates: true
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-datacenter-azure-edition'
        version: 'latest'
      }
      osDisk: {
        name: '${labName}-scanner-os'
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            primary: true
          }
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
      }
    }
  }
}

resource bootstrap 'Microsoft.Compute/virtualMachines/extensions@2023-09-01' = {
  parent: vm
  name: 'ScannerBootstrap'
  location: location
  tags: tags
  properties: {
    publisher: 'Microsoft.Compute'
    type: 'CustomScriptExtension'
    typeHandlerVersion: '1.10'
    autoUpgradeMinorVersion: false
    settings: {
      fileUris: [
        bootstrapArtifactUri
      ]
      timestamp: 1
    }
    protectedSettings: {
      commandToExecute: bootstrapCommand
    }
  }
}

output vmId string = vm.id
