targetScope = 'resourceGroup'

@description('Short demo lab name; use lowercase letters, digits, and hyphens.')
@minLength(3)
@maxLength(20)
param labName string = 'pipascode'

@description('Azure region for the isolated demo resources.')
param location string = resourceGroup().location

@description('Tags used to identify this disposable, synthetic-data lab.')
param ownerTag string

@description('Existing, reviewed release asset URL for the scanner bootstrap script.')
param bootstrapArtifactUri string

@description('Expected SHA-256 of the exact bootstrap release asset.')
@minLength(64)
@maxLength(64)
param bootstrapSha256 string

@description('Version-pinned SQL Server Express installer URL.')
param sqlExpressInstallerUri string

@description('Expected SHA-256 for the SQL Express installer.')
@minLength(64)
@maxLength(64)
param sqlExpressInstallerSha256 string

@description('Version-pinned Microsoft Purview Information Protection client installer URL.')
param informationProtectionClientInstallerUri string

@description('Expected SHA-256 for the Information Protection client installer.')
@minLength(64)
@maxLength(64)
param informationProtectionClientInstallerSha256 string

@description('Approved Microsoft Visual C++ x64 redistributable URL; content is pinned by SHA-256.')
param visualCppInstallerUri string

@description('Expected SHA-256 for the Visual C++ x64 redistributable.')
@minLength(64)
@maxLength(64)
param visualCppInstallerSha256 string

@description('Fixture ZIP from the same public release as this template.')
param demoContentUri string

@description('Expected SHA-256 for the synthetic fixture ZIP.')
@minLength(64)
@maxLength(64)
param demoContentSha256 string

@description('Tenant ID used by the separate scanner delegated identity.')
param scannerTenantId string

@description('App registration ID used by the Information Protection scanner.')
param scannerAppId string

@description('Licensed delegated Entra user assigned scanner label policies.')
param scannerDelegatedUser string

@description('Exact name of the existing cluster created in the Purview portal before deployment.')
@minLength(1)
param scannerClusterName string

@description('Online uses the portal cluster job. Offline is an explicitly selected disconnected lab mode.')
@allowed([
  'Online'
  'Offline'
])
param scannerConfigurationMode string = 'Online'

@secure()
@description('Scanner app secret, stored only as a Key Vault secret.')
param scannerAppSecret string

@description('Local Windows VM administrator account name.')
param vmAdminUsername string

@secure()
@minLength(14)
@description('Local Windows VM administrator password. Never emitted as an output.')
param vmAdminPassword string

@description('Optional supported non-Core Windows Server VM size.')
param vmSize string = 'Standard_D2s_v5'

var suffix = uniqueString(resourceGroup().id, labName)
var storageAccountName = 'pipascode${suffix}'
var keyVaultName = take(toLower(replace('${labName}-${suffix}', '-', '')), 24)
var tags = {
  'start-stop': 'workday'
  workload: 'purview-ip-as-code-scanner-demo'
  data: 'synthetic-only'
  owner: ownerTag
  environment: 'demo'
}

module networking 'modules/networking.bicep' = {
  name: 'scanner-network'
  params: {
    location: location
    labName: labName
    tags: tags
  }
}

module storage 'modules/storage.bicep' = {
  name: 'scanner-storage'
  params: {
    location: location
    storageAccountName: storageAccountName
    privateEndpointSubnetId: networking.outputs.privateEndpointSubnetId
    virtualNetworkId: networking.outputs.virtualNetworkId
    tags: tags
  }
}

module vault 'modules/key-vault.bicep' = {
  name: 'scanner-vault'
  params: {
    location: location
    keyVaultName: keyVaultName
    privateEndpointSubnetId: networking.outputs.privateEndpointSubnetId
    virtualNetworkId: networking.outputs.virtualNetworkId
    scannerAppSecret: scannerAppSecret
    tags: tags
  }
}

resource scannerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${labName}-scanner-identity'
  location: location
  tags: tags
}

module scannerVm 'modules/compute.bicep' = {
  name: 'scanner-vm'
  dependsOn: [
    vaultSecretsRole
  ]
  params: {
    location: location
    labName: labName
    vmSize: vmSize
    vmAdminUsername: vmAdminUsername
    vmAdminPassword: vmAdminPassword
    vmSubnetId: networking.outputs.vmSubnetId
    storageAccountName: storage.outputs.storageAccountName
    fileShareName: storage.outputs.fileShareName
    keyVaultUri: vault.outputs.vaultUri
    scannerTenantId: scannerTenantId
    scannerAppId: scannerAppId
    scannerDelegatedUser: scannerDelegatedUser
    scannerClusterName: scannerClusterName
    scannerConfigurationMode: scannerConfigurationMode
    identityResourceId: scannerIdentity.id
    identityClientId: scannerIdentity.properties.clientId
    bootstrapArtifactUri: bootstrapArtifactUri
    bootstrapSha256: bootstrapSha256
    sqlExpressInstallerUri: sqlExpressInstallerUri
    sqlExpressInstallerSha256: sqlExpressInstallerSha256
    informationProtectionClientInstallerUri: informationProtectionClientInstallerUri
    informationProtectionClientInstallerSha256: informationProtectionClientInstallerSha256
    visualCppInstallerUri: visualCppInstallerUri
    visualCppInstallerSha256: visualCppInstallerSha256
    demoContentUri: demoContentUri
    demoContentSha256: demoContentSha256
    tags: tags
  }
}

resource vaultResource 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: keyVaultName
}

resource vaultSecretsRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vaultResource.id, 'key-vault-secrets-user')
  scope: vaultResource
  dependsOn: [
    vault
  ]
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: scannerIdentity.properties.principalId
    principalType: 'ServicePrincipal'
  }
}

output scannerVmId string = scannerVm.outputs.vmId
output scannerIdentityPrincipalId string = scannerIdentity.properties.principalId
output storageAccountName string = storage.outputs.storageAccountName
output fileShareName string = storage.outputs.fileShareName
output keyVaultUri string = vault.outputs.vaultUri
