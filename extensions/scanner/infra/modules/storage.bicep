param location string
param storageAccountName string
param privateEndpointSubnetId string
param virtualNetworkId string
param tags object

var filePrivateDnsZoneName = 'privatelink.file.${environment().suffixes.storage}'

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  tags: tags
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: true
    publicNetworkAccess: 'Disabled'
    networkAcls: {
      bypass: 'None'
      defaultAction: 'Deny'
      virtualNetworkRules: []
      ipRules: []
    }
  }
}

resource fileService 'Microsoft.Storage/storageAccounts/fileServices@2023-05-01' = {
  parent: storage
  name: 'default'
  properties: {
    protocolSettings: {
      smb: {
        versions: 'SMB3.1.1'
        authenticationMethods: 'NTLMv2'
        channelEncryption: 'AES-256-GCM'
      }
    }
  }
}

resource fileShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-05-01' = {
  parent: fileService
  name: 'scanner-demo'
  properties: {
    enabledProtocols: 'SMB'
    shareQuota: 100
    accessTier: 'TransactionOptimized'
  }
}

resource filePrivateDns 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: filePrivateDnsZoneName
  location: 'global'
  tags: tags
}

resource fileDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: filePrivateDns
  name: '${uniqueString(virtualNetworkId)}-scanner-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: virtualNetworkId
    }
  }
}

resource filePrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-09-01' = {
  name: '${storage.name}-file-pe'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: privateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${storage.name}-file'
        properties: {
          privateLinkServiceId: storage.id
          groupIds: [
            'file'
          ]
        }
      }
    ]
  }
}

resource fileDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-09-01' = {
  parent: filePrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'file'
        properties: {
          privateDnsZoneId: filePrivateDns.id
        }
      }
    ]
  }
}

output storageAccountId string = storage.id
output storageAccountName string = storage.name
output fileShareName string = fileShare.name
