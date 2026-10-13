targetScope = 'resourceGroup'

@description('Region of the existing scanner VNet.')
param location string = resourceGroup().location

@description('Full resource ID of the existing Azure Files storage account.')
param storageAccountId string

@description('Full resource ID of the existing private-endpoints subnet in the scanner VNet.')
param privateEndpointSubnetId string

@description('Full resource ID of the existing file private DNS zone linked to the scanner VNet.')
param filePrivateDnsZoneId string

@description('Name for this dedicated connection; use the same name on subsequent deployments.')
param privateEndpointName string

param tags object = {}

resource fileEndpoint 'Microsoft.Network/privateEndpoints@2023-09-01' = {
  name: privateEndpointName
  location: location
  tags: tags
  properties: {
    subnet: {
      id: privateEndpointSubnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${privateEndpointName}-file'
        properties: {
          privateLinkServiceId: storageAccountId
          groupIds: [
            'file'
          ]
        }
      }
    ]
  }
}

resource fileDnsGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-09-01' = {
  parent: fileEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'file'
        properties: {
          privateDnsZoneId: filePrivateDnsZoneId
        }
      }
    ]
  }
}

output privateEndpointId string = fileEndpoint.id
