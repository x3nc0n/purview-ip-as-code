param location string
param labName string
param tags object

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-09-01' = {
  name: '${labName}-nsg'
  location: location
  tags: tags
  properties: {
    securityRules: [
      {
        name: 'AllowHttpsEgress'
        properties: {
          description: 'Allow scanner bootstrap and Microsoft service HTTPS egress.'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: 'Internet'
          access: 'Allow'
          priority: 100
          direction: 'Outbound'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name: '${labName}-vnet'
  location: location
  tags: tags
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.40.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'scanner-vm'
        properties: {
          addressPrefix: '10.40.1.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
      {
        name: 'private-endpoints'
        properties: {
          addressPrefix: '10.40.2.0/24'
          privateEndpointNetworkPolicies: 'Disabled'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

output virtualNetworkId string = vnet.id
output vmSubnetId string = resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'scanner-vm')
output privateEndpointSubnetId string = resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'private-endpoints')
