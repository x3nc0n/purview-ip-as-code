targetScope = 'resourceGroup'

param location string = resourceGroup().location
param diskName string

resource disk 'Microsoft.Compute/disks@2023-10-02' = {
  name: diskName
  location: location
  tags: {
    environment: 'demo'
    workload: 'purview-scanner-ad-lab'
  }
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    creationData: {
      createOption: 'Empty'
    }
    diskSizeGB: 32
    networkAccessPolicy: 'DenyAll'
    publicNetworkAccess: 'Disabled'
  }
}

output diskId string = disk.id
