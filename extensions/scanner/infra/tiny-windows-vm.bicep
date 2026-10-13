targetScope = 'resourceGroup'

@description('Name of the standalone, unpromoted Windows lab VM.')
@maxLength(64)
param vmName string

@description('Windows computer name, at most 15 characters.')
@minLength(1)
@maxLength(15)
param computerName string

param location string = resourceGroup().location

@description('Existing private VM subnet resource ID; its NSG must block public inbound access.')
param subnetId string

@description('Available static private IPv4 address in the existing subnet.')
param privateIpAddress string

@description('Small x64 Windows-compatible VM size available in the deployment region.')
param vmSize string = 'Standard_B2als_v2'

param adminUsername string

@secure()
@minLength(14)
param adminPassword string

@description('Pin a reviewed Windows Server 2022 Gen2 image version for reproducibility.')
param imageVersion string

param tags object = {
  environment: 'demo'
  workload: 'purview-scanner-ad-lab'
}

var scheduledTags = union(tags, {
  'start-stop': 'workday'
})

resource nic 'Microsoft.Network/networkInterfaces@2023-09-01' = {
  name: '${vmName}-nic'
  location: location
  tags: scheduledTags
  properties: {
    ipConfigurations: [
      {
        name: 'private-ip'
        properties: {
          primary: true
          privateIPAllocationMethod: 'Static'
          privateIPAddress: privateIpAddress
          subnet: {
            id: subnetId
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: vmName
  location: location
  tags: scheduledTags
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: computerName
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: {
        provisionVMAgent: true
        enableAutomaticUpdates: true
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-datacenter-g2'
        version: imageVersion
      }
      osDisk: {
        name: '${vmName}-os'
        createOption: 'FromImage'
        diskSizeGB: 127
        caching: 'ReadWrite'
        managedDisk: {
          storageAccountType: 'Standard_LRS'
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

output vmId string = vm.id
output privateIpAddress string = privateIpAddress
