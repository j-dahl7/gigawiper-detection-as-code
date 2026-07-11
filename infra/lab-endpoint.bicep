@description('Disposable Windows endpoint used for bounded Defender telemetry validation.')
param vmName string = 'nls-gw-win-lab'

@description('Local administrator name. RDP is not exposed by this template.')
param adminUsername string = 'nlsadmin'

@secure()
@description('Ephemeral administrator password supplied only at deployment time.')
param adminPassword string

param location string = resourceGroup().location

@description('ISO date used by cost-control and cleanup automation to identify this disposable lab.')
param expirationDate string

var prefix = 'nls-gw-lab'

resource mdeOnboarding 'Microsoft.Security/mdeOnboardings@2021-10-01-preview' existing = {
  scope: subscription()
  // The published type schema still narrows this to "default" even though
  // Microsoft's built-in MDE policy references the supported "Windows" name.
  name: any('Windows')
}

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${prefix}-nsg'
  location: location
  tags: {
    Purpose: 'SafeGigaWiperTelemetry'
    Expiration: expirationDate
  }
  properties: {
    securityRules: []
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${prefix}-vnet'
  location: location
  tags: {
    Purpose: 'SafeGigaWiperTelemetry'
    Expiration: expirationDate
  }
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.44.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'endpoint'
        properties: {
          addressPrefix: '10.44.1.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
        }
      }
    ]
  }
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${prefix}-pip'
  location: location
  sku: {
    name: 'Standard'
  }
  tags: {
    Purpose: 'OutboundOnlyNoInboundRules'
    Expiration: expirationDate
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${prefix}-nic'
  location: location
  tags: {
    Purpose: 'SafeGigaWiperTelemetry'
    Expiration: expirationDate
  }
  properties: {
    ipConfigurations: [
      {
        name: 'primary'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIp.id
          }
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', vnet.name, 'endpoint')
          }
        }
      }
    ]
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: vmName
  location: location
  tags: {
    Purpose: 'SafeGigaWiperTelemetry'
    Expiration: expirationDate
  }
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v4'
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: '2022-datacenter-azure-edition'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        caching: 'ReadWrite'
        deleteOption: 'Delete'
        managedDisk: {
          storageAccountType: 'Standard_LRS'
        }
      }
    }
    osProfile: {
      computerName: 'nls-gw-lab'
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: {
        provisionVMAgent: true
        enableAutomaticUpdates: true
        patchSettings: {
          assessmentMode: 'AutomaticByPlatform'
          patchMode: 'AutomaticByPlatform'
          enableHotpatching: false
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
          properties: {
            deleteOption: 'Delete'
            primary: true
          }
        }
      ]
    }
    securityProfile: {
      securityType: 'TrustedLaunch'
      uefiSettings: {
        secureBootEnabled: true
        vTpmEnabled: true
      }
    }
  }
}

resource mdeExtension 'Microsoft.Compute/virtualMachines/extensions@2024-07-01' = {
  parent: vm
  name: 'MDE.Windows'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.AzureDefenderForServers'
    type: 'MDE.Windows'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
    settings: {
      azureResourceId: vm.id
      vNextEnabled: 'true'
      installedBy: 'NineLivesLab'
    }
    protectedSettings: {
      defenderForEndpointOnboardingScript: mdeOnboarding.properties.onboardingPackageWindows
    }
  }
}

output virtualMachineId string = vm.id
output endpointName string = vm.name
output publicIpAddress string = publicIp.properties.ipAddress
output inboundSecurityRules int = length(nsg.properties.securityRules)
