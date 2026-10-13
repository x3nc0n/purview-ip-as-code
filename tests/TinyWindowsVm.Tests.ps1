BeforeAll {
    $repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $compiledPath = Join-Path $TestDrive 'tiny-windows-vm.json'
    az bicep build --file (Join-Path $repositoryRoot 'extensions\scanner\infra\tiny-windows-vm.bicep') --outfile $compiledPath
    if ($LASTEXITCODE -ne 0) { throw 'Tiny Windows VM Bicep compilation failed.' }
    $template = Get-Content -LiteralPath $compiledPath -Raw | ConvertFrom-Json -Depth 100
    $script:vm = $template.resources | Where-Object type -eq 'Microsoft.Compute/virtualMachines'
    $script:nic = $template.resources | Where-Object type -eq 'Microsoft.Network/networkInterfaces'
}

Describe 'Tiny Windows lab VM contract' {
    It 'creates only a VM and private NIC without promotion or extensions' {
        $template.resources.Count | Should -Be 2
        $vm | Should -Not -BeNullOrEmpty
        $nic | Should -Not -BeNullOrEmpty
        $nic.properties.ipConfigurations[0].properties.privateIPAllocationMethod | Should -Be 'Static'
        $nic.properties.ipConfigurations[0].properties.PSObject.Properties.Name | Should -Not -Contain 'publicIPAddress'
    }

    It 'uses a small Windows Gen2 VM and persistent low-cost OS disk' {
        $template.parameters.vmSize.defaultValue | Should -Be 'Standard_B2als_v2'
        $template.parameters.imageVersion.PSObject.Properties.Name | Should -Not -Contain 'defaultValue'
        $vm.properties.storageProfile.imageReference.sku | Should -Be '2022-datacenter-g2'
        $vm.properties.storageProfile.osDisk.managedDisk.storageAccountType | Should -Be 'Standard_LRS'
        $vm.properties.storageProfile.osDisk.PSObject.Properties.Name | Should -Not -Contain 'diffDiskSettings'
    }

    It 'requires a secure administrator password and never emits it' {
        $template.parameters.adminPassword.type | Should -Be 'secureString'
        $template.parameters.adminPassword.minLength | Should -Be 14
        $template.outputs.PSObject.Properties.Name | Should -Not -Contain 'adminPassword'
        ($template.outputs | ConvertTo-Json -Depth 10) | Should -Not -Match 'adminPassword'
    }

    It 'enforces workday tags on both resources while allowing other tags' {
        $template.variables.scheduledTags | Should -Match "union\(parameters\('tags'\)"
        $template.variables.scheduledTags | Should -Match 'start-stop'
        $template.variables.scheduledTags | Should -Match 'workday'
        $vm.tags | Should -Be "[variables('scheduledTags')]"
        $nic.tags | Should -Be "[variables('scheduledTags')]"
        $main = Get-Content (Join-Path $repositoryRoot 'extensions\scanner\infra\main.bicep') -Raw
        $main | Should -Match "'start-stop': 'workday'"
    }

    It 'provides only a secret reference in the example parameters' {
        $example = Get-Content (Join-Path $repositoryRoot 'extensions\scanner\infra\tiny-windows-vm.parameters.example.json') -Raw | ConvertFrom-Json
        $example.parameters.adminPassword.reference.secretName | Should -Not -BeNullOrEmpty
        $example.parameters.adminPassword.PSObject.Properties.Name | Should -Not -Contain 'value'
    }
}
