@{
    RootModule = 'PurviewIPAsCode.psm1'
    ModuleVersion = '1.0.0'
    GUID = '16d0f5c2-5272-42bc-9ba9-0eb870912afa'
    Author = 'Purview IP as code contributors'
    Description = 'Offline-first configuration validation and guarded Microsoft Purview reconciliation.'
    PowerShellVersion = '7.4'
    FunctionsToExport = @(
        'Test-PurviewConfiguration',
        'Build-PurviewRulePackage',
        'Get-PurviewDeploymentPlan',
        'Initialize-PurviewInventory',
        'Invoke-PurviewDeployment',
        'Get-PurviewDriftReport',
        'Enable-PurviewAutoLabeling',
        'Get-PurviewAdapterCapability',
        'Set-PurviewScannerDiscovery'
    )
    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @()
    PrivateData = @{
        PSData = @{
            Prerelease = 'beta1'
            Tags = @('Purview', 'InformationProtection', 'InfrastructureAsCode')
            ProjectUri = 'https://github.com/x3nc0n/purview-ip-as-code'
        }
    }
}
