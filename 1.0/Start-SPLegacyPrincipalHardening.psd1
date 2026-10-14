@{
    RootModule        = 'Start-SPLegacyPrincipalHardening.psm1'
    ModuleVersion     = '1.0'
    GUID              = 'b7d0e1a4-6c52-4f3a-9a8e-2d41c0a7f6e3'
    Author            = 'Dave Goldman'
    Description       = 'Audits and hardens a Microsoft 365 tenant against abuse of the legacy SharePoint add-in / Azure ACS and client-extensibility service principals.'
    PowerShellVersion = '7.4'
    FunctionsToExport = @('Start-SPLegacyPrincipalHardening', 'Connect-SPLegacyTenant', 'New-SPLegacyRecommendationReport')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags = @('M365', 'SharePoint', 'ACS', 'EntraID', 'Security', 'IncidentResponse', 'MicrosoftGraph', 'PnP')
        }
    }
}
