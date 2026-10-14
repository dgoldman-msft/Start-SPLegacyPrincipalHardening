$script:AllTasks = @(
    'AcsInventory'
    'LegacyAddInSettings'
    'AppOnlyPermissions'
    'CustomScript'
    'SignInMonitoring'
    'IdentityProtection'
    'LegacyAuthBlock'
    'EnterpriseAppReview'
)

# Microsoft Services and Microsoft corporate tenants that own first-party apps
$script:MicrosoftTenantIds = @('f8cdef31-a31e-4b4a-93e4-5f571e91255a', '72f988bf-86f1-41af-91ab-2d7cd011db47')

# Internal helper functions
foreach ($helperFile in (Get-ChildItem -Path (Join-Path $PSScriptRoot 'internal\functions') -Filter '*.ps1')) {
    . $helperFile.FullName
}

# Public functions
. (Join-Path $PSScriptRoot 'functions\Connect-SPLegacyTenant.ps1')
. (Join-Path $PSScriptRoot 'functions\Start-SPLegacyPrincipalHardening.ps1')
. (Join-Path $PSScriptRoot 'functions\New-SPLegacyRecommendationReport.ps1')

Export-ModuleMember -Function 'Start-SPLegacyPrincipalHardening', 'Connect-SPLegacyTenant', 'New-SPLegacyRecommendationReport'
