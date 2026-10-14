function Get-RequiredGraphScope {
    <#
    .SYNOPSIS
        Returns the delegated Microsoft Graph scopes needed for the selected tasks and mode.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Task
    )

    $scopes = [System.Collections.Generic.HashSet[string]]::new()
    [void]$scopes.Add('Organization.Read.All')

    $read = @{
        AcsInventory        = @('Application.Read.All')
        LegacyAddInSettings = @('Application.Read.All', 'DelegatedPermissionGrant.Read.All')
        AppOnlyPermissions  = @('Application.Read.All')
        CustomScript        = @()
        SignInMonitoring    = @('AuditLog.Read.All', 'Directory.Read.All')
        IdentityProtection  = @('IdentityRiskyUser.Read.All', 'IdentityRiskEvent.Read.All', 'DelegatedPermissionGrant.Read.All', 'AuditLog.Read.All', 'Policy.Read.All', 'Application.Read.All', 'SecurityAlert.Read.All')
        LegacyAuthBlock     = @('Policy.Read.All')
        EnterpriseAppReview = @('Application.Read.All', 'AuditLog.Read.All', 'Directory.Read.All', 'DelegatedPermissionGrant.Read.All')
    }

    foreach ($taskName in $Task) {
        foreach ($scope in $read[$taskName]) { [void]$scopes.Add($scope) }
    }

    return @($scopes | Sort-Object)
}
