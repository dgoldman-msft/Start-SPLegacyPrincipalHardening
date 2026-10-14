function Test-LegacyAcsAuthentication {
    <#
    .SYNOPSIS
        Task 2 - Read-only: checks whether ACS app-only (legacy add-in) authentication is disabled tenant-wide and reports the legacy SharePoint client-extensibility service principals.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $task = 'LegacyAddInSettings'
    Write-ToLogFile "`n== [2/8] Legacy add-in / ACS authentication settings ==" -LogFile $Context.LogFile -ForegroundColor Cyan

    # Entra side: the first-party principals cannot be deleted, so report their state and consented grants
    try {
        $legacyPrincipals = @(Get-LegacyServicePrincipal -Context $Context)
        if ($legacyPrincipals.Count -eq 0) {
            New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Info -Resource 'SharePoint Online Client Extensibility principals' -Finding 'None found in this tenant.'
        }
        foreach ($principal in $legacyPrincipals) {
            New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Info -Resource "$($principal.displayName) ($($principal.appId))" -Finding "Microsoft first-party principal, objectId $($principal.id), enabled: $($principal.accountEnabled). Cannot be deleted; monitored in task 5."

            $grants = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($principal.id)/oauth2PermissionGrants" -LogFile $Context.LogFile)
            foreach ($grant in $grants) {
                New-ReviewFinding -Context $Context -Task $task -Severity Low -Status Info -Resource $principal.displayName -Finding "Delegated grant ($($grant.consentType)) to resource $($grant.resourceId): $($grant.scope.Trim())" -LogOnly
            }
        }
    }
    catch {
        New-ReviewFinding -Context $Context -Task $task -Severity Low -Status Failed -Resource 'Entra service principals' -Finding 'Could not read legacy service principals.' -Detail $_.Exception.Message
    }

    if (-not $Context.PnPAvailable) {
        New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Skipped -Resource 'Tenant settings' -Finding 'PnP PowerShell session not available (no usable Entra app registration for PnP sign-in).' -Recommendation 'Provide -PnPClientId <appId> (or set $env:ENTRAID_APP_ID) for an app with a http://localhost redirect URI / public client flows enabled, and re-run.'
        return
    }

    try {
        $tenant = Get-PnPTenant -ErrorAction Stop
    }
    catch {
        New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Failed -Resource 'Tenant settings' -Finding 'Get-PnPTenant failed.' -Detail $_.Exception.Message
        return
    }

    if ($tenant.DisableCustomAppAuthentication) {
        New-ReviewFinding -Context $Context -Task $task -Severity High -Status Compliant -Resource 'DisableCustomAppAuthentication' -Finding 'ACS app-only authentication is disabled tenant-wide.'
    }
    else {
        New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource 'DisableCustomAppAuthentication' -Finding 'ACS app-only authentication is still allowed tenant-wide.' -Recommendation 'Disable it: Set-SPOTenant -DisableCustomAppAuthentication $true (or Set-PnPTenant). The setting is reversible. Confirm first that no remaining add-ins depend on ACS.'
    }

    try {
        $tenantServicePrincipal = Get-PnPTenantServicePrincipal -ErrorAction Stop
        if ($tenantServicePrincipal.AccountEnabled -eq $false) {
            New-ReviewFinding -Context $Context -Task $task -Severity Low -Status Compliant -Resource 'SharePoint Online Client service principal' -Finding 'Disabled.'
        }
        else {
            New-ReviewFinding -Context $Context -Task $task -Severity Low -Status Info -Resource 'SharePoint Online Client service principal' -Finding 'Enabled. Disabling it blocks SPFx API-permission grants, so it is only appropriate if you do not use SPFx solutions that call Graph or other APIs.' -Recommendation 'If you do not use SPFx API permissions, consider disabling it with Disable-PnPTenantServicePrincipal.'
        }
    }
    catch {
        New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Info -Resource 'SharePoint Online Client service principal' -Finding 'Not provisioned or not readable.' -Detail $_.Exception.Message -LogOnly
    }
}
