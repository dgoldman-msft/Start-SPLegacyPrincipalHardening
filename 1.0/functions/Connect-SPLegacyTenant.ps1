function Connect-SPLegacyTenant {
    <#
    .SYNOPSIS
        Connects to a tenant for the read-only legacy-principal review, installing/importing modules and reusing sessions.

    .DESCRIPTION
        Installs Microsoft.Graph.Authentication and PnP.PowerShell from the PowerShell Gallery when missing, imports them,
        and signs in interactively. Only read-only Microsoft Graph scopes are requested. Existing Microsoft Graph and PnP
        sessions for the same tenant/admin URL (and with sufficient Graph scopes) are reused instead of prompting again.

        Start-SPLegacyPrincipalHardening calls this automatically; use it directly to sign in ahead of time.

    .PARAMETER TenantId
        Tenant ID or verified domain to sign in to.

    .PARAMETER TenantName
        SharePoint tenant name (the "contoso" in contoso.sharepoint.com). Auto-detected from the initial domain if omitted.

    .PARAMETER SharePointAdminUrl
        Explicit SharePoint admin URL, e.g. https://contoso-admin.sharepoint.com.

    .PARAMETER PnPClientId
        Client ID of your Entra app registration for PnP interactive sign-in (required by PnP.PowerShell 2.x+).
        Falls back to $env:ENTRAID_APP_ID, ENTRAID_CLIENT_ID, then AZURE_CLIENT_ID.

    .PARAMETER GraphOnly
        Skip the SharePoint admin (PnP) connection.

    .PARAMETER LogPath
        Log file path. Defaults to a timestamped file under Documents\SPLegacyPrincipalHardening.

    .EXAMPLE
        Connect-SPLegacyTenant -TenantId contoso.onmicrosoft.com -PnPClientId 00000000-0000-0000-0000-000000000000
    #>
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [string]$TenantName,
        [string]$SharePointAdminUrl,
        [string]$PnPClientId,
        [switch]$GraphOnly,
        [string]$LogPath
    )

    if (-not $LogPath) {
        $LogPath = Join-Path ([Environment]::GetFolderPath('MyDocuments')) "SPLegacyPrincipalHardening\Connect_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    }

    $tasks = if ($GraphOnly) { @('SignInMonitoring', 'IdentityProtection', 'EnterpriseAppReview', 'AppOnlyPermissions') } else { $script:AllTasks }
    $session = Connect-TenantSession -TenantId $TenantId -TenantName $TenantName -SharePointAdminUrl $SharePointAdminUrl -PnPClientId $PnPClientId -Task $tasks -LogFile $LogPath
    $ready = "Ready. Tenant: $($session.TenantId); account: $($session.Account); SharePoint admin: $(if ($session.PnPAvailable) { $session.AdminUrl } else { 'NOT CONNECTED - see the ACTION REQUIRED notice above' })"
    Write-ToLogFile $ready -LogFile $LogPath -ForegroundColor $(if ($session.PnPRequired -and -not $session.PnPAvailable) { 'Yellow' } else { 'Green' })
    return $session
}
