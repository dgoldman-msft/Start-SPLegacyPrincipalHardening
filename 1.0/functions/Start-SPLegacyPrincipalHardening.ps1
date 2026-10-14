function Start-SPLegacyPrincipalHardening {
    <#
    .SYNOPSIS
        Read-only security review of a tenant's exposure to the legacy SharePoint add-in / ACS and client-extensibility principals. Produces an HTML recommendations report; it never changes the tenant.

    .DESCRIPTION
        Runs eight read-only checks:

          1. AcsInventory          Inventory legacy add-in / ACS principals.
          2. LegacyAddInSettings   Check that ACS app-only authentication is disabled tenant-wide; report the first-party
                                   "SharePoint Online Client Extensibility" service principals.
          3. AppOnlyPermissions    Find apps with tenant-wide Sites/Files application permissions (Sites.Selected migration).
          4. CustomScript          Find site collections that still allow custom script.
          5. SignInMonitoring      Analyse Entra sign-ins of the legacy principals (volume, new/multiple countries,
                                   risk) and emit alert queries.
          6. IdentityProtection    ID Protection / Defender for Cloud Apps coverage, risky users, OAuth consent grants,
                                   user-consent settings, risk-based Conditional Access.
          7. LegacyAuthBlock       Conditional Access + SharePoint tenant setting that block legacy authentication.
          8. EnterpriseAppReview   Enterprise application review: owners, credentials, permissions, new/stale apps.

        The module only reads. It requests read-only Microsoft Graph scopes and calls only read cmdlets, so it cannot
        change permissions, policies, apps or settings. Every recommendation (with the Microsoft Learn article it is
        based on) is for the customer to review and carry out themselves. Results are written to an HTML report plus
        CSV/JSON/log files in the output folder.

        Modules (Microsoft.Graph.Authentication, PnP.PowerShell) are installed from the PowerShell Gallery if missing and
        existing Graph/PnP sessions are reused. Sign-in is interactive.

    .PARAMETER Task
        One or more of: All, AcsInventory, LegacyAddInSettings, AppOnlyPermissions, CustomScript, SignInMonitoring,
        IdentityProtection, LegacyAuthBlock, EnterpriseAppReview. Default All.

    .PARAMETER TenantId
        Tenant ID or verified domain.

    .PARAMETER TenantName
        SharePoint tenant name (the "contoso" in contoso.sharepoint.com). Auto-detected if omitted.

    .PARAMETER SharePointAdminUrl
        Explicit SharePoint admin URL.

    .PARAMETER PnPClientId
        Entra app (client) ID used by PnP.PowerShell for interactive sign-in. See Connect-SPLegacyTenant.

    .PARAMETER OutputPath
        Output folder. Defaults to Documents\SPLegacyPrincipalHardening\<timestamp>.

    .PARAMETER AcsScope
        Scope for Get-PnPAzureACSPrincipal: List, Web, Site, Tenant, All. Tenant/All populate ValidUntil. Default Tenant.

    .PARAMETER IncludeSubsites
        Include subsites when enumerating ACS principals.

    .PARAMETER ExcludeSiteUrl
        Site URL wildcard patterns to skip in the custom-script check.

    .PARAMETER IncludeOneDriveSites
        Include OneDrive sites in the custom-script check.

    .PARAMETER LookbackDays
        Sign-in history window. Default 7.

    .PARAMETER RecentHours
        "Recent" window used for anomaly detection inside the lookback. Default 24.

    .PARAMETER SignInVolumeThreshold
        Sign-ins per user/IP inside the recent window that raise a finding. Default 200.

    .PARAMETER MaxSignIns
        Cap on sign-in records retrieved per app. Default 20000.

    .PARAMETER ConsentLookbackDays
        Window for consent events, risk detections and Defender alerts. Default 30.

    .PARAMETER StaleAppDays
        Days without sign-in after which an enabled app is flagged. Default 90.

    .PARAMETER NewAppDays
        Apps created within this many days are flagged for review. Default 30.

    .EXAMPLE
        Start-SPLegacyPrincipalHardening -TenantId contoso.onmicrosoft.com -PnPClientId $appId

        Read-only review of all eight areas; writes Recommendations_<timestamp>.html to the output folder.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('All', 'AcsInventory', 'LegacyAddInSettings', 'AppOnlyPermissions', 'CustomScript', 'SignInMonitoring', 'IdentityProtection', 'LegacyAuthBlock', 'EnterpriseAppReview')]
        [string[]]$Task = 'All',

        [string]$TenantId,
        [string]$TenantName,
        [string]$SharePointAdminUrl,
        [string]$PnPClientId,
        [string]$OutputPath,

        [ValidateSet('List', 'Web', 'Site', 'Tenant', 'All')]
        [string]$AcsScope = 'Tenant',
        [switch]$IncludeSubsites,

        [string[]]$ExcludeSiteUrl = @(),
        [switch]$IncludeOneDriveSites,

        [ValidateRange(1, 30)]
        [int]$LookbackDays = 7,
        [ValidateRange(1, 720)]
        [int]$RecentHours = 24,
        [int]$SignInVolumeThreshold = 200,
        [int]$MaxSignIns = 20000,

        [ValidateRange(1, 365)]
        [int]$ConsentLookbackDays = 30,

        [int]$StaleAppDays = 90,
        [int]$NewAppDays = 30
    )

    $runId = Get-Date -Format 'yyyyMMdd_HHmmss'
    if (-not $OutputPath) {
        $OutputPath = Join-Path ([Environment]::GetFolderPath('MyDocuments')) "SPLegacyPrincipalHardening\$runId"
    }
    $logFile = Join-Path $OutputPath "SPLegacyPrincipalHardening_$runId.log"
    if (-not (Test-Path -LiteralPath $OutputPath)) { New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null }

    $tasks = if ($Task -contains 'All') { $script:AllTasks } else { @($script:AllTasks | Where-Object { $_ -in $Task }) }

    Write-ToLogFile "Start-SPLegacyPrincipalHardening - read-only review (no changes are made to the tenant); tasks: $($tasks -join ', ')" -LogFile $logFile -ForegroundColor Cyan
    Write-ToLogFile "Output folder: $OutputPath" -LogFile $logFile -ForegroundColor Cyan

    try {
        $session = Connect-TenantSession -TenantId $TenantId -TenantName $TenantName -SharePointAdminUrl $SharePointAdminUrl -PnPClientId $PnPClientId -Task $tasks -LogFile $logFile
    }
    catch {
        Write-ToLogFile "ERROR: could not connect to Microsoft Graph: $($_.Exception.Message)" -LogFile $logFile -ForegroundColor Red
        return
    }

    $context = [pscustomobject]@{
        RunId                 = $runId
        LogFile               = $logFile
        OutputPath            = $OutputPath
        Tasks                 = $tasks
        TenantId              = $session.TenantId
        AdminUrl              = $session.AdminUrl
        PnPAvailable          = $session.PnPAvailable
        PnPIssue              = $session.PnPIssue
        Findings              = [System.Collections.Generic.List[object]]::new()
        Datasets              = [ordered]@{}
        Cache                 = @{}
        AcsScope              = $AcsScope
        IncludeSubsites       = [bool]$IncludeSubsites
        ExcludeSiteUrl        = @($ExcludeSiteUrl)
        IncludeOneDriveSites  = [bool]$IncludeOneDriveSites
        LookbackDays          = $LookbackDays
        RecentHours           = $RecentHours
        SignInVolumeThreshold = $SignInVolumeThreshold
        MaxSignIns            = $MaxSignIns
        ConsentLookbackDays   = $ConsentLookbackDays
        StaleAppDays          = $StaleAppDays
        NewAppDays            = $NewAppDays
    }

    if ($session.PnPRequired) {
        if ($session.PnPAvailable) {
            $appText = if ($session.PnPClientId) { "'$(if ($session.PnPClientName) { $session.PnPClientName } else { $session.PnPClientId })' ($($session.PnPClientId))" } else { 'an existing PnP connection' }
            New-ReviewFinding -Context $context -Task 'Prerequisites' -Severity Info -Status Info -Resource 'Entra app for PnP sign-in' -Finding "SharePoint admin connected using $appText; source: $($session.PnPClientSource)." -LogOnly
        }
        else {
            New-ReviewFinding -Context $context -Task 'Prerequisites' -Severity Medium -Status Skipped -Resource 'Entra app for PnP sign-in' -Finding "No usable Entra app registration for PnP sign-in, so SharePoint admin checks were not performed. $($session.PnPIssue)" -Recommendation "Create or select an Entra app registration with a http://localhost redirect URI (or 'Allow public client flows'), then re-run with -PnPClientId <appId> or set `$env:ENTRAID_APP_ID. To create one: Register-PnPEntraIDAppForInteractiveLogin -ApplicationName 'SPLegacyHardening' -Tenant <tenant>.onmicrosoft.com" -LogOnly
        }
    }

    $taskFunctions = [ordered]@{
        AcsInventory        = 'Invoke-AcsPrincipalInventory'
        LegacyAddInSettings = 'Test-LegacyAcsAuthentication'
        AppOnlyPermissions  = 'Test-AppOnlyPermissionScope'
        CustomScript        = 'Test-CustomScriptRestriction'
        SignInMonitoring    = 'Get-LegacyPrincipalSignIn'
        IdentityProtection  = 'Test-IdentityProtectionPosture'
        LegacyAuthBlock     = 'Test-LegacyAuthBlock'
        EnterpriseAppReview = 'Get-EnterpriseAppReview'
    }

    foreach ($taskName in $tasks) {
        try {
            & $taskFunctions[$taskName] -Context $context
        }
        catch {
            New-ReviewFinding -Context $context -Task $taskName -Severity Medium -Status Failed -Resource $taskName -Finding 'Task aborted with an unexpected error.' -Detail $_.Exception.Message
        }
    }

    Export-ReviewResult -Context $context
}
