function Get-LearnReference {
    <#
    .SYNOPSIS
        Maps a finding to the Microsoft Learn articles that ground its recommendation (url + title), or resolves the title of a known URL.
    .DESCRIPTION
        Every URL in the catalog was verified to resolve on learn.microsoft.com. Rules are matched against the finding's
        task and "Resource Finding" text; rules without a pattern are the per-task default, used when no specific rule matched.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Finding')]
    param(
        [Parameter(ParameterSetName = 'Finding', Mandatory)]
        [string]$Task,

        [Parameter(ParameterSetName = 'Finding')]
        [string]$Text,

        [Parameter(ParameterSetName = 'Title', Mandatory)]
        [string]$Url,

        [Parameter(ParameterSetName = 'Finding')]
        [int]$Max = 3
    )

    if (-not $script:LearnCatalog) {
        $base = 'https://learn.microsoft.com/en-us/'
        $entries = [ordered]@{
            AcsRetirement   = @('sharepoint/dev/sp-add-ins/retirement-announcement-for-azure-acs', 'Azure ACS retirement in Microsoft 365')
            AcsAppOnly      = @('sharepoint/dev/solution-guidance/security-apponly-azureacs', 'Granting access using SharePoint App-Only')
            EntraAppOnly    = @('sharepoint/dev/solution-guidance/security-apponly-azuread', 'Granting access via Entra ID App-Only')
            AddInPerms      = @('sharepoint/dev/sp-add-ins/add-in-permissions-in-sharepoint', 'Add-in permissions in SharePoint')
            SetSpoTenant    = @('powershell/module/sharepoint-online/set-spotenant', 'Set-SPOTenant (Microsoft.Online.SharePoint.PowerShell)')
            SitesSelected   = @('graph/permissions-selected-overview', 'Overview of Selected Permissions in OneDrive and SharePoint')
            GraphPerms      = @('graph/permissions-reference', 'Microsoft Graph permissions reference')
            CustomScript    = @('sharepoint/allow-or-prevent-custom-script', 'Allow or prevent custom scripts in SharePoint sites')
            SignInLogs      = @('entra/identity/monitoring-health/concept-sign-ins', 'Sign-in logs in Microsoft Entra ID')
            SpSignInActivity = @('graph/api/resources/serviceprincipalsigninactivity', 'servicePrincipalSignInActivity resource type')
            LogAnalytics    = @('entra/identity/monitoring-health/howto-analyze-activity-logs-log-analytics', 'Analyze activity logs using Log Analytics')
            SentinelRules   = @('azure/sentinel/detect-threats-custom', 'Create scheduled analytics rules in Microsoft Sentinel')
            AzureAlerts     = @('azure/azure-monitor/alerts/alerts-types', 'Types of Azure Monitor alerts')
            IdProtection    = @('entra/id-protection/overview-identity-protection', 'What is Microsoft Entra ID Protection?')
            InvestigateRisk = @('entra/id-protection/howto-identity-protection-investigate-risk', 'Investigate risk with Microsoft Entra ID Protection')
            RiskPolicies    = @('entra/id-protection/howto-identity-protection-configure-risk-policies', 'Risk policies - Microsoft Entra ID Protection')
            CaSignInRisk    = @('entra/identity/conditional-access/policy-risk-based-sign-in', 'Sign-in risk-based multifactor authentication')
            CaUserRisk      = @('entra/identity/conditional-access/policy-risk-based-user', 'Require remediation for risky users')
            CaReportOnly    = @('entra/identity/conditional-access/concept-conditional-access-report-only', 'Conditional Access Policy Insights: Monitoring and Evaluation')
            BreakGlass      = @('entra/identity/role-based-access-control/security-emergency-access', 'Manage emergency access admin accounts')
            UserConsent     = @('entra/identity/enterprise-apps/configure-user-consent', 'Configure How Users Consent to Applications')
            ConsentPlaybook = @('security/operations/incident-response-playbook-app-consent', 'App consent grant investigation')
            RiskyOAuth      = @('defender-cloud-apps/investigate-risky-oauth', 'Investigate and remediate risky OAuth apps - Microsoft Defender for Cloud Apps')
            BlockLegacyAuth = @('entra/identity/conditional-access/policy-block-legacy-authentication', 'Block legacy authentication with Conditional Access')
            AppPermissions  = @('entra/identity/enterprise-apps/manage-application-permissions', 'Review permissions granted to enterprise applications')
            AppRegSecurity  = @('entra/identity-platform/security-best-practices-for-app-registration', 'Security best practices for application properties')
            AppOwners       = @('entra/identity/enterprise-apps/assign-app-owners', 'Assign enterprise application owners')
            DisableApp      = @('entra/identity/enterprise-apps/disable-user-sign-in-portal', 'Disable user sign-in for application')
            DeleteApp       = @('entra/identity/enterprise-apps/delete-application-portal', 'Delete an enterprise application')
            UnusedCreds     = @('entra/identity/monitoring-health/recommendation-remove-unused-credential-from-apps', 'Recommendation to remove unused credentials from apps')
            RegisterApp     = @('entra/identity-platform/quickstart-register-app', 'How to Register an App in Microsoft Entra ID')
            DesktopApp      = @('entra/identity-platform/scenario-desktop-app-registration', 'Configure desktop apps that call web APIs')
            AuditSearch     = @('purview/audit-log-search', 'Search the audit log')
            AppManagement   = @('entra/identity/enterprise-apps/what-is-application-management', 'What is application management?')
        }
        $script:LearnCatalog = @{}
        foreach ($key in $entries.Keys) {
            $script:LearnCatalog[$key] = [pscustomobject]@{ Key = $key; Url = "$base$($entries[$key][0])"; Title = $entries[$key][1] }
        }

        $rule = { param($Task, $Pattern, $Keys) [pscustomobject]@{ Task = $Task; Pattern = $Pattern; Keys = @($Keys) } }
        $script:LearnRules = @(
            & $rule '*' 'session not available|needs a PnP|PnP sign-in|Entra app for PnP' 'RegisterApp', 'DesktopApp'

            & $rule 'AcsInventory' 'expired' 'AcsRetirement', 'AddInPerms'
            & $rule 'AcsInventory' 'manually|AppPrincipals' 'AcsRetirement', 'SetSpoTenant'
            & $rule 'AcsInventory' $null 'AcsRetirement', 'EntraAppOnly', 'AcsAppOnly'

            & $rule 'LegacyAddInSettings' 'Delegated grant' 'AppPermissions', 'RiskyOAuth'
            & $rule 'LegacyAddInSettings' 'DisableCustomAppAuthentication|ACS app-only|Tenant settings|Get-PnPTenant' 'SetSpoTenant', 'AcsRetirement'
            & $rule 'LegacyAddInSettings' $null 'AcsRetirement', 'SetSpoTenant'

            & $rule 'AppOnlyPermissions' 'client secret' 'SitesSelected', 'AppRegSecurity', 'GraphPerms'
            & $rule 'AppOnlyPermissions' $null 'SitesSelected', 'GraphPerms', 'EntraAppOnly'

            & $rule 'CustomScript' $null 'CustomScript', 'SetSpoTenant'

            & $rule 'SignInMonitoring' 'Alert' 'SentinelRules', 'AzureAlerts', 'LogAnalytics'
            & $rule 'SignInMonitoring' 'Risky sign-ins' 'InvestigateRisk', 'SignInLogs'
            & $rule 'SignInMonitoring' 'ACS|audit' 'AcsRetirement', 'AuditSearch'
            & $rule 'SignInMonitoring' $null 'SignInLogs', 'SpSignInActivity', 'LogAnalytics'

            & $rule 'IdentityProtection' 'Sign-in risk' 'CaSignInRisk', 'RiskPolicies', 'CaReportOnly'
            & $rule 'IdentityProtection' 'User risk' 'CaUserRisk', 'RiskPolicies', 'BreakGlass'
            & $rule 'IdentityProtection' 'Risky user|Risk detection|Identity Protection|Entra ID P2|P2 service plan' 'IdProtection', 'InvestigateRisk', 'RiskPolicies'
            & $rule 'IdentityProtection' 'Defender for Cloud Apps' 'RiskyOAuth', 'IdProtection'
            & $rule 'IdentityProtection' 'consent|OAuth|Third-party app' 'UserConsent', 'ConsentPlaybook', 'AppPermissions'
            & $rule 'IdentityProtection' $null 'IdProtection', 'RiskPolicies', 'ConsentPlaybook'

            & $rule 'LegacyAuthBlock' 'LegacyAuthProtocolsEnabled' 'SetSpoTenant', 'BlockLegacyAuth'
            & $rule 'LegacyAuthBlock' 'report-only' 'BlockLegacyAuth', 'CaReportOnly', 'BreakGlass'
            & $rule 'LegacyAuthBlock' $null 'BlockLegacyAuth', 'CaReportOnly', 'BreakGlass'

            & $rule 'EnterpriseAppReview' 'owner' 'AppOwners', 'AppManagement'
            & $rule 'EnterpriseAppReview' 'credential|secret' 'UnusedCreds', 'AppRegSecurity'
            & $rule 'EnterpriseAppReview' 'Tenant-wide application permissions' 'SitesSelected', 'AppPermissions'
            & $rule 'EnterpriseAppReview' 'No sign-in since' 'DisableApp', 'DeleteApp'
            & $rule 'EnterpriseAppReview' 'created' 'AppPermissions', 'ConsentPlaybook'
            & $rule 'EnterpriseAppReview' $null 'AppPermissions', 'AppManagement'

            & $rule 'Prerequisites' $null 'RegisterApp', 'DesktopApp'
        )
    }

    if ($PSCmdlet.ParameterSetName -eq 'Title') {
        $match = $script:LearnCatalog.Values | Where-Object { $_.Url -eq $Url } | Select-Object -First 1
        if ($match) { return $match.Title }
        return $null
    }

    $keys = [System.Collections.Generic.List[string]]::new()
    $taskRules = @($script:LearnRules | Where-Object { $_.Task -eq $Task -or $_.Task -eq '*' })
    foreach ($item in ($taskRules | Where-Object { $_.Pattern })) {
        if ($Text -match $item.Pattern) { foreach ($k in $item.Keys) { if ($k -notin $keys) { $keys.Add($k) } } }
    }
    if ($keys.Count -eq 0) {
        $fallback = $taskRules | Where-Object { -not $_.Pattern } | Select-Object -First 1
        if ($fallback) { foreach ($k in $fallback.Keys) { $keys.Add($k) } }
    }

    return @($keys | Select-Object -First $Max | ForEach-Object { $script:LearnCatalog[$_] })
}
