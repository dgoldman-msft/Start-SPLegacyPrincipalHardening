function Test-IdentityProtectionPosture {
    <#
    .SYNOPSIS
        Task 6 - Read-only check of Entra ID Protection / Defender for Cloud Apps coverage, risky users, OAuth consent grants, user-consent settings and risk-based Conditional Access.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $task = 'IdentityProtection'
    Write-ToLogFile "`n== [6/8] Identity Protection / Defender for Cloud Apps / consent-grant phishing ==" -LogFile $Context.LogFile -ForegroundColor Cyan
    $logFile = $Context.LogFile
    $since = (Get-Date).ToUniversalTime().AddDays(-$Context.ConsentLookbackDays).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")

    # Licensing
    $hasIdProtection = $false
    try {
        $skus = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/subscribedSkus' -LogFile $logFile)
        $plans = @($skus | ForEach-Object { $_.servicePlans } | Where-Object { $_.provisioningStatus -eq 'Success' } | ForEach-Object { $_.servicePlanName })
        $hasIdProtection = 'AAD_PREMIUM_P2' -in $plans
        $hasMdca = @($plans | Where-Object { $_ -like 'ADALLOM*' }).Count -gt 0
        if ($hasIdProtection) {
            New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Compliant -Resource 'Entra ID Protection' -Finding 'Licensed (Entra ID P2 service plan present).'
        }
        else {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource 'Entra ID Protection' -Finding 'No Entra ID P2 service plan found - risk-based policies are unavailable.' -Recommendation 'License Entra ID P2 (or Microsoft 365 E5) for at least the users with SharePoint access.'
        }
        if ($hasMdca) {
            New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Compliant -Resource 'Defender for Cloud Apps' -Finding 'Licensed (ADALLOM service plan present).'
        }
        else {
            New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status NonCompliant -Resource 'Defender for Cloud Apps' -Finding 'No Defender for Cloud Apps service plan found.' -Recommendation 'License it to get anomaly detection, OAuth app governance and mass-download alerts.'
        }
    }
    catch {
        New-ReviewFinding -Context $Context -Task $task -Severity Low -Status Failed -Resource 'Licensing' -Finding 'Could not read subscribed SKUs.' -Detail $_.Exception.Message
    }

    New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Manual -Resource 'Defender for Cloud Apps' -Finding 'Enabling the Microsoft 365 app connector, anomaly-detection and mass-download policies is portal-only.' -Recommendation 'Defender portal > Cloud Apps > Connected apps (Microsoft 365) and Policies > create "Mass download by a single user" and "Suspicious OAuth app" policies; enable App governance.'

    # Defender for Cloud Apps alerts
    try {
        $alerts = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/security/alerts_v2?`$filter=serviceSource eq 'microsoftDefenderForCloudApps' and createdDateTime ge $since&`$top=100" -MaxItems 200 -LogFile $logFile)
        $Context.Datasets['DefenderCloudAppsAlerts'] = @($alerts | ForEach-Object { [pscustomobject]@{ Created = $_.createdDateTime; Title = $_.title; Severity = $_.severity; Status = $_.status; Category = $_.category } })
        $openAlerts = @($alerts | Where-Object { $_.status -ne 'resolved' })
        if ($openAlerts.Count -gt 0) {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource 'Defender for Cloud Apps alerts' -Finding "$($openAlerts.Count) unresolved alert(s) in the last $($Context.ConsentLookbackDays) days: $((@($openAlerts.title | Sort-Object -Unique) | Select-Object -First 5) -join '; ')"
        }
    }
    catch {
        Write-ToLogFile "Defender for Cloud Apps alerts not readable: $($_.Exception.Message)" -LogFile $logFile -LogOnly
    }

    # Risky users and detections
    if ($hasIdProtection) {
        try {
            $riskyUsers = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'&`$top=500" -LogFile $logFile)
            $Context.Datasets['RiskyUsers'] = @($riskyUsers | ForEach-Object { [pscustomobject]@{ User = $_.userPrincipalName; RiskLevel = $_.riskLevel; RiskState = $_.riskState; Updated = $_.riskLastUpdatedDateTime } })
            foreach ($riskyUser in ($riskyUsers | Where-Object { $_.riskLevel -in 'high', 'medium' -or $_.riskState -eq 'confirmedCompromised' })) {
                New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource $riskyUser.userPrincipalName -Finding "Risky user: $($riskyUser.riskLevel) / $($riskyUser.riskState)." -Recommendation 'Revoke sessions, reset credentials and review their SharePoint downloads.'
            }
            if ($riskyUsers.Count -eq 0) {
                New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Compliant -Resource 'Risky users' -Finding 'No users currently at risk.'
            }

            $detections = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskDetections?`$filter=detectedDateTime ge $since&`$top=500" -MaxItems 2000 -LogFile $logFile)
            foreach ($group in ($detections | Group-Object riskEventType)) {
                New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Info -Resource 'Risk detections' -Finding "$($group.Count) x $($group.Name) in the last $($Context.ConsentLookbackDays) days."
            }
        }
        catch {
            New-ReviewFinding -Context $Context -Task $task -Severity Low -Status Failed -Resource 'Identity Protection' -Finding 'Could not read risky users/detections.' -Detail $_.Exception.Message
        }
    }

    # Risk-based Conditional Access
    try {
        $policies = @(Get-ConditionalAccessPolicy -Context $Context)
        $enabledPolicies = @($policies | Where-Object { $_.state -eq 'enabled' })
        $signInRiskPolicy = @($enabledPolicies | Where-Object { @($_.conditions.signInRiskLevels | Where-Object { $_ }).Count -gt 0 })
        $userRiskPolicy = @($enabledPolicies | Where-Object { @($_.conditions.userRiskLevels | Where-Object { $_ }).Count -gt 0 })

        if ($signInRiskPolicy.Count -gt 0) {
            New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Compliant -Resource 'Sign-in risk policy' -Finding "Enforced: $((@($signInRiskPolicy.displayName)) -join '; ')"
        }
        else {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource 'Sign-in risk policy' -Finding 'No enabled Conditional Access policy responds to sign-in risk.' -Recommendation 'Create a Conditional Access policy that requires MFA for medium and high sign-in risk. Start in report-only mode and exclude your break-glass accounts.'
        }

        if ($userRiskPolicy.Count -gt 0) {
            New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Compliant -Resource 'User risk policy' -Finding "Enforced: $((@($userRiskPolicy.displayName)) -join '; ')"
        }
        else {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource 'User risk policy' -Finding 'No enabled Conditional Access policy responds to user risk.' -Recommendation 'Create a Conditional Access policy that requires a secure password change for high user risk. Start in report-only mode and exclude your break-glass accounts.'
        }
    }
    catch {
        New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Failed -Resource 'Conditional Access' -Finding 'Could not read Conditional Access policies.' -Detail $_.Exception.Message
    }

    # User consent settings (consent-grant phishing)
    try {
        $authorizationPolicy = Invoke-GraphWithRetry -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authorizationPolicy' -LogFile $logFile
        $assigned = @($authorizationPolicy.defaultUserRolePermissions.permissionGrantPoliciesAssigned)
        $legacyConsent = @($assigned | Where-Object { $_ -like '*user-default-legacy' })
        if ($legacyConsent.Count -gt 0) {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource 'User consent' -Finding 'Users can consent to any app (legacy user-consent policy).' -Recommendation 'Restrict user consent to verified publishers and low-risk permissions, or disable user consent (Entra admin center > Enterprise apps > Consent and permissions).'
        }
        else {
            New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Compliant -Resource 'User consent' -Finding "User consent is restricted (assigned: $(($assigned -join ', ')))."
        }

        $adminConsent = Invoke-GraphWithRetry -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/adminConsentRequestPolicy' -LogFile $logFile
        if ($adminConsent.isEnabled) {
            New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Compliant -Resource 'Admin consent workflow' -Finding 'Enabled.'
        }
        else {
            New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Manual -Resource 'Admin consent workflow' -Finding 'Disabled - users cannot request admin review of blocked apps.' -Recommendation 'Enable it in Entra admin center > Enterprise apps > Consent and permissions > Admin consent settings (reviewers must be chosen by you).'
        }
    }
    catch {
        New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Failed -Resource 'Consent settings' -Finding 'Could not read consent policies.' -Detail $_.Exception.Message
    }

    # Existing OAuth grants and recent consent events
    try {
        $null = Get-AllServicePrincipal -Context $Context
        $servicePrincipalsById = $Context.Cache['ServicePrincipalsById']
        $sensitivePattern = '(^|\s)(Files\.|Sites\.|AllSites\.|Mail\.|MailboxSettings\.|Directory\.|User\.Read\.All|Notes\.Read\.All|full_access_as_app)'
        $grants = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/oauth2PermissionGrants?$top=999' -LogFile $logFile)
        $grantRows = [System.Collections.Generic.List[object]]::new()
        foreach ($group in ($grants | Where-Object { $_.scope -match $sensitivePattern } | Group-Object clientId)) {
            $client = $servicePrincipalsById[$group.Name]
            if ($client.appOwnerOrganizationId -in $script:MicrosoftTenantIds) { continue }
            $allUsers = @($group.Group | Where-Object consentType -eq 'AllPrincipals').Count -gt 0
            $scopes = (@($group.Group.scope | ForEach-Object { $_ -split '\s+' } | Where-Object { $_ } | Sort-Object -Unique)) -join ' '
            $grantRows.Add([pscustomobject]@{ App = $client.displayName; AppId = $client.appId; ObjectId = $group.Name; AdminConsentAllUsers = $allUsers; UserConsents = @($group.Group | Where-Object consentType -eq 'Principal').Count; Scopes = $scopes; Created = $client.createdDateTime })
            $severity = if ($allUsers) { 'High' } else { 'Medium' }
            New-ReviewFinding -Context $Context -Task $task -Severity $severity -Status NonCompliant -Resource "$($client.displayName) ($($client.appId))" -Finding "Third-party app holds delegated data scopes ($(if ($allUsers) { 'tenant-wide admin consent' } else { "$(@($group.Group).Count) user consent(s)" })): $scopes" -Recommendation 'Verify publisher and need; remove the grant if unexpected.' -LogOnly
        }
        $Context.Datasets['OAuthGrantsThirdParty'] = $grantRows.ToArray()
        New-ReviewFinding -Context $Context -Task $task -Severity $(if ($grantRows.Count -gt 0) { 'Medium' } else { 'Info' }) -Status $(if ($grantRows.Count -gt 0) { 'NonCompliant' } else { 'Compliant' }) -Resource 'OAuth grants' -Finding "$($grantRows.Count) third-party app(s) hold delegated Files/Sites/Mail/Directory scopes (see OAuthGrantsThirdParty CSV)."

        $consentEvents = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDisplayName eq 'Consent to application' and activityDateTime ge $since&`$top=200" -MaxItems 500 -LogFile $logFile)
        $Context.Datasets['RecentConsentEvents'] = @($consentEvents | ForEach-Object { [pscustomobject]@{ Time = $_.activityDateTime; By = $_.initiatedBy.user.userPrincipalName; App = @($_.targetResources)[0].displayName; Result = $_.result } })
        foreach ($consentEvent in ($consentEvents | Select-Object -First 25)) {
            New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Info -Resource @($consentEvent.targetResources)[0].displayName -Finding "Consent granted $($consentEvent.activityDateTime) by $($consentEvent.initiatedBy.user.userPrincipalName) ($($consentEvent.result))." -LogOnly
        }
        New-ReviewFinding -Context $Context -Task $task -Severity $(if ($consentEvents.Count -gt 0) { 'Medium' } else { 'Info' }) -Status Info -Resource 'Consent events' -Finding "$($consentEvents.Count) 'Consent to application' event(s) in the last $($Context.ConsentLookbackDays) days - review for the phished user (see RecentConsentEvents CSV)."
    }
    catch {
        New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Failed -Resource 'OAuth grants' -Finding 'Could not read OAuth grants/consent events.' -Detail $_.Exception.Message
    }
}
