function Get-EnterpriseAppReview {
    <#
    .SYNOPSIS
        Task 8 - Reviews every Enterprise application: ownership, credentials, permissions, recent creation and sign-in staleness.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $task = 'EnterpriseAppReview'
    Write-ToLogFile "`n== [8/8] Enterprise application review ==" -LogFile $Context.LogFile -ForegroundColor Cyan

    $servicePrincipals = @(Get-AllServicePrincipal -Context $Context)
    $appRegistrations = Get-AllAppRegistration -Context $Context
    $assignments = @(Get-BroadAppRoleAssignment -Context $Context)
    $broadByPrincipal = $assignments | Where-Object IsBroad | Group-Object PrincipalId -AsHashTable -AsString
    $legacyIds = @((Get-LegacyServicePrincipal -Context $Context).id)

    # Last sign-in activity (needs Entra ID P1/P2); optional
    $lastSignIn = @{}
    try {
        $activities = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/beta/reports/servicePrincipalSignInActivities?$top=999' -MaxItems 50000 -LogFile $Context.LogFile)
        foreach ($activity in $activities) { $lastSignIn[$activity.appId] = $activity.lastSignInActivity.lastSignInDateTime }
    }
    catch {
        Write-ToLogFile "Service principal sign-in activity not available: $($_.Exception.Message)" -LogFile $Context.LogFile -ForegroundColor Yellow
    }

    $now = Get-Date
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($sp in $servicePrincipals) {
        if ($sp.servicePrincipalType -ne 'Application') { continue }

        $microsoftOwned = $sp.appOwnerOrganizationId -in $script:MicrosoftTenantIds
        $credentialSource = if ($appRegistrations.ContainsKey("$($sp.appId)")) { $appRegistrations["$($sp.appId)"] } else { $sp }
        $secrets = @($credentialSource.passwordCredentials | Where-Object { $_ })
        $certificates = @($credentialSource.keyCredentials | Where-Object { $_ })
        $allCredentials = @($secrets + $certificates)
        $expired = @($allCredentials | Where-Object { $_.endDateTime -and ([datetime]$_.endDateTime) -lt $now })
        $expiring = @($allCredentials | Where-Object { $_.endDateTime -and ([datetime]$_.endDateTime) -ge $now -and ([datetime]$_.endDateTime) -lt $now.AddDays(30) })
        $longLived = @($secrets | Where-Object { $_.startDateTime -and $_.endDateTime -and (([datetime]$_.endDateTime) - ([datetime]$_.startDateTime)).TotalDays -gt 730 })
        $broad = @($broadByPrincipal[$sp.id] | Where-Object { $_ })
        $lastActivity = $lastSignIn[$sp.appId]
        $created = if ($sp.createdDateTime) { [datetime]$sp.createdDateTime } else { $null }

        $row = [pscustomobject]@{
            Name              = $sp.displayName
            AppId             = $sp.appId
            ObjectId          = $sp.id
            Enabled           = $sp.accountEnabled
            MicrosoftOwned    = $microsoftOwned
            Created           = $created
            Owners            = @($sp.owners | Where-Object { $_ }).Count
            Secrets           = $secrets.Count
            Certificates      = $certificates.Count
            ExpiredCredential = $expired.Count
            ExpiringIn30Days  = $expiring.Count
            LongLivedSecrets  = $longLived.Count
            BroadAppRoles     = (@($broad.AppRole | Where-Object { $_ } | Sort-Object -Unique)) -join ';'
            LastSignIn        = $lastActivity
            IsLegacyPrincipal = ($sp.id -in $legacyIds)
        }
        $rows.Add($row)
        if ($microsoftOwned) { continue }

        $resource = "$($sp.displayName) ($($sp.appId))"
        if ($created -and $created -ge $now.AddDays(-$Context.NewAppDays)) {
            New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status NonCompliant -Resource $resource -Finding "Enterprise app created $($created.ToString('yyyy-MM-dd')) (within $($Context.NewAppDays) days)." -Recommendation 'Confirm it was an expected registration/consent - recent unknown apps are a persistence indicator.' -LogOnly
        }
        if ($row.Owners -eq 0) {
            New-ReviewFinding -Context $Context -Task $task -Severity Low -Status NonCompliant -Resource $resource -Finding 'No owner assigned.' -LogOnly
        }
        if ($expired.Count -gt 0) {
            New-ReviewFinding -Context $Context -Task $task -Severity Low -Status NonCompliant -Resource $resource -Finding "$($expired.Count) expired credential(s) still present." -Recommendation 'Remove expired secrets/certificates.' -LogOnly
        }
        if ($longLived.Count -gt 0) {
            New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status NonCompliant -Resource $resource -Finding "$($longLived.Count) client secret(s) valid for more than 2 years." -Recommendation 'Rotate and prefer certificates.' -LogOnly
        }
        if ($broad.Count -gt 0) {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource $resource -Finding "Tenant-wide application permissions: $($row.BroadAppRoles)." -Recommendation 'See task 3 (Sites.Selected).' -LogOnly
        }
        if ($lastActivity -and ([datetime]$lastActivity) -lt $now.AddDays(-$Context.StaleAppDays) -and $sp.accountEnabled) {
            New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status NonCompliant -Resource $resource -Finding "No sign-in since $(([datetime]$lastActivity).ToString('yyyy-MM-dd')) (>$($Context.StaleAppDays) days)." -Recommendation 'Disable or delete if unused.' -LogOnly
        }
    }
    $Context.Datasets['EnterpriseApps'] = $rows.ToArray()

    $thirdParty = @($rows | Where-Object { -not $_.MicrosoftOwned })
    $issueCount = @($Context.Findings | Where-Object { $_.Task -eq $task -and $_.Status -eq 'NonCompliant' }).Count
    New-ReviewFinding -Context $Context -Task $task -Severity $(if ($issueCount -gt 0) { 'Medium' } else { 'Info' }) -Status $(if ($issueCount -gt 0) { 'NonCompliant' } else { 'Compliant' }) -Resource 'Enterprise applications' -Finding "$($rows.Count) enterprise apps reviewed ($($thirdParty.Count) non-Microsoft); $issueCount review finding(s). Full inventory in the EnterpriseApps CSV; filter Findings CSV on Task = $task."
    foreach ($legacy in ($rows | Where-Object IsLegacyPrincipal)) {
        New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Info -Resource "$($legacy.Name) ($($legacy.AppId))" -Finding "Legacy principal - last sign-in: $(if ($legacy.LastSignIn) { $legacy.LastSignIn } else { 'unknown' }); credentials: $($legacy.Secrets) secret(s), $($legacy.Certificates) cert(s)."
    }
}
