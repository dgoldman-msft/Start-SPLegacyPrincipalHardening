function Get-LegacyPrincipalSignIn {
    <#
    .SYNOPSIS
        Task 5 - Pulls Entra sign-ins for the legacy SharePoint client-extensibility principals, flags anomalies, and emits alert queries.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $task = 'SignInMonitoring'
    Write-ToLogFile "`n== [5/8] Sign-in monitoring for the legacy principals ==" -LogFile $Context.LogFile -ForegroundColor Cyan

    $principals = @(Get-LegacyServicePrincipal -Context $Context)
    if ($principals.Count -eq 0) {
        New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Info -Resource 'Legacy principals' -Finding 'No legacy client-extensibility service principals found to monitor.'
        return
    }

    $appIds = @($principals.appId | Sort-Object -Unique)
    $now = (Get-Date).ToUniversalTime()
    $signIns = [System.Collections.Generic.List[object]]::new()
    $failedWindows = 0
    $totalWindows = 0
    foreach ($appId in $appIds) {
        Write-ToLogFile "Querying sign-ins for appId $appId over the last $($Context.LookbackDays) day(s), one day at a time..." -LogFile $Context.LogFile -ForegroundColor Gray
        $appCount = 0
        # Day-sized windows keep each request small: one large window can exceed the 300 s Graph client timeout on busy tenants
        for ($dayOffset = $Context.LookbackDays; $dayOffset -ge 1 -and $appCount -lt $Context.MaxSignIns; $dayOffset--) {
            $from = $now.AddDays(-$dayOffset).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
            $to = $now.AddDays(-($dayOffset - 1)).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'")
            $upper = if ($dayOffset -eq 1) { '' } else { " and createdDateTime lt $to" }
            $uri = "https://graph.microsoft.com/beta/auditLogs/signIns?`$filter=createdDateTime ge $from$upper and appId eq '$appId'&`$top=500"
            $totalWindows++
            $windowRows = $null
            $lastError = $null
            foreach ($attempt in 1, 2) {
                try {
                    $windowRows = @(Invoke-GraphPaged -Uri $uri -MaxItems ($Context.MaxSignIns - $appCount) -LogFile $Context.LogFile)
                    break
                }
                catch {
                    $lastError = $_.Exception.Message
                    Write-ToLogFile "  sign-in query for $from failed (attempt $attempt): $lastError" -LogFile $Context.LogFile -ForegroundColor Yellow
                }
            }
            if ($null -eq $windowRows) {
                $failedWindows++
                New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Failed -Resource "$appId ($from)" -Finding 'Sign-in query failed for this day (needs AuditLog.Read.All and Entra ID P1/P2; large tenants can time out).' -Detail $lastError
                continue
            }
            foreach ($entry in $windowRows) { $signIns.Add($entry) }
            $appCount += $windowRows.Count
        }
    }

    $rows = foreach ($entry in $signIns) {
        [pscustomobject]@{
            Time        = ([datetime]$entry.createdDateTime).ToUniversalTime()
            User        = $entry.userPrincipalName
            App         = $entry.appDisplayName
            AppId       = $entry.appId
            Ip          = $entry.ipAddress
            Country     = $entry.location.countryOrRegion
            City        = $entry.location.city
            ClientApp   = $entry.clientAppType
            ErrorCode   = $entry.status.errorCode
            Risk        = $entry.riskLevelAggregated
            RiskState   = $entry.riskState
            Interactive = $entry.isInteractive
            EventTypes  = (@($entry.signInEventTypes) -join ';')
            Resource    = $entry.resourceDisplayName
            CaStatus    = $entry.conditionalAccessStatus
        }
    }
    $rows = @($rows)
    $Context.Datasets['LegacyPrincipalSignIns'] = $rows

    Write-ToLogFile "Retrieved $($rows.Count) sign-in(s) for $($appIds.Count) app(s) over $($Context.LookbackDays) day(s)$(if ($failedWindows -gt 0) { " ($failedWindows of $totalWindows daily queries failed - partial results)" })." -LogFile $Context.LogFile -ForegroundColor Gray
    if ($rows.Count -eq 0 -and $failedWindows -gt 0) {
        New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Skipped -Resource 'Legacy principals' -Finding "Sign-ins could not be assessed: $failedWindows of $totalWindows daily queries failed and no sign-ins were returned by the others." -Recommendation 'Re-run the review, or check the sign-in logs for these apps in Entra admin center > Monitoring > Sign-in logs.'
    }
    elseif ($rows.Count -eq 0) {
        New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Info -Resource 'Legacy principals' -Finding "No sign-ins in the last $($Context.LookbackDays) day(s)." -Detail 'ACS app-only tokens are issued by ACS and never appear in Entra sign-in logs; review SharePoint audit (FileDownloaded) for those.'
    }
    else {
        $recentCutoff = (Get-Date).ToUniversalTime().AddHours(-$Context.RecentHours)
        $recent = @($rows | Where-Object { $_.Time -ge $recentCutoff })
        $baseline = @($rows | Where-Object { $_.Time -lt $recentCutoff })

        # Volume spikes in the recent window
        foreach ($group in ($recent | Group-Object User | Where-Object { $_.Count -gt $Context.SignInVolumeThreshold })) {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource $group.Name -Finding "$($group.Count) sign-ins in $($Context.RecentHours)h (threshold $($Context.SignInVolumeThreshold))." -Recommendation 'Investigate for token replay / scripted access.'
        }
        foreach ($group in ($recent | Where-Object Ip | Group-Object Ip | Where-Object { $_.Count -gt $Context.SignInVolumeThreshold })) {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource $group.Name -Finding "IP produced $($group.Count) sign-ins in $($Context.RecentHours)h (users: $((@($group.Group.User | Sort-Object -Unique) | Select-Object -First 5) -join ', '))."
        }

        # Location anomalies: countries only seen in the recent window, and one user in several countries
        if ($baseline.Count -gt 0) {
            $knownCountries = @($baseline.Country | Where-Object { $_ } | Sort-Object -Unique)
            foreach ($group in ($recent | Where-Object { $_.Country -and $_.Country -notin $knownCountries } | Group-Object Country)) {
                $users = (@($group.Group.User | Sort-Object -Unique) | Select-Object -First 5) -join ', '
                New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource $group.Name -Finding "New country in the last $($Context.RecentHours)h - not seen in the prior baseline ($($group.Count) sign-ins; users: $users)." -Recommendation 'Confirm with the user; revoke sessions if unexpected.'
            }
        }
        else {
            New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Info -Resource 'Baseline' -Finding 'No sign-ins older than the recent window; new-country detection skipped. Increase -LookbackDays.'
        }
        foreach ($group in ($recent | Where-Object { $_.Country -and $_.ErrorCode -eq 0 } | Group-Object User)) {
            $countries = @($group.Group.Country | Sort-Object -Unique)
            if ($countries.Count -ge 2) {
                New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource $group.Name -Finding "Successful sign-ins from $($countries.Count) countries in $($Context.RecentHours)h: $($countries -join ', ')." -Recommendation 'Possible token theft / impossible travel.'
            }
        }

        $risky = @($rows | Where-Object { $_.Risk -in 'high', 'medium' -or $_.RiskState -in 'atRisk', 'confirmedCompromised' })
        if ($risky.Count -gt 0) {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource 'Risky sign-ins' -Finding "$($risky.Count) sign-in(s) carried medium/high risk (users: $((@($risky.User | Sort-Object -Unique) | Select-Object -First 5) -join ', '))."
        }
        $legacyClient = @($rows | Where-Object { $_.ClientApp -and $_.ClientApp -notin 'Browser', 'Mobile Apps and Desktop clients' })
        if ($legacyClient.Count -gt 0) {
            New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status NonCompliant -Resource 'Legacy client protocols' -Finding "$($legacyClient.Count) sign-in(s) used non-modern client types ($((@($legacyClient.ClientApp | Sort-Object -Unique)) -join ', '))."
        }

        $summary = ($rows | Group-Object Country | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name): $($_.Count)" }) -join ', '
        New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Info -Resource 'Sign-in summary' -Finding "$($rows.Count) sign-in(s); top countries - $summary"
    }

    # Ready-to-deploy alert queries (volume / location anomalies and mass download)
    $appList = ($appIds | ForEach-Object { '"' + $_ + '"' }) -join ', '
    $kql = @"
// Legacy SharePoint client-extensibility principal: volume or multi-country anomalies (Microsoft Sentinel / Log Analytics)
let legacyApps = dynamic([$appList]);
union SigninLogs, AADNonInteractiveUserSignInLogs, AADServicePrincipalSignInLogs
| where TimeGenerated > ago(1h)
| where AppId in (legacyApps)
| extend Actor = coalesce(UserPrincipalName, ServicePrincipalName), Country = tostring(LocationDetails.countryOrRegion)
| summarize Signins = count(), Countries = make_set(Country), IPs = dcount(IPAddress) by Actor, bin(TimeGenerated, 15m)
| where Signins > $($Context.SignInVolumeThreshold) or array_length(Countries) > 1

// Mass download hunting (Defender XDR advanced hunting) - tune the threshold to your tenant
CloudAppEvents
| where Timestamp > ago(1h) and ActionType in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize Downloads = count(), DistinctFiles = dcount(tostring(RawEventData.SourceFileName)) by AccountDisplayName, IPAddress, bin(Timestamp, 15m)
| where Downloads > 200
"@
    $kqlPath = Join-Path $Context.OutputPath "LegacyPrincipalAlerts_$($Context.RunId).kql"
    Set-Content -LiteralPath $kqlPath -Value $kql -Encoding utf8
    New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Manual -Resource 'Alerting' -Finding "Alert queries written to $kqlPath." -Recommendation 'Deploy as a Sentinel analytics rule / Azure Monitor alert - alert creation needs a Log Analytics workspace and cannot be automated from here.'
}
