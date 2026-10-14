function New-RecommendationReport {
    <#
    .SYNOPSIS
        Builds the customer-facing HTML recommendations report from review findings.
    .DESCRIPTION
        The review is read-only, so every item is a recommendation for the customer to carry out themselves. Each
        recommendation links to the Microsoft Learn articles it is based on. Writes a single self-contained HTML file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [object[]]$Finding,

        [Parameter(Mandatory)]
        [string]$Path,

        [string]$TenantId,
        [string]$RunId
    )

    $taskInfo = [ordered]@{
        AcsInventory        = @{ Number = 1; Title = 'Legacy add-in / ACS principal inventory'
            Steps = @(
                'Review each active principal with its owner and confirm whether it is still needed.'
                'Migrate anything still needed to Microsoft Entra ID app-only access (see the Learn articles).'
                'Remove the principal on <code>AppPrincipals.aspx</code> for the owning site (there is no supported removal cmdlet).') }
        LegacyAddInSettings = @{ Number = 2; Title = 'Disable legacy ACS app-only authentication'
            Steps = @(
                'Confirm no remaining add-ins depend on ACS (it was retired on 2 April 2026).'
                'Run <code>Set-SPOTenant -DisableCustomAppAuthentication $true</code>. The setting is reversible.') }
        AppOnlyPermissions  = @{ Number = 3; Title = 'Tenant-wide application permissions (Sites.Selected migration)'
            Steps = @(
                'For each app, agree with its owner which sites it really needs.'
                'Grant the app <code>Sites.Selected</code> and a per-site permission on only those sites; use certificate credentials instead of client secrets.'
                'Test the app, then remove its tenant-wide role in Entra admin center &gt; Enterprise applications &gt; the app &gt; Permissions. Removing it before the replacement works will stop the app.') }
        CustomScript        = @{ Number = 4; Title = 'Custom script on site collections'
            Steps = @(
                'Check whether a site genuinely needs custom script.'
                'Prevent it with <code>Set-SPOSite -Identity &lt;url&gt; -DenyAddAndCustomizePages $true</code>.') }
        SignInMonitoring    = @{ Number = 5; Title = 'Sign-in monitoring for the legacy principals'
            Steps = @(
                'Deploy the generated <code>LegacyPrincipalAlerts_*.kql</code> queries as a Microsoft Sentinel analytics rule or Azure Monitor alert.'
                'Investigate any new-country, high-volume or risky sign-ins listed below.') }
        IdentityProtection  = @{ Number = 6; Title = 'Identity Protection, Defender for Cloud Apps and consent-grant phishing'
            Steps = @(
                'Triage risky users and unresolved Defender for Cloud Apps alerts.'
                'Create the missing risk-based Conditional Access policies (report-only first, excluding break-glass accounts).'
                'Restrict user consent and review third-party OAuth grants in Entra admin center &gt; Enterprise applications &gt; Consent and permissions.') }
        LegacyAuthBlock     = @{ Number = 7; Title = 'Block legacy authentication'
            Steps = @(
                'Create a Conditional Access policy that blocks legacy authentication client types (report-only first, excluding break-glass accounts), then switch it On.'
                'Run <code>Set-SPOTenant -LegacyAuthProtocolsEnabled $false</code> after confirming no required clients depend on legacy protocols.') }
        EnterpriseAppReview = @{ Number = 8; Title = 'Enterprise application review'
            Steps = @(
                'In Entra admin center &gt; Enterprise applications, assign owners, remove expired credentials, and rotate long-lived secrets.'
                'Disable or delete applications that are no longer used, and confirm any recently created app was expected.') }
    }
    $priority = @{ Critical = 'P1'; High = 'P1'; Medium = 'P2'; Low = 'P3' }
    $severityOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4 }
    $h = { param($text) [System.Net.WebUtility]::HtmlEncode("$text") }

    $linkList = {
        param($finding)
        $urls = @("$($finding.Reference)" -split '\s*;\s*' | Where-Object { $_ })
        $parts = foreach ($url in $urls) {
            $title = Get-LearnReference -Url $url
            if (-not $title) { $title = 'Microsoft Learn' }
            "<a href=""$(& $h $url)"">$(& $h $title)</a>"
        }
        return @($parts)
    }
    $linkBlock = {
        param($finding)
        $parts = @(& $linkList $finding)
        if ($parts.Count -eq 0) { return '' }
        return "<ul class=""learn"">$(($parts | ForEach-Object { "<li>$_</li>" }) -join '')</ul>"
    }
    $badge = {
        param($severity)
        $cls = "$severity".ToLowerInvariant()
        $label = if ($priority.ContainsKey("$severity")) { "$($priority["$severity"]) &middot; $(& $h $severity)" } else { & $h $severity }
        "<span class=""badge $cls"">$label</span>"
    }

    $usedReferences = [System.Collections.Generic.SortedSet[string]]::new()
    foreach ($f in @($Finding)) { foreach ($u in ("$($f.Reference)" -split '\s*;\s*' | Where-Object { $_ })) { [void]$usedReferences.Add($u) } }

    # One row per distinct issue; several resources with the same issue are folded into a single expandable row
    $renderTable = {
        param($findings, [bool]$showArea)
        $groups = @($findings | Group-Object { "$($_.Task)|$($_.Severity)|$($_.Finding)" } | Sort-Object { $severityOrder["$($_.Group[0].Severity)"] }, { $_.Group[0].Task })
        $sb2 = [System.Text.StringBuilder]::new()
        [void]$sb2.AppendLine('<div class="tablewrap"><table class="findings"><thead><tr>')
        [void]$sb2.AppendLine('<th class="c-pri">Priority</th>')
        if ($showArea) { [void]$sb2.AppendLine('<th class="c-area">Area</th>') }
        [void]$sb2.AppendLine('<th class="c-res">Resource</th><th class="c-issue">Issue</th><th class="c-act">Recommended action</th><th class="c-learn">Microsoft Learn</th></tr></thead><tbody>')
        foreach ($group in $groups) {
            $first = $group.Group[0]
            $resources = @($group.Group | ForEach-Object { $_.Resource })
            $resourceHtml = if ($resources.Count -gt 1) {
                "<details><summary>$($resources.Count) items</summary><ul>$(($resources | ForEach-Object { "<li>$(& $h $_)</li>" }) -join '')</ul></details>"
            }
            else { & $h $resources[0] }
            $areaTitle = if ($taskInfo.Contains("$($first.Task)")) { "$($taskInfo["$($first.Task)"].Number). $($taskInfo["$($first.Task)"].Title)" } else { "$($first.Task)" }
            [void]$sb2.Append('<tr>')
            [void]$sb2.Append("<td class=""c-pri"">$(& $badge $first.Severity)</td>")
            if ($showArea) { [void]$sb2.Append("<td class=""c-area"">$(& $h $areaTitle)</td>") }
            [void]$sb2.Append("<td class=""c-res"">$resourceHtml</td><td class=""c-issue"">$(& $h $first.Finding)</td><td class=""c-act"">$(& $h $first.Recommendation)</td><td class=""c-learn"">$(& $linkBlock $first)</td>")
            [void]$sb2.AppendLine('</tr>')
        }
        [void]$sb2.AppendLine('</tbody></table></div>')
        return $sb2.ToString()
    }

    $items = @($Finding)
    $open = @($items | Where-Object Status -eq 'NonCompliant')
    $skipped = @($items | Where-Object Status -eq 'Skipped')
    $manual = @($items | Where-Object Status -eq 'Manual')
    $failed = @($items | Where-Object Status -eq 'Failed')
    $compliant = @($items | Where-Object Status -eq 'Compliant')
    $count = { param($p) @($open | Where-Object { $priority["$($_.Severity)"] -eq $p }).Count }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">')
    [void]$sb.AppendLine('<title>Legacy SharePoint principal review - recommendations</title>')
    [void]$sb.AppendLine('<style>')
    [void]$sb.AppendLine(@'
:root{--blue:#0f6cbd;--text:#1f2328;--muted:#59636e;--line:#d1d9e0;--bg:#f6f8fa}
*{box-sizing:border-box}
body{font-family:"Segoe UI",system-ui,Arial,sans-serif;color:var(--text);line-height:1.5;margin:0;background:#fff}
main{max-width:1500px;margin:0 auto;padding:24px 32px 64px}
h1{font-size:1.9rem;margin:0 0 .25rem;color:var(--blue)}
h2{font-size:1.35rem;margin:2.2rem 0 .8rem;padding-bottom:.3rem;border-bottom:2px solid var(--blue);color:var(--blue)}
h3{font-size:1.1rem;margin:1.8rem 0 .6rem}
.meta{color:var(--muted);margin:0 0 1rem}.meta span{margin-right:1.5rem;white-space:nowrap}
.banner{border:1px solid var(--line);border-left:5px solid var(--blue);background:var(--bg);padding:12px 16px;border-radius:6px;margin:1rem 0}
.banner.warn{border-left-color:#bf8700;background:#fff8c5}
.banner.bad{border-left-color:#cf222e;background:#ffebe9}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:1rem 0}
.card{border:1px solid var(--line);border-radius:8px;padding:12px 14px;background:var(--bg)}
.card b{display:block;font-size:1.8rem;line-height:1.1}.card span{color:var(--muted);font-size:.85rem}
.tablewrap{overflow-x:auto;margin:.8rem 0 1.2rem;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:.92rem}
table.findings{table-layout:fixed;min-width:1100px}
th{background:var(--blue);color:#fff;text-align:left;padding:8px 10px;white-space:nowrap}
td{padding:8px 10px;border-top:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere}
tbody tr:nth-child(even){background:var(--bg)}
.c-pri{width:96px}.c-area{width:160px}.c-res{width:19%}.c-issue{width:25%}.c-act{width:28%}.c-learn{width:22%}
table.score td:first-child{width:48px;text-align:right}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:.78rem;font-weight:600;white-space:nowrap;border:1px solid transparent}
.badge.critical{background:#cf222e;color:#fff}.badge.high{background:#ffebe9;color:#a40e26;border-color:#ff8182}
.badge.medium{background:#fff8c5;color:#7d4e00;border-color:#d4a72c}.badge.low{background:#ddf4ff;color:#0550ae;border-color:#54aeff}
.badge.info{background:var(--bg);color:var(--muted);border-color:var(--line)}
.res-ok{color:#1a7f37;font-weight:600}.res-bad{color:#a40e26;font-weight:600}.res-warn{color:#7d4e00;font-weight:600}.res-na{color:var(--muted)}
ul.learn{margin:0;padding-left:1.1rem}ul.learn li{margin:0 0 .25rem}
details summary{cursor:pointer;color:var(--blue)}details ul{margin:.4rem 0 0;padding-left:1.1rem}
a{color:var(--blue)}code{background:#eff1f3;border-radius:4px;padding:1px 5px;font-family:Consolas,monospace;font-size:.9em;overflow-wrap:anywhere}
.steps{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:8px 16px 8px 32px;margin:.6rem 0}
.notes li{margin:.3rem 0}
.item{margin:.4rem 0;padding:8px 12px;border:1px solid var(--line);border-radius:6px}
.item .tag{font-weight:700;margin-right:.4rem}
.item.err{border-left:4px solid #cf222e}.item.na{border-left:4px solid #bf8700}.item.man{border-left:4px solid var(--blue)}
@media print{.tablewrap{overflow:visible}table.findings{min-width:0}}
'@)
    [void]$sb.AppendLine('</style></head><body><main>')
    [void]$sb.AppendLine('<h1>Legacy SharePoint principal review</h1>')
    [void]$sb.AppendLine("<p class=""meta""><span>Tenant: <code>$(& $h $TenantId)</code></span><span>Run: <code>$(& $h $RunId)</code></span><span>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</span></p>")
    [void]$sb.AppendLine('<div class="banner"><b>Read-only review.</b> Nothing in your tenant was changed. Every item below is a recommendation for your administrators to review and carry out themselves, with the Microsoft Learn articles it is based on.</div>')

    $prerequisites = @($items | Where-Object Task -eq 'Prerequisites')
    foreach ($finding in $prerequisites) {
        if ($finding.Status -eq 'Skipped') {
            [void]$sb.AppendLine("<div class=""banner bad""><b>Action required - this review is incomplete.</b> $(& $h $finding.Finding)<br><b>Fix:</b> $(& $h $finding.Recommendation)$(& $linkBlock $finding)</div>")
        }
        else {
            [void]$sb.AppendLine("<div class=""banner""><b>Run prerequisites.</b> $(& $h $finding.Finding)</div>")
        }
    }

    [void]$sb.AppendLine('<h2>Summary</h2><div class="cards">')
    [void]$sb.AppendLine("<div class=""card""><b>$(& $count 'P1')</b><span>P1 - Critical/High, fix now</span></div>")
    [void]$sb.AppendLine("<div class=""card""><b>$(& $count 'P2')</b><span>P2 - Medium, fix this cycle</span></div>")
    [void]$sb.AppendLine("<div class=""card""><b>$(& $count 'P3')</b><span>P3 - Low, hygiene</span></div>")
    [void]$sb.AppendLine("<div class=""card""><b>$($compliant.Count)</b><span>Already in good shape</span></div>")
    [void]$sb.AppendLine("<div class=""card""><b>$($skipped.Count)</b><span>Not assessed (skipped)</span></div>")
    [void]$sb.AppendLine("<div class=""card""><b>$($manual.Count)</b><span>Manual steps</span></div>")
    [void]$sb.AppendLine("<div class=""card""><b>$($failed.Count)</b><span>Errors</span></div>")
    [void]$sb.AppendLine('</div>')

    [void]$sb.AppendLine('<h2>Scorecard</h2><div class="tablewrap"><table class="score"><thead><tr><th>#</th><th>Area</th><th>Result</th></tr></thead><tbody>')
    foreach ($taskName in $taskInfo.Keys) {
        $taskItems = @($items | Where-Object Task -eq $taskName)
        $taskOpen = @($taskItems | Where-Object Status -eq 'NonCompliant')
        $taskSkipped = @($taskItems | Where-Object Status -eq 'Skipped')
        $taskFailed = @($taskItems | Where-Object Status -eq 'Failed')
        $taskCompliant = @($taskItems | Where-Object Status -eq 'Compliant')
        [string]$class = 'res-ok'
        [string]$result = 'OK'
        if ($taskItems.Count -eq 0) { $class = 'res-na'; $result = 'Not run' }
        elseif ($taskOpen.Count -gt 0) {
            $class = 'res-bad'
            $result = "Action needed ($($taskOpen.Count) open, worst: $((@($taskOpen | Sort-Object { $severityOrder["$($_.Severity)"] })[0]).Severity))"
        }
        elseif ($taskSkipped.Count -gt 0 -and $taskCompliant.Count -eq 0) { $class = 'res-warn'; $result = 'Not assessed' }
        elseif ($taskFailed.Count -gt 0 -and $taskCompliant.Count -eq 0) { $class = 'res-warn'; $result = 'Error - not assessed' }
        elseif ($taskSkipped.Count -gt 0 -or $taskFailed.Count -gt 0) { $class = 'res-warn'; $result = 'Partial - some checks not assessed' }
        [void]$sb.AppendLine("<tr><td>$($taskInfo[$taskName].Number)</td><td>$(& $h $taskInfo[$taskName].Title)</td><td class=""$class"">$(& $h $result)</td></tr>")
    }
    [void]$sb.AppendLine('</tbody></table></div>')

    $topActions = @($open | Where-Object { $priority["$($_.Severity)"] -eq 'P1' })
    if ($topActions.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Fix first (P1)</h2>')
        [void]$sb.AppendLine((& $renderTable $topActions $true))
    }

    [void]$sb.AppendLine('<h2>Detail by area</h2>')
    foreach ($taskName in $taskInfo.Keys) {
        $taskOpen = @($open | Where-Object Task -eq $taskName)
        $taskSkipped = @($skipped | Where-Object Task -eq $taskName)
        $taskManual = @($manual | Where-Object Task -eq $taskName)
        $taskFailed = @($failed | Where-Object Task -eq $taskName)
        if ($taskOpen.Count + $taskSkipped.Count + $taskManual.Count + $taskFailed.Count -eq 0) { continue }

        [void]$sb.AppendLine("<h3>$($taskInfo[$taskName].Number). $(& $h $taskInfo[$taskName].Title)</h3>")
        if ($taskOpen.Count -gt 0) { [void]$sb.AppendLine((& $renderTable $taskOpen $false)) }
        foreach ($finding in $taskSkipped) {
            [void]$sb.AppendLine("<div class=""item na""><span class=""tag"">Not assessed</span>$(& $h $finding.Resource) - $(& $h $finding.Finding) $(& $h $finding.Recommendation)$(& $linkBlock $finding)</div>")
        }
        foreach ($finding in $taskManual) {
            [void]$sb.AppendLine("<div class=""item man""><span class=""tag"">Manual step</span>$(& $h $finding.Resource) - $(& $h $finding.Finding) $(& $h $finding.Recommendation)$(& $linkBlock $finding)</div>")
        }
        foreach ($finding in $taskFailed) {
            $detail = if ($finding.Detail) { "<br><code>$(& $h $finding.Detail)</code>" } else { '' }
            [void]$sb.AppendLine("<div class=""item err""><span class=""tag"">Error</span>$(& $h $finding.Resource) - $(& $h $finding.Finding)$detail</div>")
        }
        [void]$sb.AppendLine('<p><b>What to do</b></p><ol class="steps">')
        foreach ($step in $taskInfo[$taskName].Steps) { [void]$sb.AppendLine("<li>$step</li>") }
        [void]$sb.AppendLine('</ol>')
    }

    if ($compliant.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Already compliant</h2><ul>')
        foreach ($finding in $compliant) { [void]$sb.AppendLine("<li>$(& $h $finding.Resource) - $(& $h $finding.Finding)</li>") }
        [void]$sb.AppendLine('</ul>')
    }

    $selectedLink = '<a href="https://learn.microsoft.com/en-us/graph/permissions-selected-overview">Overview of Selected Permissions in OneDrive and SharePoint</a>'
    $auditLink = '<a href="https://learn.microsoft.com/en-us/purview/audit-log-search">Search the audit log</a>'
    [void]$usedReferences.Add('https://learn.microsoft.com/en-us/graph/permissions-selected-overview')
    [void]$usedReferences.Add('https://learn.microsoft.com/en-us/purview/audit-log-search')
    [void]$sb.AppendLine('<h2>Notes</h2><ul class="notes">')
    [void]$sb.AppendLine('<li>Create Conditional Access policies in report-only mode first and exclude your emergency-access (break-glass) accounts.</li>')
    [void]$sb.AppendLine("<li>Before removing a tenant-wide permission from an app, grant it <code>Sites.Selected</code> on the sites it needs and confirm the owner is ready, or the app will stop working. See $selectedLink.</li>")
    [void]$sb.AppendLine("<li>ACS app-only tokens do not appear in Entra sign-in logs; use the SharePoint audit log (<code>FileDownloaded</code>, <code>FileSyncDownloadedFull</code>) to scope any suspected data theft. See $auditLink.</li>")
    [void]$sb.AppendLine('<li>Re-run the review after you make changes and periodically; compare the <code>EnterpriseApps</code> CSV between runs to spot new apps.</li>')
    [void]$sb.AppendLine('</ul>')

    if ($usedReferences.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Microsoft Learn references</h2><p>Every recommendation above is grounded in the following Microsoft documentation:</p><ul>')
        foreach ($url in $usedReferences) {
            $title = Get-LearnReference -Url $url
            if (-not $title) { $title = $url }
            [void]$sb.AppendLine("<li><a href=""$(& $h $url)"">$(& $h $title)</a></li>")
        }
        [void]$sb.AppendLine('</ul>')
    }

    [void]$sb.AppendLine('</main></body></html>')
    Set-Content -LiteralPath $Path -Value $sb.ToString() -Encoding utf8
    return $Path
}
