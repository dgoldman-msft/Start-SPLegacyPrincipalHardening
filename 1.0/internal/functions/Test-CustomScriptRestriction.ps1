function Test-CustomScriptRestriction {
    <#
    .SYNOPSIS
        Task 4 - Read-only: finds site collections that allow custom script (DenyAddAndCustomizePages not enforced).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $task = 'CustomScript'
    Write-ToLogFile "`n== [4/8] Custom script restriction (DenyAddAndCustomizePages) ==" -LogFile $Context.LogFile -ForegroundColor Cyan

    if (-not $Context.PnPAvailable) {
        New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Skipped -Resource 'Site collections' -Finding 'PnP PowerShell session not available (no usable Entra app registration for PnP sign-in).' -Recommendation 'Provide -PnPClientId <appId> (or set $env:ENTRAID_APP_ID) for an app with a http://localhost redirect URI / public client flows enabled, and re-run.'
        return
    }

    try {
        $siteParameters = @{ ErrorAction = 'Stop' }
        if ($Context.IncludeOneDriveSites) { $siteParameters.IncludeOneDriveSites = $true }
        Write-ToLogFile 'Enumerating site collections...' -LogFile $Context.LogFile -ForegroundColor Gray
        $sites = @(Get-PnPTenantSite @siteParameters)
    }
    catch {
        New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Failed -Resource 'Site collections' -Finding 'Get-PnPTenantSite failed.' -Detail $_.Exception.Message
        return
    }

    $skipTemplates = 'RedirectSite#0', 'SRCHCEN#0', 'TENANTADMIN#0', 'SPSMSITEHOST#0', 'APPCATALOG#0'
    $rows = [System.Collections.Generic.List[object]]::new()
    $index = 0
    $compliantCount = 0
    foreach ($site in $sites) {
        $index++
        if ($index % 25 -eq 0) { Write-Progress -Activity 'Checking custom script settings' -Status "$index of $($sites.Count)" -PercentComplete (($index / [Math]::Max($sites.Count, 1)) * 100) }

        $url = $site.Url
        if ($site.Template -in $skipTemplates -or $site.Status -ne 'Active') { continue }
        if ($Context.ExcludeSiteUrl | Where-Object { $url -like $_ }) { continue }

        $status = "$($site.DenyAddAndCustomizePages)"
        if (-not $status -or $status -eq 'Unknown') {
            try { $status = "$((Get-PnPTenantSite -Identity $url -Detailed -ErrorAction Stop).DenyAddAndCustomizePages)" } catch { $status = 'Unknown' }
        }

        $row = [pscustomobject]@{ Url = $url; Title = $site.Title; Template = $site.Template; DenyAddAndCustomizePages = $status; Result = '' }
        if ($status -eq 'Enabled') {
            $compliantCount++
            $row.Result = 'Compliant'
            $rows.Add($row)
            continue
        }

        $row.Result = 'NonCompliant'
        New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status NonCompliant -Resource $url -Finding "Custom script allowed (DenyAddAndCustomizePages = $status)." -Recommendation 'Prevent custom script on the site: Set-SPOSite -Identity <url> -DenyAddAndCustomizePages $true (or Set-PnPSite -Identity <url> -NoScriptSite $true). Check first that the site does not rely on custom script.' -LogOnly
        $rows.Add($row)
    }
    Write-Progress -Activity 'Checking custom script settings' -Completed
    $Context.Datasets['CustomScriptSites'] = $rows.ToArray()

    $nonCompliantCount = @($rows | Where-Object Result -eq 'NonCompliant').Count
    $severity = if ($nonCompliantCount -gt 0) { 'Medium' } else { 'Info' }
    $status = if ($nonCompliantCount -gt 0) { 'NonCompliant' } else { 'Compliant' }
    New-ReviewFinding -Context $Context -Task $task -Severity $severity -Status $status -Resource 'Site collections' -Finding "$compliantCount compliant, $nonCompliantCount allow custom script (of $($rows.Count) checked). Per-site detail in the CustomScriptSites CSV." -Recommendation $(if ($nonCompliantCount -gt 0) { 'Prevent custom script on the sites listed in the CustomScriptSites CSV (Set-SPOSite -DenyAddAndCustomizePages $true).' })
}
