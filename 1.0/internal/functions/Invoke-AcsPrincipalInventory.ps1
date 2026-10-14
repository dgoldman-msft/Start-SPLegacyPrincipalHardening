function Invoke-AcsPrincipalInventory {
    <#
    .SYNOPSIS
        Task 1 - Read-only inventory of legacy SharePoint add-in / Azure ACS principals.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $task = 'AcsInventory'
    Write-ToLogFile "`n== [1/8] Inventory legacy add-in / ACS principals ==" -LogFile $Context.LogFile -ForegroundColor Cyan

    if (-not $Context.PnPAvailable) {
        New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Skipped -Resource 'ACS principals' -Finding 'PnP PowerShell session not available (no usable Entra app registration for PnP sign-in).' -Recommendation 'Provide -PnPClientId <appId> (or set $env:ENTRAID_APP_ID) for an app with a http://localhost redirect URI / public client flows enabled, and re-run.'
        return
    }

    try {
        $acsParameters = @{ Scope = $Context.AcsScope; ErrorAction = 'Stop' }
        if ($Context.IncludeSubsites) { $acsParameters.IncludeSubsites = $true }
        Write-ToLogFile "Querying ACS principals (scope: $($Context.AcsScope)) - this can be slow on large tenants..." -LogFile $Context.LogFile -ForegroundColor Gray
        $principals = @(Get-PnPAzureACSPrincipal @acsParameters)
    }
    catch {
        New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Failed -Resource 'ACS principals' -Finding 'Get-PnPAzureACSPrincipal failed.' -Detail $_.Exception.Message
        return
    }

    $now = Get-Date
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($group in ($principals | Group-Object { "$($_.AppId)" })) {
        $principal = $group.Group | Sort-Object ValidUntil -Descending | Select-Object -First 1
        $appId = "$($principal.AppId)"

        $entraSp = $null
        try {
            $response = Invoke-GraphWithRetry -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$appId'&`$select=id,displayName,accountEnabled,appOwnerOrganizationId" -LogFile $Context.LogFile
            $entraSp = @($response.value) | Select-Object -First 1
        }
        catch {
            Write-ToLogFile "Entra lookup failed for ACS AppId ${appId}: $($_.Exception.Message)" -LogFile $Context.LogFile -LogOnly
        }

        $validUntilKnown = $principal.ValidUntil -and $principal.ValidUntil -gt [datetime]'1900-01-01'
        $rows.Add([pscustomobject]@{
                AppId          = $appId
                EntraName      = $entraSp.displayName
                EntraObjectId  = $entraSp.id
                EntraEnabled   = $entraSp.accountEnabled
                RedirectUri    = $principal.RedirectUri
                AppDomains     = (@($principal.AppDomains) -join ';')
                ValidUntil     = if ($validUntilKnown) { $principal.ValidUntil } else { $null }
                Expired        = [bool]($validUntilKnown -and $principal.ValidUntil -lt $now)
                SeenInSites    = $group.Count
            })
    }
    $Context.Datasets['AcsPrincipals'] = $rows.ToArray()

    if ($rows.Count -eq 0) {
        New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Compliant -Resource 'ACS principals' -Finding 'No legacy ACS principals found.'
    }
    foreach ($row in $rows) {
        $label = if ($row.EntraName) { "$($row.EntraName) ($($row.AppId))" } else { $row.AppId }
        if ($row.Expired) {
            New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status NonCompliant -Resource $label -Finding "ACS principal credential expired $($row.ValidUntil.ToString('yyyy-MM-dd'))." -Recommendation "Remove the expired principal manually on AppPrincipals.aspx for the owning site (no supported cmdlet exists); it has no legitimate use. If an Entra service principal exists, review it with its owner."
        }
        else {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource $label -Finding "Active legacy ACS principal (RedirectUri: $($row.RedirectUri))." -Detail "ValidUntil: $($row.ValidUntil)" -Recommendation "Confirm the business need with the owner. ACS is retired (2 Apr 2026), so migrate the app to Entra ID app-only access, then remove the principal manually on AppPrincipals.aspx (no supported cmdlet exists). Treat unknown principals during an incident as persistence. Until then, disabling ACS app-only authentication tenant-wide blocks their tokens (task 2)."
        }
    }
}
