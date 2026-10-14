function Find-PnPClientApp {
    <#
    .SYNOPSIS
        Looks for an Entra app registration usable for PnP interactive sign-in in the connected tenant.
    .DESCRIPTION
        Candidates are app registrations configured as public clients (a localhost or nativeclient redirect URI, or
        "Allow public client flows"), which is what Register-PnPEntraIDAppForInteractiveLogin creates. An app named
        'SPLegacyHardening' wins; otherwise a single candidate is used. With several candidates nothing is chosen
        automatically so the caller must pass -PnPClientId.
        Returns an object with AppId, Name and Reason (why nothing was selected, when AppId is empty).
    #>
    [CmdletBinding()]
    param(
        [string]$PreferredName = 'SPLegacyHardening',

        [Parameter(Mandatory)]
        [string]$LogFile
    )

    $uri = 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,createdDateTime,isFallbackPublicClient,publicClient&$top=999'
    try {
        $applications = @(Invoke-GraphPaged -Uri $uri -LogFile $LogFile)
    }
    catch {
        $reason = "The tenant's app registrations could not be read to look for a PnP client app ($($_.Exception.Message))."
        Write-ToLogFile $reason -LogFile $LogFile -ForegroundColor Yellow
        return [pscustomobject]@{ AppId = $null; Name = $null; Reason = $reason }
    }

    $isPublicClientRedirect = { $_ -match '^http://localhost' -or $_ -match 'login\.microsoftonline\.com/common/oauth2/nativeclient$' }
    $candidates = @($applications | Where-Object {
            $_.isFallbackPublicClient -or @($_.publicClient.redirectUris | Where-Object $isPublicClientRedirect).Count -gt 0
        })

    $selected = $null
    $preferred = @($candidates | Where-Object { $_.displayName -ieq $PreferredName })
    if ($preferred.Count -eq 1) { $selected = $preferred[0] }
    elseif ($candidates.Count -eq 1) { $selected = $candidates[0] }

    if ($selected) {
        return [pscustomobject]@{ AppId = $selected.appId; Name = $selected.displayName; Reason = $null }
    }

    $reason = if ($candidates.Count -gt 1) {
        "$($candidates.Count) possible PnP client apps were found and none could be chosen automatically: $((($candidates | ForEach-Object { "$($_.displayName) ($($_.appId))" }) -join '; '))."
    }
    else {
        "None of the $($applications.Count) app registration(s) visible in the tenant is a public client. The app needs a http://localhost redirect URI (Mobile and desktop applications platform) or 'Allow public client flows' enabled."
    }
    Write-ToLogFile $reason -LogFile $LogFile -ForegroundColor Yellow
    return [pscustomobject]@{ AppId = $null; Name = $null; Reason = $reason }
}
