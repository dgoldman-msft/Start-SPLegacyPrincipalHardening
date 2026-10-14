function Get-SharePointAdminUrl {
    <#
    .SYNOPSIS
        Resolves the SharePoint admin center URL from an explicit value, a tenant name, or the tenant's initial domain.
    #>
    [CmdletBinding()]
    param(
        [string]$AdminUrl,

        [string]$TenantName,

        [Parameter(Mandatory)]
        [string]$LogFile
    )

    if ($AdminUrl) {
        return $AdminUrl.TrimEnd('/')
    }

    if (-not $TenantName) {
        $organization = Invoke-GraphWithRetry -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains' -LogFile $LogFile
        $initialDomain = @($organization.value[0].verifiedDomains) | Where-Object { $_.isInitial } | Select-Object -First 1
        if (-not $initialDomain) {
            throw 'Could not determine the tenant name. Specify -TenantName or -SharePointAdminUrl.'
        }
        $TenantName = ($initialDomain.name -split '\.')[0]
    }

    $resolvedUrl = "https://$TenantName-admin.sharepoint.com"
    Write-ToLogFile "SharePoint admin URL: $resolvedUrl" -LogFile $LogFile -LogOnly
    return $resolvedUrl
}
