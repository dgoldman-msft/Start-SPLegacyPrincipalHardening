function Get-LegacyServicePrincipal {
    <#
    .SYNOPSIS
        Finds the Microsoft first-party "SharePoint Online Client Extensibility" service principals (Web Application Principal and its WebShell/Helper siblings) by display name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    if ($Context.Cache.ContainsKey('LegacyServicePrincipals')) { return $Context.Cache['LegacyServicePrincipals'] }

    $select = 'id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,createdDateTime,appRoleAssignmentRequired'
    $found = @{}
    foreach ($prefix in 'SharePoint Online Client Extensibility', 'SharePoint Online Web Client Extensibility') {
        $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=startswith(displayName,'$prefix')&`$select=$select"
        foreach ($sp in @(Invoke-GraphPaged -Uri $uri -LogFile $Context.LogFile)) { $found[$sp.id] = $sp }
    }

    $result = @($found.Values)
    Write-ToLogFile "Found $($result.Count) legacy client-extensibility service principal(s): $((@($result.displayName) -join '; '))" -LogFile $Context.LogFile -LogOnly
    $Context.Cache['LegacyServicePrincipals'] = $result
    return $result
}
