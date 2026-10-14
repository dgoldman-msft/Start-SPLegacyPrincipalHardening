function Get-AllServicePrincipal {
    <#
    .SYNOPSIS
        Returns every service principal in the tenant (with owners) and caches it for the run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    if ($Context.Cache.ContainsKey('ServicePrincipals')) { return $Context.Cache['ServicePrincipals'] }

    Write-ToLogFile 'Loading all service principals from Microsoft Graph (this can take a while)...' -LogFile $Context.LogFile -ForegroundColor Gray
    $select = 'id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId,createdDateTime,appRoleAssignmentRequired,tags,passwordCredentials,keyCredentials'
    $uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=$select&`$expand=owners(`$select=id)&`$top=100"
    $all = @(Invoke-GraphPaged -Uri $uri -LogFile $Context.LogFile)

    $byId = @{}
    foreach ($sp in $all) { $byId[$sp.id] = $sp }
    $Context.Cache['ServicePrincipals'] = $all
    $Context.Cache['ServicePrincipalsById'] = $byId
    Write-ToLogFile "Loaded $($all.Count) service principals." -LogFile $Context.LogFile -LogOnly
    return $all
}
