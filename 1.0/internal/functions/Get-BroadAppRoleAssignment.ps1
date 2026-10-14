function Get-BroadAppRoleAssignment {
    <#
    .SYNOPSIS
        Returns every application-permission assignment on the SharePoint Online and Microsoft Graph resource principals, flagging tenant-wide site/file roles. Cached for the run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    if ($Context.Cache.ContainsKey('AppRoleAssignments')) { return $Context.Cache['AppRoleAssignments'] }

    $resources = @(
        @{ Name = 'Office 365 SharePoint Online'; AppId = '00000003-0000-0ff1-ce00-000000000000' }
        @{ Name = 'Microsoft Graph'; AppId = '00000003-0000-0000-c000-000000000000' }
    )
    $broadPattern = '^(Sites|Files)\.(FullControl|Manage|ReadWrite|Read)\.All$|^AllSites\.(FullControl|Manage|Write|Read)$'

    $result = [System.Collections.Generic.List[object]]::new()
    foreach ($resource in $resources) {
        $spResponse = Invoke-GraphWithRetry -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$($resource.AppId)'&`$select=id,displayName,appRoles" -LogFile $Context.LogFile
        $resourceSp = @($spResponse.value) | Select-Object -First 1
        if (-not $resourceSp) { continue }

        $roleNames = @{}
        foreach ($role in @($resourceSp.appRoles)) { $roleNames[$role.id] = $role.value }

        $assignments = @(Invoke-GraphPaged -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($resourceSp.id)/appRoleAssignedTo?`$top=999" -LogFile $Context.LogFile)
        foreach ($assignment in $assignments) {
            $roleValue = $roleNames[$assignment.appRoleId]
            $isBroad = [bool]($roleValue -match $broadPattern)
            $severity = 'Info'
            if ($isBroad) {
                $severity = if ($roleValue -match 'FullControl') { 'Critical' } elseif ($roleValue -match 'Manage|ReadWrite|Write') { 'High' } else { 'Medium' }
            }
            $result.Add([pscustomobject]@{
                    Resource        = $resource.Name
                    ResourceAppId   = $resource.AppId
                    ResourceSpId    = $resourceSp.id
                    AssignmentId    = $assignment.id
                    PrincipalId     = $assignment.principalId
                    PrincipalName   = $assignment.principalDisplayName
                    PrincipalType   = $assignment.principalType
                    AppRole         = $roleValue
                    AppRoleId       = $assignment.appRoleId
                    IsBroad         = $isBroad
                    IsSitesSelected = ($roleValue -eq 'Sites.Selected')
                    Severity        = $severity
                    Created         = $assignment.createdDateTime
                })
        }
    }

    $Context.Cache['AppRoleAssignments'] = $result.ToArray()
    return $Context.Cache['AppRoleAssignments']
}
