function Test-AppOnlyPermissionScope {
    <#
    .SYNOPSIS
        Task 3 - Read-only: finds apps holding tenant-wide SharePoint/Graph application permissions and recommends migrating them to Sites.Selected.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $task = 'AppOnlyPermissions'
    Write-ToLogFile "`n== [3/8] App-only permission scope (Sites.Selected migration) ==" -LogFile $Context.LogFile -ForegroundColor Cyan

    $assignments = @(Get-BroadAppRoleAssignment -Context $Context)
    $null = Get-AllServicePrincipal -Context $Context
    $servicePrincipalsById = $Context.Cache['ServicePrincipalsById']
    $appRegistrations = Get-AllAppRegistration -Context $Context

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($assignment in ($assignments | Where-Object { $_.IsBroad -or $_.IsSitesSelected })) {
        $principal = $servicePrincipalsById[$assignment.PrincipalId]
        $appId = $principal.appId
        $credentialSource = if ($appRegistrations.ContainsKey("$appId")) { $appRegistrations["$appId"] } else { $principal }
        $secretCount = @($credentialSource.passwordCredentials | Where-Object { $_ }).Count
        $certificateCount = @($credentialSource.keyCredentials | Where-Object { $_ }).Count
        $microsoftOwned = $principal.appOwnerOrganizationId -in $script:MicrosoftTenantIds

        $rows.Add([pscustomobject]@{
                AppName        = $assignment.PrincipalName
                AppId          = $appId
                ObjectId       = $assignment.PrincipalId
                Resource       = $assignment.Resource
                Permission     = $assignment.AppRole
                Broad          = $assignment.IsBroad
                MicrosoftOwned = $microsoftOwned
                Secrets        = $secretCount
                Certificates   = $certificateCount
                Severity       = $assignment.Severity
                AssignmentId   = $assignment.AssignmentId
                ResourceSpId   = $assignment.ResourceSpId
            })
    }
    $Context.Datasets['AppOnlyPermissions'] = $rows.ToArray()

    $broadRows = @($rows | Where-Object { $_.Broad })
    $selectedRows = @($rows | Where-Object { -not $_.Broad })
    if ($selectedRows.Count -gt 0) {
        New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Compliant -Resource 'Sites.Selected' -Finding "$($selectedRows.Count) app(s) already use Sites.Selected: $((@($selectedRows.AppName | Sort-Object -Unique)) -join ', ')"
    }
    if ($broadRows.Count -eq 0) {
        New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Compliant -Resource 'Application permissions' -Finding 'No app holds tenant-wide Sites/Files application permissions.'
    }
    foreach ($row in $broadRows) {
        $credentialNote = if ($row.Certificates -eq 0 -and $row.Secrets -gt 0) { ' Authenticates with a client secret only.' } elseif ($row.Secrets -gt 0) { ' Also has a client secret.' } else { '' }
        $ownerNote = if ($row.MicrosoftOwned) { ' (Microsoft-owned)' } else { '' }
        New-ReviewFinding -Context $Context -Task $task -Severity $row.Severity -Status NonCompliant -Resource "$($row.AppName) ($($row.AppId))$ownerNote" -Finding "Holds $($row.Permission) on $($row.Resource).$credentialNote" -Recommendation 'Work with the app owner: grant the app Sites.Selected plus a per-site permission on only the sites it needs, switch it to certificate credentials, test it, then remove the tenant-wide role. Do not remove the role before the replacement works or the app will stop.' -LogOnly:$row.MicrosoftOwned
    }
}
