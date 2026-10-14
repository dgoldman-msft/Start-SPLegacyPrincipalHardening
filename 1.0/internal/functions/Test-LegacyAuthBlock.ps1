function Test-LegacyAuthBlock {
    <#
    .SYNOPSIS
        Task 7 - Read-only check that legacy authentication is blocked by Conditional Access and in SharePoint Online.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $task = 'LegacyAuthBlock'
    Write-ToLogFile "`n== [7/8] Block legacy authentication ==" -LogFile $Context.LogFile -ForegroundColor Cyan

    try {
        $policies = @(Get-ConditionalAccessPolicy -Context $Context)
        $blockPolicies = @($policies | Where-Object {
                $clientTypes = @($_.conditions.clientAppTypes)
                $_.conditions.users.includeUsers -contains 'All' -and
                $_.conditions.applications.includeApplications -contains 'All' -and
                $clientTypes -contains 'exchangeActiveSync' -and $clientTypes -contains 'other' -and
                @($_.grantControls.builtInControls) -contains 'block'
            })
        $enforced = @($blockPolicies | Where-Object { $_.state -eq 'enabled' })
        $reportOnly = @($blockPolicies | Where-Object { $_.state -eq 'enabledForReportingButNotEnforced' })

        if ($enforced.Count -gt 0) {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status Compliant -Resource 'Conditional Access' -Finding "Legacy authentication is blocked by: $(@($enforced.displayName) -join '; ')"
        }
        elseif ($reportOnly.Count -gt 0) {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource 'Conditional Access' -Finding "Block-legacy-auth policy exists but is report-only: $(@($reportOnly.displayName) -join '; ')" -Recommendation 'Review the report-only results, then switch the policy to On.'
        }
        else {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource 'Conditional Access' -Finding 'No policy blocks legacy authentication for all users and apps.' -Recommendation 'Create a Conditional Access policy that blocks the Exchange ActiveSync and "other clients" client app types for all users and apps. Start in report-only mode and exclude your break-glass accounts.'
        }
    }
    catch {
        New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Failed -Resource 'Conditional Access' -Finding 'Could not evaluate Conditional Access policies.' -Detail $_.Exception.Message
    }

    if (-not $Context.PnPAvailable) {
        New-ReviewFinding -Context $Context -Task $task -Severity Info -Status Skipped -Resource 'SharePoint LegacyAuthProtocolsEnabled' -Finding 'PnP PowerShell session not available (no usable Entra app registration for PnP sign-in).' -Recommendation 'Provide -PnPClientId <appId> (or set $env:ENTRAID_APP_ID) for an app with a http://localhost redirect URI / public client flows enabled, and re-run.'
        return
    }

    try {
        $tenant = Get-PnPTenant -ErrorAction Stop
        if ($tenant.LegacyAuthProtocolsEnabled) {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status NonCompliant -Resource 'SharePoint LegacyAuthProtocolsEnabled' -Finding 'SharePoint Online still accepts legacy authentication protocols.' -Recommendation 'Disable legacy authentication protocols in SharePoint Online: Set-SPOTenant -LegacyAuthProtocolsEnabled $false (or Set-PnPTenant -LegacyAuthProtocolsEnabled $false). Confirm no business-critical clients depend on them first.'
        }
        else {
            New-ReviewFinding -Context $Context -Task $task -Severity High -Status Compliant -Resource 'SharePoint LegacyAuthProtocolsEnabled' -Finding 'Legacy authentication protocols are disabled in SharePoint Online.'
        }
    }
    catch {
        New-ReviewFinding -Context $Context -Task $task -Severity Medium -Status Failed -Resource 'SharePoint LegacyAuthProtocolsEnabled' -Finding 'Could not read the SharePoint tenant setting.' -Detail $_.Exception.Message
    }
}
