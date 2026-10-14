function Connect-TenantSession {
    <#
    .SYNOPSIS
        Connects (or reuses) the Microsoft Graph and PnP/SharePoint admin sessions for the selected tasks.
    #>
    [CmdletBinding()]
    param(
        [string]$TenantId,

        [string]$TenantName,

        [string]$SharePointAdminUrl,

        [string]$PnPClientId,

        [Parameter(Mandatory)]
        [string[]]$Task,

        [Parameter(Mandatory)]
        [string]$LogFile
    )

    $pnpTasks = 'AcsInventory', 'LegacyAddInSettings', 'CustomScript', 'LegacyAuthBlock'
    $needsPnP = [bool]($Task | Where-Object { $_ -in $pnpTasks })
    $pnpAvailable = $false
    $adminUrl = $null
    $pnpIssue = $null
    $pnpClientName = $null
    $pnpClientSource = if ($PnPClientId) { 'Parameter' } else { 'None' }

    if ($needsPnP -and -not $PnPClientId) {
        foreach ($variableName in 'ENTRAID_APP_ID', 'ENTRAID_CLIENT_ID', 'AZURE_CLIENT_ID') {
            if ([Environment]::GetEnvironmentVariable($variableName)) {
                $PnPClientId = [Environment]::GetEnvironmentVariable($variableName)
                $pnpClientSource = "Environment variable $variableName"
                break
            }
        }
    }
    $discoverPnPClient = $needsPnP -and -not $PnPClientId

    $scopes = @(Get-RequiredGraphScope -Task $Task)
    if ($discoverPnPClient) { $scopes = @($scopes + 'Application.Read.All' | Sort-Object -Unique) }
    $graphContext = Connect-GraphSession -TenantId $TenantId -Scope $scopes -LogFile $LogFile

    $discoveryReason = $null
    if ($discoverPnPClient) {
        $discovered = Find-PnPClientApp -LogFile $LogFile
        $discoveryReason = $discovered.Reason
        if ($discovered.AppId) {
            $PnPClientId = $discovered.AppId
            $pnpClientName = $discovered.Name
            $pnpClientSource = 'Auto-detected in tenant'
        }
    }

    if ($needsPnP) {
        try {
            $adminUrl = Get-SharePointAdminUrl -AdminUrl $SharePointAdminUrl -TenantName $TenantName -LogFile $LogFile
            $null = Connect-PnPSession -AdminUrl $adminUrl -ClientId $PnPClientId -TenantId $TenantId -LogFile $LogFile
            $pnpAvailable = $true
        }
        catch {
            $pnpIssue = $_.Exception.Message
            if ($discoveryReason) { $pnpIssue = "$discoveryReason $pnpIssue" }
        }
    }

    if ($needsPnP) {
        $pnpTaskList = ($Task | Where-Object { $_ -in $pnpTasks }) -join ', '
        if ($pnpAvailable) {
            $appText = if ($PnPClientId) { "app '$(if ($pnpClientName) { $pnpClientName } else { $PnPClientId })' ($PnPClientId), source: $pnpClientSource" } else { 'existing connection reused' }
            Write-ToLogFile "SharePoint admin (PnP) connected using $appText." -LogFile $LogFile -ForegroundColor Green
        }
        else {
            Write-ToLogFile '' -LogFile $LogFile
            Write-ToLogFile '!! ACTION REQUIRED: SharePoint admin (PnP) is NOT connected !!' -LogFile $LogFile -ForegroundColor Red
            Write-ToLogFile "Reason: $pnpIssue" -LogFile $LogFile -ForegroundColor Red
            Write-ToLogFile "Impact: these checks will be reported as 'Skipped / not assessed': $pnpTaskList." -LogFile $LogFile -ForegroundColor Yellow
            Write-ToLogFile "Fix: create or pick an Entra app registration with a http://localhost redirect URI (or 'Allow public client flows'), then re-run with -PnPClientId <appId> or set `$env:ENTRAID_APP_ID. Sign in as a SharePoint Administrator. To create one: Register-PnPEntraIDAppForInteractiveLogin -ApplicationName 'SPLegacyHardening' -Tenant <tenant>.onmicrosoft.com" -LogFile $LogFile -ForegroundColor Yellow
            Write-ToLogFile "Learn: $((Get-LearnReference -Url 'https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app')): https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app" -LogFile $LogFile -ForegroundColor DarkGray
            Write-ToLogFile "Learn: $((Get-LearnReference -Url 'https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-app-registration')): https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-app-registration" -LogFile $LogFile -ForegroundColor DarkGray
            Write-ToLogFile '' -LogFile $LogFile
        }
    }

    return [pscustomobject]@{
        TenantId        = $graphContext.TenantId
        Account         = $graphContext.Account
        AdminUrl        = $adminUrl
        PnPAvailable    = $pnpAvailable
        PnPRequired     = $needsPnP
        PnPClientId     = $PnPClientId
        PnPClientName   = $pnpClientName
        PnPClientSource = $pnpClientSource
        PnPIssue        = $pnpIssue
    }
}
