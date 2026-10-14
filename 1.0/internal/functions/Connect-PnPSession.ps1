function Connect-PnPSession {
    <#
    .SYNOPSIS
        Connects PnP PowerShell to the SharePoint admin site, reusing an existing connection to the same URL.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AdminUrl,

        [string]$ClientId,

        [string]$TenantId,

        [Parameter(Mandatory)]
        [string]$LogFile
    )

    Install-RequiredModule -Name 'PnP.PowerShell' -LogFile $LogFile | Out-Null

    $existing = $null
    try { $existing = Get-PnPConnection -ErrorAction Stop } catch { $existing = $null }
    if ($existing -and $existing.Url.TrimEnd('/') -ieq $AdminUrl.TrimEnd('/')) {
        Write-ToLogFile "Reusing existing PnP connection to $AdminUrl." -LogFile $LogFile -ForegroundColor Green
        return $existing
    }

    if (-not $ClientId) {
        foreach ($variableName in 'ENTRAID_APP_ID', 'ENTRAID_CLIENT_ID', 'AZURE_CLIENT_ID') {
            $value = [Environment]::GetEnvironmentVariable($variableName)
            if ($value) { $ClientId = $value; break }
        }
    }
    if (-not $ClientId) {
        throw "PnP.PowerShell needs your own Entra app registration for interactive sign-in. Pass -PnPClientId or set `$env:ENTRAID_APP_ID. Create one with: Register-PnPEntraIDAppForInteractiveLogin -ApplicationName 'SPLegacyHardening' -Tenant <tenant>.onmicrosoft.com"
    }

    $connectParameters = @{
        Url         = $AdminUrl
        Interactive = $true
        ClientId    = $ClientId
        ErrorAction = 'Stop'
    }
    if ($TenantId) { $connectParameters.Tenant = $TenantId }

    Write-ToLogFile "Connecting PnP PowerShell to $AdminUrl (interactive)..." -LogFile $LogFile -ForegroundColor Cyan
    # No -ReturnConnection: it would not set the current connection, so later PnP cmdlets would report "not signed in".
    Connect-PnPOnline @connectParameters
    $connection = Get-PnPConnection -ErrorAction Stop
    Write-ToLogFile "Connected to SharePoint admin site $AdminUrl." -LogFile $LogFile -ForegroundColor Green
    return $connection
}
