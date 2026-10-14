function Connect-GraphSession {
    <#
    .SYNOPSIS
        Connects to Microsoft Graph, reusing an existing session when the tenant and scopes already match.
    #>
    [CmdletBinding()]
    param(
        [string]$TenantId,

        [Parameter(Mandatory)]
        [string[]]$Scope,

        [Parameter(Mandatory)]
        [string]$LogFile
    )

    Install-RequiredModule -Name 'Microsoft.Graph.Authentication' -MinimumVersion '2.0.0' -LogFile $LogFile | Out-Null

    $context = Get-MgContext
    $requiredScopes = @($Scope | Sort-Object -Unique)

    if ($context) {
        $tenantMatches = (-not $TenantId) -or ($context.TenantId -eq $TenantId)
        if (-not $tenantMatches -and $TenantId -notmatch '^[0-9a-fA-F-]{36}$') {
            try {
                $organization = Invoke-GraphWithRetry -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=verifiedDomains' -LogFile $LogFile
                $tenantMatches = @($organization.value[0].verifiedDomains.name) -contains $TenantId
            }
            catch {
                Write-ToLogFile "Could not verify the tenant of the existing Graph session: $($_.Exception.Message)" -LogFile $LogFile -LogOnly
            }
        }

        if ($tenantMatches -and $context.AuthType -ne 'Delegated') {
            Write-ToLogFile "Reusing existing Microsoft Graph $($context.AuthType) session (tenant $($context.TenantId)); scope check skipped." -LogFile $LogFile -ForegroundColor Green
            return $context
        }

        $missingScopes = @($requiredScopes | Where-Object { $_ -notin $context.Scopes })
        if ($tenantMatches -and $missingScopes.Count -eq 0) {
            Write-ToLogFile "Reusing existing Microsoft Graph session ($($context.Account), tenant $($context.TenantId))." -LogFile $LogFile -ForegroundColor Green
            return $context
        }

        if ($tenantMatches) {
            Write-ToLogFile "Existing Graph session is missing scopes: $($missingScopes -join ', '). Reconnecting with the combined scope set..." -LogFile $LogFile -ForegroundColor Yellow
            $requiredScopes = @($requiredScopes + $context.Scopes | Sort-Object -Unique)
        }
        else {
            Write-ToLogFile "Existing Graph session targets a different tenant ($($context.TenantId)). Reconnecting..." -LogFile $LogFile -ForegroundColor Yellow
        }
    }

    $connectParameters = @{
        Scopes       = $requiredScopes
        NoWelcome    = $true
        ErrorAction  = 'Stop'
    }
    if ($TenantId) { $connectParameters.TenantId = $TenantId }

    Write-ToLogFile "Connecting to Microsoft Graph (interactive) with $($requiredScopes.Count) scope(s)..." -LogFile $LogFile -ForegroundColor Cyan
    Connect-MgGraph @connectParameters
    $context = Get-MgContext
    Write-ToLogFile "Connected to Microsoft Graph as $($context.Account) (tenant $($context.TenantId))." -LogFile $LogFile -ForegroundColor Green
    return $context
}
