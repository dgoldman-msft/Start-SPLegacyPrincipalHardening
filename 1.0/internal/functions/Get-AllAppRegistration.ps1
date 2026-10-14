function Get-AllAppRegistration {
    <#
    .SYNOPSIS
        Returns a hashtable of appId -> application registration (credentials only), cached for the run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    if ($Context.Cache.ContainsKey('AppRegistrations')) { return $Context.Cache['AppRegistrations'] }

    $uri = 'https://graph.microsoft.com/v1.0/applications?$select=appId,displayName,passwordCredentials,keyCredentials&$top=999'
    $map = @{}
    try {
        foreach ($app in @(Invoke-GraphPaged -Uri $uri -LogFile $Context.LogFile)) { $map[$app.appId] = $app }
    }
    catch {
        Write-ToLogFile "Could not read app registrations: $($_.Exception.Message)" -LogFile $Context.LogFile -ForegroundColor Yellow
    }

    $Context.Cache['AppRegistrations'] = $map
    return $map
}
