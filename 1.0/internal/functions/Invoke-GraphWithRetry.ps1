function Invoke-GraphWithRetry {
    <#
    .SYNOPSIS
        Calls Invoke-MgGraphRequest (GET only) and retries on throttling (429) and transient 5xx errors.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('GET')]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [int]$MaxRetries = 6,

        [Parameter(Mandatory)]
        [string]$LogFile
    )

    # Read-only by design: GET is the only method this module is allowed to send to Microsoft Graph
    $attempt = 0
    while ($true) {
        try {
            $requestParameters = @{
                Method     = $Method
                Uri        = $Uri
                OutputType = 'PSObject'
            }

            return Invoke-MgGraphRequest @requestParameters
        }
        catch {
            $statusCode = 0
            try { $statusCode = [int]$_.Exception.Response.StatusCode } catch {}

            if ($statusCode -in 429, 500, 502, 503, 504 -and $attempt -lt $MaxRetries) {
                $waitSeconds = 15
                try {
                    $retryAfter = $_.Exception.Response.Headers.RetryAfter.Delta.TotalSeconds
                    if ($retryAfter) { $waitSeconds = [int]$retryAfter }
                }
                catch {}

                Write-ToLogFile "  request failed ($statusCode) - retrying in $waitSeconds s..." -LogFile $LogFile -ForegroundColor Yellow
                Start-Sleep -Seconds $waitSeconds
                $attempt++
                continue
            }
            throw
        }
    }
}
