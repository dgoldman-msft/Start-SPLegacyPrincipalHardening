function Install-RequiredModule {
    <#
    .SYNOPSIS
        Ensures a PowerShell module is installed (from the PowerShell Gallery if missing) and imported.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [version]$MinimumVersion,

        [Parameter(Mandatory)]
        [string]$LogFile
    )

    $installed = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $installed -or ($MinimumVersion -and $installed.Version -lt $MinimumVersion)) {
        Write-ToLogFile "Module '$Name' not found (or too old) - installing from the PowerShell Gallery for the current user..." -LogFile $LogFile -ForegroundColor Yellow
        $installParameters = @{
            Name         = $Name
            Scope        = 'CurrentUser'
            Repository   = 'PSGallery'
            Force        = $true
            AllowClobber = $true
            ErrorAction  = 'Stop'
        }
        if ($MinimumVersion) { $installParameters.MinimumVersion = $MinimumVersion }
        Install-Module @installParameters
        Write-ToLogFile "Installed module '$Name'." -LogFile $LogFile -ForegroundColor Green
    }

    $loaded = Get-Module -Name $Name
    if (-not $loaded) {
        Write-ToLogFile "Importing module '$Name'..." -LogFile $LogFile -LogOnly
        Import-Module -Name $Name -ErrorAction Stop
        $loaded = Get-Module -Name $Name
    }
    else {
        Write-ToLogFile "Module '$Name' $($loaded.Version) already imported." -LogFile $LogFile -LogOnly
    }

    return $loaded
}
