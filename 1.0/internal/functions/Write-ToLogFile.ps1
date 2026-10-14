function Write-ToLogFile {
    <#
    .SYNOPSIS
        Single logging entry point for the module. Writes to the console and the log file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string]$StringObject,

        [Parameter(Mandatory)]
        [string]$LogFile,

        [System.ConsoleColor]$ForegroundColor,

        [switch]$LogOnly
    )

    $targetDirectory = Split-Path -Path $LogFile -Parent
    if ($targetDirectory -and -not (Test-Path -LiteralPath $targetDirectory)) {
        New-Item -Path $targetDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    if (-not $LogOnly -and $StringObject -ne '') {
        if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
            Write-Host $StringObject -ForegroundColor $ForegroundColor
        }
        else {
            Write-Host $StringObject
        }
    }

    if ($StringObject -eq '') {
        Add-Content -LiteralPath $LogFile -Value '' -Encoding utf8
        return
    }

    $content = $StringObject
    while ($content.StartsWith("`n")) {
        Add-Content -LiteralPath $LogFile -Value '' -Encoding utf8
        $content = $content.Substring(1)
    }

    if ($content) {
        Add-Content -LiteralPath $LogFile -Value "$(Get-TimeStamp) $content" -Encoding utf8
    }
}
