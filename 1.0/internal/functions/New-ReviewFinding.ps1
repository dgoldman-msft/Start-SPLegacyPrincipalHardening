function New-ReviewFinding {
    <#
    .SYNOPSIS
        Records a finding in the run context and logs it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context,

        [Parameter(Mandatory)]
        [string]$Task,

        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Severity,

        [Parameter(Mandatory)]
        [ValidateSet('Compliant', 'NonCompliant', 'Info', 'Failed', 'Manual', 'Skipped')]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Resource,

        [Parameter(Mandatory)]
        [string]$Finding,

        [string]$Detail,

        [string]$Recommendation,

        [string[]]$Reference,

        [switch]$LogOnly
    )

    $actionable = $Status -in 'NonCompliant', 'Manual', 'Skipped', 'Failed' -or [bool]$Recommendation
    $referenceLinks = @()
    if ($Reference) {
        $referenceLinks = @($Reference | ForEach-Object { [pscustomobject]@{ Url = $_; Title = (Get-LearnReference -Url $_) } })
    }
    elseif ($actionable) {
        $referenceLinks = @(Get-LearnReference -Task $Task -Text "$Resource $Finding $Recommendation")
    }

    $record = [pscustomobject]@{
        Timestamp      = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Task           = $Task
        Severity       = $Severity
        Status         = $Status
        Resource       = $Resource
        Finding        = $Finding
        Detail         = $Detail
        Recommendation = $Recommendation
        Reference      = (@($referenceLinks | ForEach-Object { $_.Url }) -join ' ; ')
    }
    $Context.Findings.Add($record)

    $color = switch ($Status) {
        'Compliant' { 'Green' }
        'Failed' { 'Red' }
        'Manual' { 'Yellow' }
        'Skipped' { 'DarkYellow' }
        'NonCompliant' { if ($Severity -in 'Critical', 'High') { 'Red' } else { 'Yellow' } }
        default { 'Gray' }
    }

    Write-ToLogFile "  [$Task] [$Status/$Severity] $Resource - $Finding" -LogFile $Context.LogFile -ForegroundColor $color -LogOnly:$LogOnly
    # Failure causes are shown on the console too; other detail stays in the log
    if ($Detail) { Write-ToLogFile "      $Detail" -LogFile $Context.LogFile -ForegroundColor $color -LogOnly:($Status -ne 'Failed' -or $LogOnly) }
    if ($Recommendation -and $Status -in 'NonCompliant', 'Manual') {
        Write-ToLogFile "      Recommendation: $Recommendation" -LogFile $Context.LogFile -LogOnly
    }
    foreach ($link in $referenceLinks) {
        $linkText = if ($link.Title) { "$($link.Title): $($link.Url)" } else { $link.Url }
        Write-ToLogFile "      Learn: $linkText" -LogFile $Context.LogFile -ForegroundColor DarkGray -LogOnly
        # On the console each article is shown once per task to keep the output readable; the log and reports list every one
        $shownKey = "LearnShown|$Task|$($link.Url)"
        if (-not $LogOnly -and $actionable -and $Context.Cache -is [hashtable] -and -not $Context.Cache.ContainsKey($shownKey)) {
            $Context.Cache[$shownKey] = $true
            Write-Host "      Learn: $linkText" -ForegroundColor DarkGray
        }
    }
}
