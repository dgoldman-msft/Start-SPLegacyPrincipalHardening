function New-SPLegacyRecommendationReport {
    <#
    .SYNOPSIS
        Regenerates the HTML recommendations report from a Findings CSV produced by Start-SPLegacyPrincipalHardening.

    .DESCRIPTION
        Start-SPLegacyPrincipalHardening already writes Recommendations_<timestamp>.html at the end of every run.
        Use this command to rebuild it from an earlier run's Findings_<timestamp>.csv.

    .PARAMETER FindingsCsv
        Path to a Findings_<timestamp>.csv file.

    .PARAMETER OutputPath
        HTML file to write. Defaults to Recommendations_<timestamp>.html beside the CSV.

    .EXAMPLE
        New-SPLegacyRecommendationReport -FindingsCsv .\Findings_20261014_124258.csv
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
        [string]$FindingsCsv,

        [string]$OutputPath
    )

    $csv = Get-Item -LiteralPath $FindingsCsv
    $runId = $csv.BaseName -replace '^Findings_', ''
    if (-not $OutputPath) { $OutputPath = Join-Path $csv.DirectoryName "Recommendations_$runId.html" }

    $tenantId = ''
    $summaryPath = Join-Path $csv.DirectoryName "Summary_$runId.json"
    if (Test-Path -LiteralPath $summaryPath) {
        $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
        $tenantId = $summary.Tenant
    }

    $logFile = Join-Path $csv.DirectoryName "Recommendations_$runId.log"
    $path = New-RecommendationReport -Finding @(Import-Csv -LiteralPath $csv.FullName) -Path $OutputPath -TenantId $tenantId -RunId $runId
    Write-ToLogFile "Recommendations written to $path" -LogFile $logFile -ForegroundColor Green
    return $path
}
