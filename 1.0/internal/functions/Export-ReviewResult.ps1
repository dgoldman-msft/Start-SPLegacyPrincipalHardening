function Export-ReviewResult {
    <#
    .SYNOPSIS
        Writes findings, per-task datasets and a JSON summary to the output folder and logs a run summary.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    $findings = @($Context.Findings)
    $findingsPath = Join-Path $Context.OutputPath "Findings_$($Context.RunId).csv"
    $findings | Export-Csv -LiteralPath $findingsPath -NoTypeInformation -Encoding utf8
    Write-ToLogFile "Findings written to $findingsPath" -LogFile $Context.LogFile -ForegroundColor Cyan

    $datasetPaths = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $Context.Datasets.Keys) {
        $rows = @($Context.Datasets[$name])
        if ($rows.Count -eq 0) { continue }
        $path = Join-Path $Context.OutputPath "${name}_$($Context.RunId).csv"
        $rows | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding utf8
        $datasetPaths.Add($path)
        Write-ToLogFile "Dataset '$name' ($($rows.Count) rows) written to $path" -LogFile $Context.LogFile -ForegroundColor Cyan
    }

    $summary = [ordered]@{
        RunId     = $Context.RunId
        Tenant    = $Context.TenantId
        ReadOnly  = $true
        Tasks     = $Context.Tasks
        Prerequisites = @($findings | Where-Object Task -eq 'Prerequisites' | ForEach-Object { [ordered]@{ Status = $_.Status; Finding = $_.Finding; Recommendation = $_.Recommendation } })
        ByStatus  = @($findings | Group-Object Status | ForEach-Object { [ordered]@{ Status = $_.Name; Count = $_.Count } })
        BySeverityNonCompliant = @($findings | Where-Object Status -eq 'NonCompliant' | Group-Object Severity | ForEach-Object { [ordered]@{ Severity = $_.Name; Count = $_.Count } })
    }
    $summaryPath = Join-Path $Context.OutputPath "Summary_$($Context.RunId).json"
    $summary | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $summaryPath -Encoding utf8

    $recommendationsPath = Join-Path $Context.OutputPath "Recommendations_$($Context.RunId).html"
    $null = New-RecommendationReport -Finding $findings -Path $recommendationsPath -TenantId $Context.TenantId -RunId $Context.RunId
    Write-ToLogFile "Recommendations report written to $recommendationsPath" -LogFile $Context.LogFile -ForegroundColor Cyan

    Write-ToLogFile "`n================ SUMMARY ================" -LogFile $Context.LogFile -ForegroundColor Cyan
    $table = $findings | Group-Object Task | ForEach-Object {
        $group = $_.Group
        [pscustomobject]@{
            Task           = $_.Name
            NonCompliant   = @($group | Where-Object Status -eq 'NonCompliant').Count
            Compliant      = @($group | Where-Object Status -eq 'Compliant').Count
            Manual         = @($group | Where-Object Status -eq 'Manual').Count
            Failed         = @($group | Where-Object Status -eq 'Failed').Count
            Skipped        = @($group | Where-Object Status -eq 'Skipped').Count
        }
    }
    foreach ($line in (($table | Format-Table -AutoSize | Out-String) -split "`r?`n")) {
        if ($line.Trim()) { Write-ToLogFile $line -LogFile $Context.LogFile }
    }

    $prerequisiteIssues = @($findings | Where-Object { $_.Task -eq 'Prerequisites' -and $_.Status -eq 'Skipped' })
    foreach ($issue in $prerequisiteIssues) {
        Write-ToLogFile "`n!! NOT FULLY ASSESSED: $($issue.Finding)" -LogFile $Context.LogFile -ForegroundColor Red
        Write-ToLogFile "   Fix: $($issue.Recommendation)" -LogFile $Context.LogFile -ForegroundColor Yellow
        foreach ($url in ("$($issue.Reference)" -split '\s*;\s*' | Where-Object { $_ })) {
            Write-ToLogFile "   Learn: $url" -LogFile $Context.LogFile -ForegroundColor DarkGray
        }
    }

    return [pscustomobject]@{
        OutputPath   = $Context.OutputPath
        LogFile      = $Context.LogFile
        FindingsCsv  = $findingsPath
        SummaryJson  = $summaryPath
        Recommendations = $recommendationsPath
        DatasetCsvs  = $datasetPaths.ToArray()
        Findings     = $findings
    }
}
