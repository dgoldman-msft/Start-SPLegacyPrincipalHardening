function Invoke-GraphPaged {
    <#
    .SYNOPSIS
        Follows @odata.nextLink and returns every item of a Microsoft Graph collection as an array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Uri,

        [int]$MaxItems = 0,

        [Parameter(Mandatory)]
        [string]$LogFile
    )

    $items = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    while ($nextUri) {
        $response = Invoke-GraphWithRetry -Method GET -Uri $nextUri -LogFile $LogFile
        foreach ($item in @($response.value)) {
            if ($null -ne $item) { $items.Add($item) }
        }
        if ($MaxItems -gt 0 -and $items.Count -ge $MaxItems) { break }
        $nextUri = $response.'@odata.nextLink'
    }

    return $items.ToArray()
}
