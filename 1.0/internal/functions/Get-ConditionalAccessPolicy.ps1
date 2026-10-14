function Get-ConditionalAccessPolicy {
    <#
    .SYNOPSIS
        Returns all Conditional Access policies, cached for the run.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Context
    )

    if ($Context.Cache.ContainsKey('CaPolicies')) { return $Context.Cache['CaPolicies'] }
    $policies = @(Invoke-GraphPaged -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' -LogFile $Context.LogFile)
    $Context.Cache['CaPolicies'] = $policies
    return $policies
}
