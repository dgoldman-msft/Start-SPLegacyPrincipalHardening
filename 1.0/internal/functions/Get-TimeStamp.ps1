function Get-TimeStamp {
    [CmdletBinding()]
    param()

    return '[{0:MM/dd/yy} {0:HH:mm:ss}] -' -f (Get-Date)
}
