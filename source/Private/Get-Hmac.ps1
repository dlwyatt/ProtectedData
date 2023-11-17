function Get-Hmac
{
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]] $Key,

        [Parameter(Mandatory = $true)]
        [byte[]] $Bytes
    )

    $hmac = $null
    $sha = $null

    try
    {
        $sha = New-Object System.Security.Cryptography.SHA256CryptoServiceProvider
        $hmac = New-Object PowerShellUtils.FipsHmacSha256(, $sha.ComputeHash($Key))
        return , $hmac.ComputeHash($Bytes)
    }
    finally
    {
        if ($null -ne $hmac)
        {
            $hmac.Clear()
        }
        if ($null -ne $sha)
        {
            $sha.Clear()
        }
    }
}
