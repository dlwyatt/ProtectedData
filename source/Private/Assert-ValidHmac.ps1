function Assert-ValidHmac
{
    [OutputType([void])]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]] $Key,

        [Parameter(Mandatory = $true)]
        [byte[]] $Bytes,

        [Parameter(Mandatory = $true)]
        [byte[]] $Hmac
    )

    $recomputedHmac = Get-Hmac -Key $Key -Bytes $Bytes

    if (-not (Test-ByteArraysAreEqual $Hmac $recomputedHmac))
    {
        throw 'Decryption failed due to invalid HMAC.'
    }
}
