function Protect-DataWithAes
{
    [CmdletBinding(DefaultParameterSetName = 'KnownKey')]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]
        $PlainText,

        [Parameter()]
        [byte[]]
        $Key,

        [Parameter()]
        [byte[]]
        $InitializationVector,

        [Parameter()]
        [switch]
        $NoHMAC
    )

    $aes = $null
    $memoryStream = $null
    $cryptoStream = $null

    try
    {
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider

        if ($null -ne $Key)
        {
            $aes.Key = $Key
        }
        if ($null -ne $InitializationVector)
        {
            $aes.IV = $InitializationVector
        }

        $memoryStream = New-Object System.IO.MemoryStream
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream(
            $memoryStream, $aes.CreateEncryptor(), 'Write'
        )

        $cryptoStream.Write($PlainText, 0, $PlainText.Count)
        $cryptoStream.FlushFinalBlock()

        $properties = @{
            CipherText = $memoryStream.ToArray()
            HMAC       = $null
        }

        $hmacKeySplat = @{
            Key = $Key
        }

        if ($null -eq $Key)
        {
            $properties['Key'] = New-Object PowerShellUtils.PinnedArray[byte](, $aes.Key)
            $hmacKeySplat['Key'] = $properties['Key']
        }

        if ($null -eq $InitializationVector)
        {
            $properties['IV'] = New-Object PowerShellUtils.PinnedArray[byte](, $aes.IV)
        }

        if (-not $NoHMAC)
        {
            $properties['HMAC'] = Get-Hmac @hmacKeySplat -Bytes $properties['CipherText']
        }

        New-Object psobject -Property $properties
    }
    finally
    {
        if ($null -ne $aes)
        {
            $aes.Clear()
        }
        if ($cryptoStream -is [IDisposable])
        {
            $cryptoStream.Dispose()
        }
        if ($memoryStream -is [IDisposable])
        {
            $memoryStream.Dispose()
        }
    }
}
