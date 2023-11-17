function Unprotect-DataWithAes
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]
        $CipherText,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $Key,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $InitializationVector,

        [byte[]]
        $HMAC
    )

    $aes = $null
    $memoryStream = $null
    $cryptoStream = $null
    $buffer = $null

    if ($null -ne $HMAC)
    {
        Assert-ValidHmac -Key $Key -Bytes $CipherText -Hmac $HMAC
    }

    try
    {
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider -Property @{
            Key = $Key
            IV  = $InitializationVector
        }

        # Not sure exactly how long of a buffer we'll need to hold the decrypted data. Twice
        # the ciphertext length should be more than enough.
        $buffer = New-Object PowerShellUtils.PinnedArray[byte](2 * $CipherText.Count)

        $memoryStream = New-Object System.IO.MemoryStream(, $buffer)
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream(
            $memoryStream, $aes.CreateDecryptor(), 'Write'
        )

        $cryptoStream.Write($CipherText, 0, $CipherText.Count)
        $cryptoStream.FlushFinalBlock()

        $plainText = New-Object PowerShellUtils.PinnedArray[byte]($memoryStream.Position)
        [Array]::Copy($buffer.Array, $plainText.Array, $memoryStream.Position)

        return New-Object psobject -Property @{
            PlainText = $plainText
        }
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
        if ($buffer -is [IDisposable])
        {
            $buffer.Dispose()
        }
    }
}
