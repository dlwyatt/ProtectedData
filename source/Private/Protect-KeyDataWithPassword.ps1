function Protect-KeyDataWithPassword
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]
        $Password,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $Key,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $InitializationVector,

        [Parameter()]
        [ValidateRange(1, 2147483647)]
        [int]
        $IterationCount = 50000
    )

    $keyGen = $null
    $ephemeralKey = $null
    $ephemeralIV = $null

    try
    {
        $keyGen = Get-KeyGenerator -Password $Password -IterationCount $IterationCount
        $ephemeralKey = New-Object PowerShellUtils.PinnedArray[byte](, $keyGen.GetBytes(32))
        $ephemeralIV = New-Object PowerShellUtils.PinnedArray[byte](, $keyGen.GetBytes(16))

        $hashSalt = Get-RandomBytes -Count 32
        $hash = Get-PasswordHash -Password $Password -Salt $hashSalt -IterationCount $IterationCount

        $encryptedKey = (Protect-DataWithAes -PlainText $Key -Key $ephemeralKey -InitializationVector $ephemeralIV -NoHMAC).CipherText
        $encryptedIV = (Protect-DataWithAes -PlainText $InitializationVector -Key $ephemeralKey -InitializationVector $ephemeralIV -NoHMAC).CipherText

        New-Object psobject -Property @{
            Key            = $encryptedKey
            IV             = $encryptedIV
            Salt           = $keyGen.Salt
            IterationCount = $keyGen.IterationCount
            Hash           = $hash
            HashSalt       = $hashSalt
        }
    }
    catch
    {
        throw
    }
    finally
    {
        if ($keyGen -is [IDisposable])
        {
            $keyGen.Dispose()
        }
        if ($ephemeralKey -is [IDisposable])
        {
            $ephemeralKey.Dispose()
        }
        if ($ephemeralIV -is [IDisposable])
        {
            $ephemeralIV.Dispose()
        }
    }

}
