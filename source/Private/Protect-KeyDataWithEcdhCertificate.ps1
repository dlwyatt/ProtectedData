function Protect-KeyDataWithEcdhCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter()]
        [byte[]]
        $Key,

        [Parameter()]
        [byte[]]
        $InitializationVector
    )

    $publicKey = $null
    $ephemeralKey = $null
    $ecdh = $null
    $derivedKey = $null

    try
    {
        $publicKey = Get-EcdhPublicKey -Certificate $cert

        $ephemeralKey = [System.Security.Cryptography.CngKey]::Create($publicKey.Algorithm)
        $ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]$ephemeralKey

        $derivedKey = New-Object PowerShellUtils.PinnedArray[byte](
            , ($ecdh.DeriveKeyMaterial($publicKey) | Select-Object -First 32)
        )

        if ($derivedKey.Count -ne 32)
        {
            # This shouldn't happen, but just in case...
            throw "Error: Key material derived from ECDH certificate $($Certificate.Thumbprint) was less than the required 32 bytes"
        }

        $ecdhIv = Get-RandomBytes -Count 16

        $encryptedKey = Protect-DataWithAes -PlainText $Key -Key $derivedKey -InitializationVector $ecdhIv -NoHMAC
        $encryptedIv = Protect-DataWithAes -PlainText $InitializationVector -Key $derivedKey -InitializationVector $ecdhIv -NoHMAC

        New-Object psobject -Property @{
            Key           = $encryptedKey.CipherText
            IV            = $encryptedIv.CipherText
            EcdhPublicKey = $ecdh.PublicKey.ToByteArray()
            EcdhIV        = $ecdhIv
            Thumbprint    = $Certificate.Thumbprint
        }
    }
    finally
    {
        if ($publicKey -is [IDisposable])
        {
            $publicKey.Dispose()
        }
        if ($ephemeralKey -is [IDisposable])
        {
            $ephemeralKey.Dispose()
        }
        if ($null -ne $ecdh)
        {
            $ecdh.Clear()
        }
        if ($derivedKey -is [IDisposable])
        {
            $derivedKey.Dispose()
        }
    }
}
