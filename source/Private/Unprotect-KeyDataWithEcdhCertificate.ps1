function Unprotect-KeyDataWithEcdhCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $KeyData,

        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    $doFinallyBlock = $true
    $key = $null
    $iv = $null
    $derivedKey = $null
    $publicKey = $null
    $privateKey = $null
    $ecdh = $null

    try
    {
        $privateKey = [Security.Cryptography.X509Certificates.X509Certificate2ExtensionMethods]::GetCngPrivateKey($Certificate)

        if ($privateKey.AlgorithmGroup -ne [System.Security.Cryptography.CngAlgorithmGroup]::ECDiffieHellman)
        {
            throw "Certificate '$($Certificate.Thumbprint)' contains a non-ECDH key pair."
        }

        if ($null -eq $KeyData.EcdhPublicKey -or $null -eq $KeyData.EcdhIV)
        {
            throw "Certificate '$($Certificate.Thumbprint)' is a valid ECDH certificate, but the stored KeyData structure is missing the public key and/or IV used during encryption."
        }

        $publicKey = [System.Security.Cryptography.CngKey]::Import($KeyData.EcdhPublicKey, [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
        $ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]$privateKey

        $derivedKey = New-Object PowerShellUtils.PinnedArray[byte](, ($ecdh.DeriveKeyMaterial($publicKey) | Select-Object -First 32))
        if ($derivedKey.Count -ne 32)
        {
            # This shouldn't happen, but just in case...
            throw "Error: Key material derived from ECDH certificate $($Certificate.Thumbprint) was less than the required 32 bytes"
        }

        $key = (Unprotect-DataWithAes -CipherText $KeyData.Key -Key $derivedKey -InitializationVector $KeyData.EcdhIV).PlainText
        $iv = (Unprotect-DataWithAes -CipherText $KeyData.IV -Key $derivedKey -InitializationVector $KeyData.EcdhIV).PlainText

        $doFinallyBlock = $false

        return New-Object psobject -Property @{
            Key = $key
            IV  = $iv
        }
    }
    catch
    {
        throw
    }
    finally
    {
        if ($doFinallyBlock)
        {
            if ($key -is [IDisposable])
            {
                $key.Dispose()
            }
            if ($iv -is [IDisposable])
            {
                $iv.Dispose()
            }
        }

        if ($derivedKey -is [IDisposable])
        {
            $derivedKey.Dispose()
        }
        if ($privateKey -is [IDisposable])
        {
            $privateKey.Dispose()
        }
        if ($publicKey -is [IDisposable])
        {
            $publicKey.Dispose()
        }
        if ($null -ne $ecdh)
        {
            $ecdh.Clear()
        }
    }
}
