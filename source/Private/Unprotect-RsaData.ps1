function Unprotect-RsaData(
    [System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
    [byte[]] $CipherText,
    [switch] $UseOaepPadding)
{
    if ($Certificate.PrivateKey -is [System.Security.Cryptography.RSACryptoServiceProvider] -or $Certificate.PrivateKey -is [System.Security.Cryptography.RSACng])
    {
        if (-not $UseOaepPadding)
        {
            return New-Object PowerShellUtils.PinnedArray[byte](
                , $Certificate.PrivateKey.Decrypt($CipherText, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            )
        }
        else
        {
            return New-Object PowerShellUtils.PinnedArray[byte](
                , $Certificate.PrivateKey.Decrypt($CipherText, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
            )
        }
    }

    # By the time we get here, we've already validated that either the certificate has an RsaCryptoServiceProvider
    # object in its PrivateKey property, or we can fetch an RSA CNG key.

    $cngKey = $null
    $cngRsa = $null
    try
    {
        $cngKey = [Security.Cryptography.X509Certificates.X509Certificate2ExtensionMethods]::GetCngPrivateKey($Certificate)
        $cngRsa = [Security.Cryptography.RSACng]$cngKey

        if (-not $UseOaepPadding)
        {
            return New-Object PowerShellUtils.PinnedArray[byte](
                , $cngRsa.Decrypt($CipherText, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
            )
        }
        else
        {
            return New-Object PowerShellUtils.PinnedArray[byte](
                , $cngRsa.Decrypt($CipherText, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
            )
        }
    }
    catch
    {
        throw
    }
    finally
    {
        if ($cngKey -is [IDisposable])
        {
            $cngKey.Dispose()
        }
        if ($null -ne $cngRsa)
        {
            $cngRsa.Clear()
        }
    }
}
