function Test-KeyEncryptionCertificate
{
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        $CertificateGroup,

        [switch]
        $RequirePrivateKey
    )

    process
    {
        $Certificate = $CertificateGroup[0]

        $isEccCertificate = $Certificate.GetKeyAlgorithm() -eq $script:EccAlgorithmOid

        if (($Certificate.PublicKey.Key -isnot [System.Security.Cryptography.RSACryptoServiceProvider] -and
                $Certificate.PublicKey.Key -isnot [System.Security.Cryptography.RSACng]) -and
            -not $isEccCertificate)
        {
            Write-Error "Certficiate '$($Certificate.Thumbprint)' is not an RSA or ECDH certificate."
            return
        }

        if ($isEccCertificate)
        {
            $neededKeyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyAgreement
        }
        else
        {
            $neededKeyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
        }

        $keyUsageFlags = 0

        foreach ($extension in $Certificate.Extensions)
        {
            if ($extension -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension])
            {
                $keyUsageFlags = $keyUsageFlags -bor $extension.KeyUsages
            }
        }

        if (($keyUsageFlags -band $neededKeyUsage) -ne $neededKeyUsage)
        {
            Write-Error "Certificate '$($Certificate.Thumbprint)' does not have the required $($neededKeyUsage.ToString()) Key Usage flag."
            return
        }

        if ($RequirePrivateKey)
        {
            $Certificate = $CertificateGroup |
                Where-Object { Test-PrivateKey -Certificate $_ } |
                    Select-Object -First 1

            if ($null -eq $Certificate)
            {
                Write-Error "Could not find private key for certificate '$($CertificateGroup[0].Thumbprint)'."
                return
            }
        }

        $Certificate

    }

}
