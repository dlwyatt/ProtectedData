function Get-EcdhPublicKey([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
{
    # If we get here, we've already verified that the certificate has the Key Agreement usage extension,
    # and that it is an ECC algorithm cert, meaning we can treat the OIDs as ECDH algorithms.  (These OIDs
    # are shared with ECDSA, for some reason, and the ECDSA magic constants are different.)

    $magic = @{
        '1.2.840.10045.3.1.7' = [uint32]0x314B4345L # BCRYPT_ECDH_PUBLIC_P256_MAGIC
        '1.3.132.0.34'        = [uint32]0x334B4345L # BCRYPT_ECDH_PUBLIC_P384_MAGIC
        '1.3.132.0.35'        = [uint32]0x354B4345L # BCRYPT_ECDH_PUBLIC_P521_MAGIC
    }

    $algorithm = Get-AlgorithmOid -Certificate $Certificate

    if (-not $magic.ContainsKey($algorithm))
    {
        throw "Certificate '$($Certificate.Thumbprint)' returned an unknown Public Key Algorithm OID: '$algorithm'"
    }

    $size = (($cert.GetPublicKey().Count - 1) / 2)

    $keyBlob = [byte[]]@(
        [System.BitConverter]::GetBytes($magic[$algorithm])
        [System.BitConverter]::GetBytes($size)
        $cert.GetPublicKey() | Select-Object -Skip 1
    )

    return [System.Security.Cryptography.CngKey]::Import($keyBlob, [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
}
