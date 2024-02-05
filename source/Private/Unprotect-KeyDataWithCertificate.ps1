function Unprotect-KeyDataWithCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $KeyData,

        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    if ($Certificate.PublicKey.Key -is [System.Security.Cryptography.RSA])
    {
        Unprotect-KeyDataWithRsaCertificate -KeyData $KeyData -Certificate $Certificate
    }
    elseif ($Certificate.GetKeyAlgorithm() -eq $script:EccAlgorithmOid)
    {
        Unprotect-KeyDataWithEcdhCertificate -KeyData $KeyData -Certificate $Certificate
    }
    else
    {
        Write-Error "The certificate '$($Certificate.Thumbprint)' does not contain a supported public key algorithm."
    }
}
