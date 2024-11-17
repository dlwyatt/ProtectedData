
function Protect-KeyDataWithCertificate
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
        $InitializationVector,

        [Parameter()]
        [switch]
        $UseLegacyPadding
    )

    if ($Certificate.PublicKey.Key -is [System.Security.Cryptography.RSA])
    {
        Protect-KeyDataWithRsaCertificate -Certificate $Certificate -Key $Key -InitializationVector $InitializationVector -UseLegacyPadding:$UseLegacyPadding
    }
    elseif ($Certificate.GetKeyAlgorithm() -eq $script:EccAlgorithmOid)
    {
        Protect-KeyDataWithEcdhCertificate -Certificate $Certificate -Key $Key -InitializationVector $InitializationVector
    }
    else
    {
        Write-Error "The certificate '$($Certificate.Thumbprint)' does not contain a supported public key algorithm."
    }
}
