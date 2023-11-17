
function Protect-KeyDataWithCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [byte[]]
        $Key,

        [byte[]]
        $InitializationVector,

        [switch] $UseLegacyPadding
    )

    if ($Certificate.PublicKey.Key -is [System.Security.Cryptography.RSACryptoServiceProvider] -or $Certificate.PublicKey.Key -is [System.Security.Cryptography.RSACng])
    {
        Protect-KeyDataWithRsaCertificate -Certificate $Certificate -Key $Key -InitializationVector $InitializationVector -UseLegacyPadding:$UseLegacyPadding
    }
    elseif ($Certificate.GetKeyAlgorithm() -eq $script:EccAlgorithmOid)
    {
        Protect-KeyDataWithEcdhCertificate -Certificate $Certificate -Key $Key -InitializationVector $InitializationVector
    }
}
