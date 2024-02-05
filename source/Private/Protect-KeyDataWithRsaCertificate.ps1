function Protect-KeyDataWithRsaCertificate
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

    $useOAEP = -not $UseLegacyPadding

    try
    {
        if ($Certificate.PublicKey.Key -is [System.Security.Cryptography.RSA])
        {
            if ($PSVersionTable.PSEdition -eq 'Core')
            {
                if ($useOAEP)
                {
                    New-Object psobject -Property @{
                        Key           = $Certificate.PublicKey.Key.Encrypt($key, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
                        IV            = $Certificate.PublicKey.Key.Encrypt($InitializationVector, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
                        Thumbprint    = $Certificate.Thumbprint
                        LegacyPadding = [bool] $UseLegacyPadding
                    }
                }
                else
                {
                    New-Object psobject -Property @{
                        Key           = $Certificate.PublicKey.Key.Encrypt($key, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
                        IV            = $Certificate.PublicKey.Key.Encrypt($InitializationVector, [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1)
                        Thumbprint    = $Certificate.Thumbprint
                        LegacyPadding = [bool] $UseLegacyPadding
                    }
                }
            }
            else
            {
                New-Object psobject -Property @{
                    Key           = $Certificate.PublicKey.Key.Encrypt($key, $useOAEP)
                    IV            = $Certificate.PublicKey.Key.Encrypt($InitializationVector, $useOAEP)
                    Thumbprint    = $Certificate.Thumbprint
                    LegacyPadding = $UseLegacyPadding
                }
            }
        }
        else
        {
            if (-not $useOAEP)
            {
                throw 'RSA encryption with PKCS#1 v1.5 padding is not supported with CNG keys.'
            }

            New-Object psobject -Property @{
                Key           = $Certificate.PublicKey.Key.Encrypt($key, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
                IV            = $Certificate.PublicKey.Key.Encrypt($InitializationVector, [System.Security.Cryptography.RSAEncryptionPadding]::OaepSHA1)
                Thumbprint    = $Certificate.Thumbprint
                LegacyPadding = $UseLegacyPadding
            }
        }
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }
}
