function Add-KeyData
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $Key,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $InitializationVector,

        [ValidateNotNull()]
        [AllowEmptyCollection()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        $Certificate = @(),

        [switch]
        $UseLegacyPadding,

        [ValidateNotNull()]
        [AllowEmptyCollection()]
        [System.Security.SecureString[]]
        $Password = @(),

        [ValidateRange(1, 2147483647)]
        [int]
        $PasswordIterationCount = 50000
    )

    if ($certs.Count -eq 0 -and $Password.Count -eq 0)
    {
        return
    }

    $useOAEP = -not $UseLegacyPadding

    $InputObject.KeyData += @(
        foreach ($cert in $Certificate)
        {
            $match = $InputObject.KeyData |
                Where-Object { $_.Thumbprint -eq $cert.Thumbprint }

            if ($null -ne $match)
            {
                continue
            }
            Protect-KeyDataWithCertificate -Certificate $cert -Key $Key -InitializationVector $InitializationVector -UseLegacyPadding:$UseLegacyPadding
        }

        foreach ($secureString in $Password)
        {
            $match = $InputObject.KeyData |
                Where-Object {
                    $params = @{
                        Password       = $secureString
                        Salt           = $_.HashSalt
                        IterationCount = $_.IterationCount
                    }

                    $null -ne $_.Hash -and $_.Hash -eq (Get-PasswordHash @params)
                }

            if ($null -ne $match)
            {
                continue
            }
            Protect-KeyDataWithPassword -Password $secureString -Key $Key -InitializationVector $InitializationVector -IterationCount $PasswordIterationCount
        }
    )

}
