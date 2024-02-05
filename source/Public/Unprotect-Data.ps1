function Unprotect-Data
{
    <#
    .Synopsis
       Decrypts an object that was produced by the Protect-Data command.
    .DESCRIPTION
       Decrypts an object that was produced by the Protect-Data command. If a Certificate is used to perform the decryption, it must be installed in either the local computer or current user's certificate stores (with its private key), and the current user must have permission to use that key.
    .PARAMETER InputObject
       The ProtectedData object that is to be decrypted.
    .PARAMETER Certificate
       An RSA or ECDH certificate that will be used to decrypt the data.  You must have the certificate's private key, and it must be one of the certificates that was used to encrypt the data.  You can pass an X509Certificate2 object to this parameter, or you can pass in a string which contains either a path to a certificate file on the file system, a path to the certificate in the Certificate provider, or a certificate thumbprint (in which case the certificate provider will be searched to find the certificate.)
    .PARAMETER Password
       A SecureString containing a password that will be used to derive an encryption key. One of the InputObject's KeyData objects must be protected with this password.
    .PARAMETER SkipCertificateValidation
       Deprecated parameter, which will be removed in a future release.  Specifying this switch will generate a warning.
    .EXAMPLE
       $decryptedObject = $encryptedObject | Unprotect-Data -Password (Read-Host -AsSecureString -Prompt 'Enter password to decrypt the data')

       Decrypts the contents of $encryptedObject and outputs an object of the same type as what was originally passed to Protect-Data. Uses a password to decrypt the object instead of a certificate.
    .INPUTS
       PSObject

       The input object should be a copy of an object that was produced by Protect-Data.
    .OUTPUTS
       Object

       Object may be any type returned by Get-ProtectedDataSupportedTypes. Specifically, it will be an object of the type specified in the InputObject's Type property.
    .LINK
        Protect-Data
    .LINK
        Add-ProtectedDataCredential
    .LINK
        Remove-ProtectedDataCredential
    .LINK
        Get-ProtectedDataSupportedTypes
    #>

    [CmdletBinding(DefaultParameterSetName = 'Certificate')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateScript({
                if (-not (Test-IsProtectedData -InputObject $_))
                {
                    throw 'InputObject argument must be a ProtectedData object.'
                }

                if ($null -eq $_.CipherText -or $_.CipherText.Count -eq 0)
                {
                    throw 'Protected data object contained no cipher text.'
                }

                $type = $_.Type -as [type]

                if ($null -eq $type -or (Get-ProtectedDataSupportedTypes) -notcontains $type)
                {
                    throw "Protected data object specified an invalid type. Type must be one of: $((Get-ProtectedDataSupportedTypes) -join ', ')"
                }

                return $true
            })]
        $InputObject,

        [Parameter(ParameterSetName = 'Certificate')]
        [object]
        $Certificate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Password')]
        [System.Security.SecureString]
        $Password,

        [Parameter()]
        [switch]
        $SkipCertificateVerification
    )

    begin
    {
        if ($PSBoundParameters.ContainsKey('SkipCertificateVerification'))
        {
            Write-Warning 'The -SkipCertificateVerification switch has been deprecated, and the module now treats that as its default behavior.  This switch will be removed in a future release.'
        }

        $cert = $null

        if ($Certificate)
        {
            try
            {
                $cert = ConvertTo-X509Certificate2 -InputObject $Certificate -ErrorAction Stop

                $params = @{
                    CertificateGroup  = $cert
                    RequirePrivateKey = $true
                }

                $cert = Test-KeyEncryptionCertificate @params -ErrorAction Stop
            }
            catch
            {
                throw
            }
        }
    }

    process
    {
        $plainText = $null
        $aes = $null
        $key = $null
        $iv = $null

        if ($null -ne $Password)
        {
            $params = @{ Password = $Password }
        }
        else
        {
            if ($null -eq $cert)
            {
                $paths = 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\My'

                $cert = :outer foreach ($path in $paths)
                {
                    foreach ($keyData in $InputObject.KeyData)
                    {
                        if ($keyData.Thumbprint)
                        {
                            $certObject = $null
                            try
                            {
                                $certObject = Get-KeyEncryptionCertificate -Path $path -CertificateThumbprint $keyData.Thumbprint -RequirePrivateKey -ErrorAction $IgnoreError
                            }
                            catch
                            {
                            }

                            if ($null -ne $certObject)
                            {
                                $certObject
                                break outer
                            }
                        }
                    }
                }
            }

            if ($null -eq $cert)
            {
                Write-Error -Message 'No decryption certificate for the specified InputObject was found.' -TargetObject $InputObject
                return
            }

            $params = @{
                Certificate = $cert
            }
        }

        try
        {
            $result = Unprotect-MatchingKeyData -InputObject $InputObject @params
            $key = $result.Key
            $iv = $result.IV

            if ($null -eq $InputObject.HMAC)
            {
                throw 'Input Object contained no HMAC code.'
            }

            $hmac = $InputObject.HMAC

            $plainText = (Unprotect-DataWithAes -CipherText $InputObject.CipherText -Key $key -InitializationVector $iv -HMAC $hmac).PlainText

            ConvertFrom-ByteArray -ByteArray $plainText -Type $InputObject.Type -ByteCount $plainText.Count
        }
        catch
        {
            Write-Error -ErrorRecord $_
            return
        }
        finally
        {
            if ($plainText -is [IDisposable])
            {
                $plainText.Dispose()
            }
            if ($key -is [IDisposable])
            {
                $key.Dispose()
            }
            if ($iv -is [IDisposable])
            {
                $iv.Dispose()
            }
        }

    }

}
