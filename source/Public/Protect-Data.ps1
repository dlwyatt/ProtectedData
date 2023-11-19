function Protect-Data
{
    <#
    .Synopsis
       Encrypts an object using one or more digital certificates and/or passwords.
    .DESCRIPTION
       Encrypts an object using a randomly-generated AES key. AES key information is encrypted using one or more certificate public keys and/or password-derived keys, allowing the data to be securely shared among multiple users and computers.
       If certificates are used, they must be installed in either the local computer or local user's certificate stores, and the certificates' Key Usage extension must allow Key Encipherment (for RSA) or Key Agreement (for ECDH). The private keys are not required for Protect-Data.
    .PARAMETER InputObject
       The object that is to be encrypted. The object must be of one of the types returned by the Get-ProtectedDataSupportedTypes command.
    .PARAMETER Certificate
       Zero or more RSA or ECDH certificates that should be used to encrypt the data. The data can later be decrypted by using the same certificate (with its private key.)  You can pass an X509Certificate2 object to this parameter, or you can pass in a string which contains either a path to a certificate file on the file system, a path to the certificate in the Certificate provider, or a certificate thumbprint (in which case the certificate provider will be searched to find the certificate.)
    .PARAMETER UseLegacyPadding
       Optional switch specifying that when performing certificate-based encryption, PKCS#1 v1.5 padding should be used instead of the newer, more secure OAEP padding scheme.  Some certificates may not work properly with OAEP padding
    .PARAMETER Password
       Zero or more SecureString objects containing password that will be used to derive encryption keys. The data can later be decrypted by passing in a SecureString with the same value.
    .PARAMETER SkipCertificateVerification
       Deprecated parameter, which will be removed in a future release.  Specifying this switch will generate a warning.
    .PARAMETER PasswordIterationCount
       Optional positive integer value specifying the number of iteration that should be used when deriving encryption keys from the specified password(s). Defaults to 50000.
       Higher values make it more costly to crack the passwords by brute force.
    .EXAMPLE
       $encryptedObject = Protect-Data -InputObject $myString -CertificateThumbprint CB04E7C885BEAE441B39BC843C85855D97785D25 -Password (Read-Host -AsSecureString -Prompt 'Enter password to encrypt')

       Encrypts a string using a single RSA or ECDH certificate, and a password. Either the certificate or the password can be used when decrypting the data.
    .EXAMPLE
       $credential | Protect-Data -CertificateThumbprint 'CB04E7C885BEAE441B39BC843C85855D97785D25', 'B5A04AB031C24BCEE220D6F9F99B6F5D376753FB'

       Encrypts a PSCredential object using two RSA or ECDH certificates. Either private key can be used to later decrypt the data.
    .INPUTS
       Object

       Object must be one of the types returned by the Get-ProtectedDataSupportedTypes command.
    .OUTPUTS
       PSObject

       The output object contains the following properties:

       CipherText : An array of bytes containing the encrypted data
       Type : A string representation of the InputObject's original type (used when decrypting back to the original object later.)
       KeyData : One or more structures which contain encrypted copies of the AES key used to protect the ciphertext, and other identifying information about the way this copy of the keys was protected, such as Certificate Thumbprint, Password Hash, Salt values, and Iteration count.
    .LINK
        Unprotect-Data
    .LINK
        Add-ProtectedDataCredential
    .LINK
        Remove-ProtectedDataCredential
    .LINK
        Get-ProtectedDataSupportedTypes
    #>

    [CmdletBinding()]
    [OutputType([psobject])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateScript({
                if ((Get-ProtectedDataSupportedTypes) -notcontains $_.GetType() -and $null -eq ($_ -as [byte[]]))
                {
                    throw "InputObject must be one of the following types: $((Get-ProtectedDataSupportedTypes) -join ', ')"
                }

                if ($_ -is [System.Security.SecureString] -and $_.Length -eq 0)
                {
                    throw 'SecureString argument contained no data.'
                }

                return $true
            })]
        $InputObject,

        [ValidateNotNullOrEmpty()]
        [AllowEmptyCollection()]
        [object[]]
        $Certificate = @(),

        [switch]
        $UseLegacyPadding,

        [ValidateNotNull()]
        [AllowEmptyCollection()]
        [ValidateScript({
                if ($_.Length -eq 0)
                {
                    throw 'You may not pass empty SecureStrings to the Password parameter'
                }

                return $true
            })]
        [System.Security.SecureString[]]
        $Password = @(),

        [ValidateRange(1, 2147483647)]
        [int]
        $PasswordIterationCount = 50000,

        [switch]
        $SkipCertificateVerification
    )

    begin
    {
        if ($PSBoundParameters.ContainsKey('SkipCertificateVerification'))
        {
            Write-Warning 'The -SkipCertificateVerification switch has been deprecated, and the module now treats that as its default behavior.  This switch will be removed in a future release.'
        }

        $certs = @(
            foreach ($cert in $Certificate)
            {
                try
                {

                    $x509Cert = ConvertTo-X509Certificate2 -InputObject $cert -ErrorAction Stop
                    Test-KeyEncryptionCertificate -CertificateGroup $x509Cert -ErrorAction Stop
                }
                catch
                {
                    Write-Error -ErrorRecord $_
                }
            }
        )

        if ($certs.Count -eq 0 -and $Password.Count -eq 0)
        {
            throw ('None of the specified certificates could be used for encryption, and no passwords were specified.' +
                ' Data protection cannot be performed.')
        }
    }

    process
    {
        $plainText = $null
        $payload = $null

        try
        {
            $plainText = ConvertTo-PinnedByteArray -InputObject $InputObject
            $payload = Protect-DataWithAes -PlainText $plainText

            $protectedData = New-Object psobject -Property @{
                CipherText = $payload.CipherText
                HMAC       = $payload.HMAC
                Type       = $InputObject.GetType().FullName
                KeyData    = @()
            }

            $params = @{
                InputObject            = $protectedData
                Key                    = $payload.Key
                InitializationVector   = $payload.IV
                Certificate            = $certs
                Password               = $Password
                PasswordIterationCount = $PasswordIterationCount
                UseLegacyPadding       = $UseLegacyPadding
            }

            Add-KeyData @params

            if ($protectedData.KeyData.Count -eq 0)
            {
                Write-Error 'Failed to protect data with any of the supplied certificates or passwords.'
                return
            }
            else
            {
                $protectedData
            }
        }
        finally
        {
            if ($plainText -is [IDisposable])
            {
                $plainText.Dispose()
            }
            if ($null -ne $payload)
            {
                if ($payload.Key -is [IDisposable])
                {
                    $payload.Key.Dispose()
                }
                if ($payload.IV -is [IDisposable])
                {
                    $payload.IV.Dispose()
                }
            }
        }

    }

}
