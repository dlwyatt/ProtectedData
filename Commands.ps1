if ($PSVersionTable.PSVersion.Major -eq 2)
{
    $IgnoreError = 'SilentlyContinue'
}
else
{
    $IgnoreError = 'Ignore'
}

$script:ValidTypes = @(
    [string],
    [System.Security.SecureString],
    [System.Management.Automation.PSCredential]
    [byte[]]
)

$script:PSCredentialHeader = [byte[]](5,12,19,75,80,20,19,11,11,6,11,13)

$script:EccAlgorithmOid = '1.2.840.10045.2.1'

#region Exported functions

function Protect-Data
{
    <#
    .Synopsis
       Encrypts an object using one or more digital certificates and/or passwords.
    .DESCRIPTION
       Encrypts an object using a randomly-generated AES key. AES key information is encrypted using one or more certificate public keys and/or password-derived keys, allowing the data to be securely shared among multiple users and computers.
       If certificates are used, they must be installed in either the local computer or local user's certificate stores, and the certificates' Key Usage extension (if present) must allow Key Encipherment. The private keys are not required for Protect-Data.
    .PARAMETER InputObject
       The object that is to be encrypted. The object must be of one of the types returned by the Get-ProtectedDataSupportedTypes command.
    .PARAMETER CertificateThumbprint
       Zero or more certificate thumbprints that should be used to encrypt the data. The certificates must be installed in the local computer or current user's certificate stores, and must be RSA or ECDH certificates. The data can later be decrypted by using the same certificate (with its private key.)
    .PARAMETER Certificate
       Zero or more X509Certificate2 objects that should be used to encrypt the data.  Using this parameter instead of CertificateThumbprint can offer more flexibility, as the certificate may be loaded from a file instead of being installed in a certificate store.
    .PARAMETER UseLegacyPadding
       Optional switch specifying that when performing certificate-based encryption, PKCS#1 v1.5 padding should be used instead of the newer, more secure OAEP padding scheme.  Some certificates may not work properly with OAEP padding
    .PARAMETER Password
       Zero or more SecureString objects containing password that will be used to derive encryption keys. The data can later be decrypted by passing in a SecureString with the same value.
    .PARAMETER SkipCertificateValidation
       If specified, the command does not attempt to validate that the specified certificate(s) came from trusted publishers and have not been revoked or expired.
       This is primarily intended to allow the use of self-signed certificates.
    .PARAMETER PasswordIterationCount
       Optional positive integer value specifying the number of iteration that should be used when deriving encryption keys from the specified password(s). Defaults to 1000.
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
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateScript({
            if ($script:ValidTypes -notcontains $_.GetType() -and $null -eq ($_ -as [byte[]]))
            {
                throw "InputObject must be one of the following types: $($script:ValidTypes -join ', ')"
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
        [ValidateScript({
            if ($_ -notmatch '^[A-F\d]+$')
            {
                throw 'Certificate thumbprints must only contain hexadecimal digits (0-9 and letters A-F).'
            }

            return $true
        })]
        [string[]]
        $CertificateThumbprint = @(),

        [ValidateNotNullOrEmpty()]
        [AllowEmptyCollection()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
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

        [ValidateRange(1,2147483647)]
        [int]
        $PasswordIterationCount = 1000,

        [switch]
        $SkipCertificateVerification
    )

    begin
    {
        $certs = @(
            foreach ($thumbprint in $CertificateThumbprint)
            {
                try
                {
                    $params = @{
                        CertificateThumbprint = $thumbprint
                        SkipCertificateVerification = $SkipCertificateVerification
                        ErrorAction = 'Stop'
                    }
                    Get-KeyEncryptionCertificate @params |
                    Select-Object -First 1
                }
                catch
                {
                    Write-Error -ErrorRecord $_
                }
            }

            foreach ($cert in $Certificate)
            {
                ValidateKeyEncryptionCertificate -CertificateGroup $cert -SkipCertificateVerification:$SkipCertificateVerification
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
                Type = $InputObject.GetType().FullName
                KeyData = @()
            }

            $params = @{
                InputObject = $protectedData
                Key = $payload.Key
                IV = $payload.IV
                Certificate = $certs
                Password = $Password
                PasswordIterationCount = $PasswordIterationCount
                UseLegacyPadding = $UseLegacyPadding
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
            if ($plainText -is [IDisposable]) { $plainText.Dispose() }
            if ($null -ne $payload)
            {
                if ($payload.Key -is [IDisposable]) { $payload.Key.Dispose() }
                if ($payload.IV -is [IDisposable]) { $payload.IV.Dispose() }
            }
        }

    } # process

} # function Protect-Data

function Unprotect-Data
{
    <#
    .Synopsis
       Decrypts an object that was produced by the Protect-Data command.
    .DESCRIPTION
       Decrypts an object that was produced by the Protect-Data command. If a Certificate is used to perform the decryption, it must be installed in either the local computer or current user's certificate stores (with its private key), and the current user must have permission to use that key.
    .PARAMETER InputObject
       The ProtectedData object that is to be decrypted.
    .PARAMETER CertificateThumbprint
       Thumbprint of an RSA or ECDH certificate that will be used to decrypt the data. This certificate must be present in either the local computer or current user's certificate stores, and the current user must have permission to use the certificate's private key. One of the InputObject's KeyData objects must be protected with this certificate.
    .PARAMETER Certificate
       An X509Certificate2 object that should be used to decrypt the data.  Using this parameter instead of CertificateThumbprint can offer more flexibility, as the certificate may be loaded from a file instead of being installed in a certificate store.  One of the InputObject's KeyData objects must be protected with this certificate.
    .PARAMETER Password
       A SecureString containing a password that will be used to derive an encryption key. One of the InputObject's KeyData objects must be protected with this password.
    .PARAMETER SkipCertificateValidation
       If specified, the command does not attempt to validate that the specified certificate(s) came from trusted publishers and have not been revoked or expired.
       This is primarily intended to allow the use of self-signed certificates.
    .EXAMPLE
       $decryptedObject = Unprotect-Data -InputObject $encryptedObject -CertificateThumbprint CB04E7C885BEAE441B39BC843C85855D97785D25

       Decrypts the contents of $encryptedObject and outputs either a String or SecureString (depending on what was originally encrypted.)
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
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
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

            if ($null -eq $type -or $script:ValidTypes -notcontains $type)
            {
                throw 'Protected data object specified an invalid type. Type must be one of: ' +
                      ($script:ValidTypes -join ', ')
            }

            return $true
        })]
        $InputObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [ValidateScript({
            if ($_ -notmatch '^[A-F\d]+$')
            {
                throw 'Certificate thumbprints must only contain hexadecimal digits (0-9 and letters A-F).'
            }

            return $true
        })]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Password')]
        [System.Security.SecureString]
        $Password,

        [switch]
        $SkipCertificateVerification
    )

    begin
    {
        $cert = $null

        if ($CertificateThumbprint)
        {
            try
            {
                $params = @{
                    CertificateThumbprint = $CertificateThumbprint
                    RequirePrivateKey = $true
                    SkipCertificateVerification = $SkipCertificateVerification
                }

                $cert = Get-KeyEncryptionCertificate @params -ErrorAction Stop |
                        Select-Object -First 1
            }
            catch
            {
                throw
            }
        }
        elseif ($Certificate)
        {
            try
            {
                $params = @{
                    CertificateGroup = $Certificate
                    RequirePrivateKey = $true
                    SkipCertificateVerification = $SkipCertificateVerification
                }

                $cert = ValidateKeyEncryptionCertificate @params -ErrorAction Stop
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

        if ($null -ne $cert)
        {
            $params = @{ Certificate = $cert }
        }
        else
        {
            $params = @{ Password = $Password }
        }

        try
        {
            $result = Unprotect-MatchingKeyData -InputObject $InputObject @params
            $key = $result.Key
            $iv = $result.IV

            $plainText = (Unprotect-DataWithAes -CipherText $InputObject.CipherText -Key $key -IV $iv).PlainText

            ConvertFrom-ByteArray -ByteArray $plainText -Type $InputObject.Type -ByteCount $plainText.Count
        }
        catch
        {
            Write-Error -ErrorRecord $_
            return
        }
        finally
        {
            if ($plainText -is [IDisposable]) { $plainText.Dispose() }
            if ($key -is [IDisposable]) { $key.Dispose() }
            if ($iv -is [IDisposable]) { $iv.Dispose() }
        }

    } # process

} # function Unprotect-Data

function Add-ProtectedDataCredential
{
    <#
    .Synopsis
       Adds one or more new copies of an encryption key to an object generated by Protect-Data.
    .DESCRIPTION
       This command can be used to add new certificates and/or passwords to an object that was previously encrypted by Protect-Data. The caller must provide one of the certificates or passwords that already exists in the ProtectedData object to perform this operation.
    .PARAMETER InputObject
       The ProtectedData object which was created by an earlier call to Protect-Data.
    .PARAMETER CertificateThumbprint
       The thumbprint of a certificate which was previously used to encrypt the ProtectedData structure's key. This certificate must be installed in the local computer or current user's stores (with its private key), and the current user must have permission to use the private key.
    .PARAMETER Certificate
       An X509Certificate2 object which was previously used to encrypt the ProtectedData structure's key.  Using this parameter instead of CertificateThumbprint can offer more flexibility, as the certificate may be loaded from a file instead of being installed in a certificate store.  The certificate object must have a private key.
    .PARAMETER Password
       A password which was previously used to encrypt the ProtectedData structure's key.
    .PARAMETER NewCertificateThumbprint
       Zero or more certificate thumbprints that should be used to encrypt the data. The certificates must be installed in the local computer or current user's certificate stores, and must be RSA or ECDH certificates. The data can later be decrypted by using the same certificate (with its private key.)
    .PARAMETER NewCertificate
       Zero or more X509Certificate2 objects that should be used to encrypt the data.  Using this parameter instead of CertificateThumbprint can offer more flexibility, as the certificate may be loaded from a file instead of being installed in a certificate store.
    .PARAMETER UseLegacyPadding
       Optional switch specifying that when performing certificate-based encryption, PKCS#1 v1.5 padding should be used instead of the newer, more secure OAEP padding scheme.  Some certificates may not work properly with OAEP padding
    .PARAMETER NewPassword
       Zero or more SecureString objects containing password that will be used to derive encryption keys. The data can later be decrypted by passing in a SecureString with the same value.
    .PARAMETER SkipCertificateValidation
       If specified, the command does not attempt to validate that the specified certificate(s) came from trusted publishers and have not been revoked or expired.
       This is primarily intended to allow the use of self-signed certificates.
    .PARAMETER PasswordIterationCount
       Optional positive integer value specifying the number of iteration that should be used when deriving encryption keys from the specified password(s). Defaults to 1000.
       Higher values make it more costly to crack the passwords by brute force.
    .PARAMETER Passthru
       If this switch is used, the ProtectedData object is output to the pipeline after it is modified.
    .EXAMPLE
       Add-ProtectedDataCredential -InputObject $protectedData -CertificateThumbprint $oldThumbprint -NewCertificateThumbprint $newThumbprints -NewPassword $newPasswords

       Uses the certificate with thumbprint $oldThumbprint to add new key copies to the $protectedData object. $newThumbprints would be a string array containing thumbprints, and $newPasswords would be an array of SecureString objects.
    .INPUTS
       [PSObject]

       The input object should be a copy of an object that was produced by Protect-Data.
    .OUTPUTS
       None, or
       [PSObject]
    .LINK
        Unprotect-Data
    .LINK
        Add-ProtectedDataCredential
    .LINK
        Remove-ProtectedDataCredential
    .LINK
        Get-ProtectedDataSupportedTypes
    #>

    [CmdletBinding(DefaultParameterSetName = 'Certificate')]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateScript({
            if (-not (Test-IsProtectedData -InputObject $_))
            {
                throw 'InputObject argument must be a ProtectedData object.'
            }

            return $true
        })]
        $InputObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'Thumbprint')]
        [ValidateScript({
            if ($_ -notmatch '^[A-F\d]+$')
            {
                throw 'Certificate thumbprints must only contain hexadecimal digits (0-9 and letters A-F).'
            }

            return $true
        })]
        [string]
        $CertificateThumbprint,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(ParameterSetName = 'Certificate')]
        [Parameter(ParameterSetName = 'Thumbprint')]
        [switch]
        $UseLegacyPaddingForDecryption,

        [Parameter(Mandatory = $true, ParameterSetName = 'Password')]
        [System.Security.SecureString]
        $Password,

        [ValidateNotNullOrEmpty()]
        [AllowEmptyCollection()]
        [ValidateScript({
            if ($_ -notmatch '^[A-F\d]+$')
            {
                throw 'Certificate thumbprints must only contain hexadecimal digits (0-9 and letters A-F).'
            }

            return $true
        })]
        [string[]]
        $NewCertificateThumbprint = @(),

        [ValidateNotNull()]
        [AllowEmptyCollection()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        $NewCertificate = @(),

        [switch]
        $UseLegacyPadding,

        [ValidateNotNull()]
        [AllowEmptyCollection()]
        [System.Security.SecureString[]]
        $NewPassword = @(),

        [ValidateRange(1,2147483647)]
        [int]
        $PasswordIterationCount = 1000,

        [switch]
        $SkipCertificateVerification,

        [switch]
        $Passthru
    )

    begin
    {
        $decryptionCert = $null

        if ($PSCmdlet.ParameterSetName -eq 'Thumbprint')
        {
            try
            {
                $params = @{
                    CertificateThumbprint = $CertificateThumbprint
                    SkipCertificateVerification = $SkipCertificateVerification
                    RequirePrivateKey = $true
                }

                $decryptionCert = Get-KeyEncryptionCertificate @params -ErrorAction Stop |
                                  Select-Object -First 1
            }
            catch
            {
                throw
            }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Certificate')
        {
            try
            {
                $params = @{
                    CertificateGroup = $Certificate
                    SkipCertificateVerification = $SkipCertificateVerification
                    RequirePrivateKey = $true
                }

                $decryptionCert = ValidateKeyEncryptionCertificate @params -ErrorAction Stop
            }
            catch
            {
                throw
            }
        }

        $certs = @(
            foreach ($thumbprint in $NewCertificateThumbprint)
            {
                try
                {
                    $params = @{
                        CertificateThumbprint = $thumbprint
                        SkipCertificateVerification = $SkipCertificateVerification
                        ErrorAction = 'Stop'
                    }
                    Get-KeyEncryptionCertificate @params |
                    Select-Object -First 1
                }
                catch
                {
                    Write-Error -ErrorRecord $_
                }
            }

            foreach ($cert in $NewCertificate)
            {
                ValidateKeyEncryptionCertificate -CertificateGroup $cert -SkipCertificateVerification:$SkipCertificateVerification
            }
        )

        if ($certs.Count -eq 0 -and $NewPassword.Count -eq 0)
        {
            throw 'None of the specified certificates could be used for encryption, and no passwords were ' +
                  'specified. Data protection cannot be performed.'
        }

    } # begin

    process
    {
        if ($null -ne $decryptionCert)
        {
            $params = @{ Certificate = $decryptionCert }
        }
        else
        {
            $params = @{ Password = $Password }
        }

        $key = $null
        $iv = $null

        try
        {
            $result = Unprotect-MatchingKeyData -InputObject $InputObject @params
            $key = $result.Key
            $iv = $result.IV

            Add-KeyData -InputObject $InputObject -Key $key -IV $iv -Certificate $certs -Password $NewPassword -UseLegacyPadding:$UseLegacyPadding
        }
        catch
        {
            Write-Error -ErrorRecord $_
            return
        }
        finally
        {
            if ($key -is [IDisposable]) { $key.Dispose() }
            if ($iv -is [IDisposable]) { $iv.Dispose() }
        }

        if ($Passthru)
        {
            $InputObject
        }

    } # process

} # function Add-ProtectedDataCredential

function Remove-ProtectedDataCredential
{
    <#
    .Synopsis
       Removes copies of encryption keys from a ProtectedData object.
    .DESCRIPTION
       The KeyData copies in a ProtectedData object which are associated with the specified Certificates and/or Passwords are removed from the object, unless that removal would leave no KeyData copies behind.
    .PARAMETER InputObject
       The ProtectedData object which is to be modified.
    .PARAMETER CertificateThumbprint
       Thumbprints of the certificates that you wish to remove from this ProtectedData object.
    .PARAMETER Certificate
       X509Certificate2 objects that you wish to remove from this ProtectedData object.
    .PARAMETER Password
       Passwords in SecureString form which are to be removed from this ProtectedData object.
    .PARAMETER Passthru
       If this switch is used, the ProtectedData object will be written to the pipeline after processing is complete.
    .EXAMPLE
       $protectedData | Remove-ProtectedDataCredential -CertificateThumbprint $thumbprints -Password $passwords

       Removes certificates and passwords from an existing ProtectedData object.
    .INPUTS
       [PSObject]

       The input object should be a copy of an object that was produced by Protect-Data.
    .OUTPUTS
       None, or
       [PSObject]
    .LINK
       Protect-Data
    .LINK
       Unprotect-Data
    .LINK
       Add-ProtectedDataCredential
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateScript({
            if (-not (Test-IsProtectedData -InputObject $_))
            {
                throw 'InputObject argument must be a ProtectedData object.'
            }

            return $true
        })]
        $InputObject,

        [ValidateNotNull()]
        [AllowEmptyCollection()]
        [ValidateScript({
            if ($_ -notmatch '^[A-F\d]+$')
            {
                throw 'Certificate thumbprints must only contain hexadecimal digits (0-9 and letters A-F).'
            }

            return $true
        })]
        [string[]]
        $CertificateThumbprint,

        [ValidateNotNull()]
        [AllowEmptyCollection()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        $Certificate,

        [ValidateNotNull()]
        [AllowEmptyCollection()]
        [System.Security.SecureString[]]
        $Password,

        [switch]
        $Passthru
    )

    begin
    {
        $thumbprints = $CertificateThumbprint + ($Certificate | Select-Object -ExpandProperty Thumbprint) |
                       Get-Unique
    }

    process
    {
        $matchingKeyData = @(
            foreach ($keyData in $InputObject.KeyData)
            {
                if (Test-IsCertificateProtectedKeyData -InputObject $keyData)
                {
                    if ($thumbprints -contains $keyData.Thumbprint) { $keyData }
                }
                elseif (Test-IsPasswordProtectedKeyData -InputObject $keyData)
                {
                    foreach ($secureString in $Password)
                    {
                        $params = @{
                            Password = $secureString
                            Salt = $keyData.HashSalt
                            IterationCount = $keyData.IterationCount
                        }
                        if ($keyData.Hash -eq (Get-PasswordHash @params))
                        {
                            $keyData
                        }
                    }
                }
            }
        )

        if ($matchingKeyData.Count -eq $InputObject.KeyData.Count)
        {
            Write-Error 'You must leave at least one copy of the ProtectedData object''s keys.'
            return
        }

        $InputObject.KeyData = $InputObject.KeyData | Where-Object { $matchingKeyData -notcontains $_ }

        if ($Passthru)
        {
            $InputObject
        }
    }

} # function Remove-ProtectedDataCredential

function Get-ProtectedDataSupportedTypes
{
    <#
    .Synopsis
       Returns a list of types that can be used as the InputObject in the Protect-Data command.
    .EXAMPLE
       $types = Get-ProtectedDataSupportedTypes
    .INPUTS
       None.
    .OUTPUTS
       Type[]
    .NOTES
       This function allows you to know which InputObject types are supported by the Protect-Data and Unprotect-Data commands in this version of the module. This list may expand over time, will always be backwards-compatible with previously-encrypted data.
    .LINK
       Protect-Data
    .LINK
       Unprotect-Data
    #>

    [CmdletBinding()]
    [OutputType([Type[]])]
    param ( )

    $script:ValidTypes
}

function Get-KeyEncryptionCertificate
{
    <#
    .Synopsis
       Finds certificates which can be used by Protect-Data and related commands.
    .DESCRIPTION
       Searches the given path, and all child paths, for certificates which can be used by Protect-Data. Such certificates must support Key Encipherment usage, and by default, must not be expired and must be issued by a trusted authority.
    .PARAMETER Path
       Path which should be searched for the certifictes. Defaults to the entire Cert: drive.
    .PARAMETER CertificateThumbprint
       Thumbprints which should be included in the search. Wildcards are allowed. Defaults to '*'.
    .PARAMETER SkipCertificateVerification
       If this switch is used, the command will include certificates which are not yet valid, expired, revoked, or issued by an untrusted authority. This can be useful if you wish to use a self-signed certificate for encryption.
    .PARAMETER RequirePrivateKey
       If this switch is used, the command will only output certificates which have a usable private key on this computer.
    .EXAMPLE
       Get-KeyEncryptionCertificate -Path Cert:\CurrentUser -RequirePrivateKey -SkipCertificateVerification

       Searches for certificates which support key encipherment and have a private key installed. All matching certificates are returned, and they do not need to be verified for trust, revocation or validity period.
    .EXAMPLE
       Get-KeyEncryptionCertificate -Path Cert:\CurrentUser\TrustedPeople

       Searches the current user's Trusted People store for certificates that can be used with Protect-Data. Certificates must be current, issued by a trusted authority, and not revoked, but they do not need to have a private key available to the current user.
    .INPUTS
       None.
    .OUTPUTS
       [System.Security.Cryptography.X509Certificates.X509Certificate2]
    .LINK
       Protect-Data
    .LINK
       Unprotect-Data
    .LINK
       Add-ProtectedDataCredential
    .LINK
       Remove-ProtectedDataCredential
    #>

    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param (
        [ValidateNotNullOrEmpty()]
        [string]
        $Path = 'Cert:\',

        [string]
        $CertificateThumbprint = '*',

        [switch]
        $SkipCertificateVerification,

        [switch]
        $RequirePrivateKey
    )

    # Suppress error output if we're doing a wildcard search (unless user specifically asks for it via -ErrorAction)
    # This is a little ugly, may rework this later now that I've made Get-KeyEncryptionCertificate public. Originally
    # it was only used to search for a single thumbprint, and threw errors back to the caller if no suitable cert could
    # be found. Now I want it to also be used as a search tool for users to identify suitable certificates. Maybe just
    # needs to be two separate functions, one internal and one public.

    if (-not $PSBoundParameters.ContainsKey('ErrorAction') -and
        $CertificateThumbprint -notmatch '^[A-F\d]+$')
    {
        $ErrorActionPreference = $IgnoreError
    }

    $certGroups = Get-ChildItem -Path $Path -Recurse -Include $CertificateThumbprint -ErrorAction $IgnoreError |
                  Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] } |
                  Group-Object -Property Thumbprint

    if ($null -eq $certGroups)
    {
        throw "Certificate '$CertificateThumbprint' was not found."
    }

    $params = @{
        SkipCertificateVerification = $SkipCertificateVerification
        RequirePrivateKey = $RequirePrivateKey
    }

    foreach ($group in $certGroups)
    {
        ValidateKeyEncryptionCertificate -CertificateGroup $group.Group @params
    }

} # function Get-KeyEncryptionCertificate

#endregion

#region Helper functions

function Protect-DataWithAes
{
    [CmdletBinding(DefaultParameterSetName = 'KnownKey')]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]
        $PlainText,

        [byte[]]
        $Key,

        [byte[]]
        $IV
    )

    $aes = $null
    $memoryStream = $null
    $cryptoStream = $null

    try
    {
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider

        if ($null -ne $Key) { $aes.Key = $Key }
        if ($null -ne $IV) { $aes.IV = $IV }

        $memoryStream = New-Object System.IO.MemoryStream
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream(
            $memoryStream, $aes.CreateEncryptor(), 'Write'
        )

        $cryptoStream.Write($PlainText, 0, $PlainText.Count)
        $cryptoStream.FlushFinalBlock()


        $properties = @{
            CipherText = $memoryStream.ToArray()
        }

        if ($null -eq $Key)
        {
            $properties['Key'] = New-Object PowerShellUtils.PinnedArray[byte](,$aes.Key)
        }

        if ($null -eq $IV)
        {
            $properties['IV'] = New-Object PowerShellUtils.PinnedArray[byte](,$aes.IV)
        }

        New-Object psobject -Property $properties
    }
    finally
    {
        if ($null -ne $aes) { $aes.Clear() }
        if ($cryptoStream -is [IDisposable]) { $cryptoStream.Dispose() }
        if ($memoryStream -is [IDisposable]) { $memoryStream.Dispose() }
    }
}

function Unprotect-DataWithAes
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]
        $CipherText,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $Key,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $IV
    )

    $aes = $null
    $memoryStream = $null
    $cryptoStream = $null
    $buffer = $null

    try
    {
        $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider -Property @{
            Key = $Key
            IV = $IV
        }

        # Not sure exactly how long of a buffer we'll need to hold the decrypted data. Twice
        # the ciphertext length should be more than enough.
        $buffer = New-Object PowerShellUtils.PinnedArray[byte](2 * $CipherText.Count)

        $memoryStream = New-Object System.IO.MemoryStream(,$buffer)
        $cryptoStream = New-Object System.Security.Cryptography.CryptoStream(
            $memoryStream, $aes.CreateDecryptor(), 'Write'
        )

        $cryptoStream.Write($CipherText, 0, $CipherText.Count)
        $cryptoStream.FlushFinalBlock()

        $plainText = New-Object PowerShellUtils.PinnedArray[byte]($memoryStream.Position)
        [Array]::Copy($buffer.Array, $plainText.Array, $memoryStream.Position)

        return New-Object psobject -Property @{
            PlainText = $plainText
        }
    }
    finally
    {
        if ($null -ne $aes) { $aes.Clear() }
        if ($cryptoStream -is [IDisposable]) { $cryptoStream.Dispose() }
        if ($memoryStream -is [IDisposable]) { $memoryStream.Dispose() }
        if ($buffer -is [IDisposable]) { $buffer.Dispose() }
    }
}

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
        $IV,

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

        [ValidateRange(1,2147483647)]
        [int]
        $PasswordIterationCount = 1000
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

            if ($null -ne $match) { continue }
            Protect-KeyDataWithCertificate -Certificate $cert -Key $Key -IV $IV -UseLegacyPadding:$UseLegacyPadding
        }

        foreach ($secureString in $Password)
        {
            $match = $InputObject.KeyData |
                     Where-Object {
                        $params = @{
                            Password = $secureString
                            Salt = $_.HashSalt
                            IterationCount = $_.IterationCount
                        }

                        $null -ne $_.Hash -and $_.Hash -eq (Get-PasswordHash @params)
                     }

            if ($null -ne $match) { continue }
            Protect-KeyDataWithPassword -Password $secureString -Key $Key -IV $IV -IterationCount $PasswordIterationCount
        }
    )

} # function Add-KeyData

function Unprotect-MatchingKeyData
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $InputObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Password')]
        [System.Security.SecureString]
        $Password
    )

    if ($PSCmdlet.ParameterSetName -eq 'Certificate')
    {
        $keyData = $InputObject.KeyData |
                    Where-Object { (Test-IsCertificateProtectedKeyData -InputObject $_) -and $_.Thumbprint -eq $Certificate.Thumbprint } |
                    Select-Object -First 1

        if ($null -eq $keyData)
        {
            throw "Protected data object was not encrypted with certificate '$($Certificate.Thumbprint)'."
        }

        try
        {
            return Unprotect-KeyDataWithCertificate -KeyData $keyData -Certificate $Certificate
        }
        catch
        {
            throw
        }
    }
    else
    {
        $keyData =
        $InputObject.KeyData |
        Where-Object {
            (Test-IsPasswordProtectedKeyData -InputObject $_) -and
            $_.Hash -eq (Get-PasswordHash -Password $Password -Salt $_.HashSalt -IterationCount $_.IterationCount)
        } |
        Select-Object -First 1

        if ($null -eq $keyData)
        {
            throw 'Protected data object was not encrypted with the specified password.'
        }

        try
        {
            return Unprotect-KeyDataWithPassword -KeyData $keyData -Password $Password
        }
        catch
        {
            throw
        }
    }

} # function Unprotect-MatchingKeyData

function ValidateKeyEncryptionCertificate
{
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param (
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]
        $CertificateGroup,

        [switch]
        $SkipCertificateVerification,

        [switch]
        $RequirePrivateKey
    )

    process
    {
        $Certificate = $CertificateGroup[0]

        $isEccCertificate = $Certificate.GetKeyAlgorithm() -eq $script:EccAlgorithmOid

        if ($Certificate.PublicKey.Key -isnot [System.Security.Cryptography.RSACryptoServiceProvider] -and
            -not $isEccCertificate)
        {
            Write-Error "Certficiate '$($Certificate.Thumbprint)' is not an RSA or ECDH certificate."
            return
        }

        if (-not $SkipCertificateVerification)
        {
            if ($Certificate.NotBefore -gt (Get-Date))
            {
                Write-Error "Certificate '$($Certificate.Thumbprint)' is not yet valid."
                return
            }

            if ($Certificate.NotAfter -lt (Get-Date))
            {
                Write-Error "Certificate '$($Certificate.Thumbprint)' has expired."
                return
            }
        }

        if ($isEccCertificate)
        {
            $neededKeyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyAgreement
        }
        else
        {
            $neededKeyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
        }

        $keyUsageFound = $false
        $keyUsageFlags = 0

        foreach ($extension in $Certificate.Extensions)
        {
            if ($extension -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension])
            {
                $keyUsageFound = $true
                $keyUsageFlags = $keyUsageFlags -bor $extension.KeyUsages
            }
        }

        if ($keyUsageFound -and ($keyUsageFlags -band $neededKeyUsage) -ne $neededKeyUsage)
        {
            Write-Error ("Certificate '$($Certificate.Thumbprint)' contains a Key Usage extension which does not" +
                        "allow $($neededKeyUsage.ToString()).")
            return
        }

        if (-not $SkipCertificateVerification -and -not $Certificate.Verify())
        {
            Write-Error "Verification of certificate '$($Certificate.Thumbprint)' failed."
            return
        }

        if ($RequirePrivateKey)
        {
            $Certificate = $CertificateGroup |
                           Where-Object { TestPrivateKey -Certificate $_ } |
                           Select-Object -First 1

            if ($null -eq $Certificate)
            {
                Write-Error "Could not find private key for certificate '$($CertificateGroup[0].Thumbprint)'."
                return
            }
        }

        $Certificate

    } # process

} # function ValidateKeyEncryptionCertificate

function TestPrivateKey([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate)
{
    if (-not $Certificate.HasPrivateKey) { return $false }
    if ($Certificate.PrivateKey -is [System.Security.Cryptography.RSACryptoServiceProvider]) { return $true }

    $cngKey = $null
    try
    {
        if ([Security.Cryptography.X509Certificates.X509CertificateExtensionMethods]::HasCngKey($Certificate))
        {
            $cngKey = [Security.Cryptography.X509Certificates.X509Certificate2ExtensionMethods]::GetCngPrivateKey($Certificate)
            return $null -ne $cngKey -and
                   ($cngKey.AlgorithmGroup -eq [System.Security.Cryptography.CngAlgorithmGroup]::Rsa -or
                    $cngKey.AlgorithmGroup -eq [System.Security.Cryptography.CngAlgorithmGroup]::ECDiffieHellman)
        }
    }
    catch
    {
        return $false
    }
    finally
    {
        if ($cngKey -is [IDisposable]) { $cngKey.Dispose() }
    }
}

function Get-KeyGenerator
{
    [CmdletBinding(DefaultParameterSetName = 'CreateNew')]
    [OutputType([System.Security.Cryptography.Rfc2898DeriveBytes])]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]
        $Password,

        [Parameter(Mandatory = $true, ParameterSetName = 'RestoreExisting')]
        [byte[]]
        $Salt,

        [ValidateRange(1,2147483647)]
        [int]
        $IterationCount = 1000
    )

    $byteArray = $null

    try
    {
        $byteArray = Convert-SecureStringToPinnedByteArray -SecureString $Password

        if ($PSCmdlet.ParameterSetName -eq 'RestoreExisting')
        {
            $saltBytes = $Salt
        }
        else
        {
            $saltBytes = Get-RandomBytes -Count 32
        }

        New-Object System.Security.Cryptography.Rfc2898DeriveBytes($byteArray, $saltBytes, $IterationCount)
    }
    finally
    {
        if ($byteArray -is [IDisposable]) { $byteArray.Dispose() }
    }

} # function Get-KeyGenerator

function Get-PasswordHash
{
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]
        $Password,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $Salt,

        [ValidateRange(1, 2147483647)]
        [int]
        $IterationCount = 1000
    )

    $keyGen = $null

    try
    {
        $keyGen = Get-KeyGenerator @PSBoundParameters
        [BitConverter]::ToString($keyGen.GetBytes(32)) -replace '[^A-F\d]'
    }
    finally
    {
        if ($keyGen -is [IDisposable]) { $keyGen.Dispose() }
    }

} # function Get-PasswordHash

function Get-RandomBytes
{
    [CmdletBinding()]
    [OutputType([byte[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateRange(1,1000)]
        $Count
    )

    $rng = $null

    try
    {
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $bytes = New-Object byte[]($Count)
        $rng.GetBytes($bytes)

        ,$bytes
    }
    finally
    {
        if ($rng -is [IDisposable]) { $rng.Dispose() }
    }

} # function Get-RandomBytes

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
        $IV,

        [switch] $UseLegacyPadding
    )

    if ($Certificate.PublicKey.Key -is [System.Security.Cryptography.RSACryptoServiceProvider])
    {
        Protect-KeyDataWithRsaCertificate -Certificate $Certificate -Key $Key -IV $IV -UseLegacyPadding:$UseLegacyPadding
    }
    elseif ($Certificate.GetKeyAlgorithm() -eq $script:EccAlgorithmOid)
    {
        Protect-KeyDataWithEcdhCertificate -Certificate $Certificate -Key $Key -IV $IV
    }
}

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
        $IV,

        [switch] $UseLegacyPadding
    )

    $useOAEP = -not $UseLegacyPadding

    try
    {
        New-Object psobject -Property @{
            Key = $Certificate.PublicKey.Key.Encrypt($key, $useOAEP)
            IV = $Certificate.PublicKey.Key.Encrypt($iv, $useOAEP)
            Thumbprint = $Certificate.Thumbprint
            LegacyPadding = [bool] $UseLegacyPadding
        }
    }
    catch
    {
        Write-Error -ErrorRecord $_
    }
}

function Protect-KeyDataWithEcdhCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [byte[]]
        $Key,

        [byte[]]
        $IV
    )

    $publicKey = $null
    $ephemeralKey = $null
    $ecdh = $null
    $derivedKey = $null

    try
    {
        $publicKey = Get-EcdhPublicKey -Certificate $cert

        $ephemeralKey = [System.Security.Cryptography.CngKey]::Create($publicKey.Algorithm)
        $ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]$ephemeralKey

        $derivedKey = New-Object PowerShellUtils.PinnedArray[byte](
            ,($ecdh.DeriveKeyMaterial($publicKey) | Select-Object -First 32)
        )

        if ($derivedKey.Count -ne 32)
        {
            # This shouldn't happen, but just in case...
            throw "Error:  Key material derived from ECDH certificate $($Certificate.Thumbprint) was less than the required 32 bytes"
        }

        $ecdhIv = Get-RandomBytes -Count 16

        $encryptedKey = Protect-DataWithAes -PlainText $Key -Key $derivedKey -IV $ecdhIv
        $encryptedIv  = Protect-DataWithAes -PlainText $IV -Key $derivedKey -IV $ecdhIv

        New-Object psobject @{
            Key = $encryptedKey.CipherText
            IV = $encryptedIv.CipherText
            EcdhPublicKey = $ecdh.PublicKey.ToByteArray()
            EcdhIV = $ecdhIv
            Thumbprint = $Certificate.Thumbprint
        }
    }
    finally
    {
        if ($publicKey -is [IDisposable]) { $publicKey.Dispose() }
        if ($ephemeralKey -is [IDisposable]) { $ephemeralKey.Dispose() }
        if ($null -ne $ecdh) { $ecdh.Clear() }
        if ($derivedKey -is [IDisposable]) { $derivedKey.Dispose() }
    }
}

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


function Get-AlgorithmOid([System.Security.Cryptography.X509Certificates.X509Certificate] $Certificate)
{
    $algorithmOid = $Certificate.GetKeyAlgorithm();

    if ($algorithmOid -eq $script:EccAlgorithmOid)
    {
        $algorithmOid = DecodeBinaryOid -Bytes $Certificate.GetKeyAlgorithmParameters()
    }

    return $algorithmOid
}

function DecodeBinaryOid([byte[]] $Bytes)
{
    # Thanks to Vadims Podans (http://sysadmins.lv/) for this cool technique to take a byte array
    # and decode the OID without having to use P/Invoke to call the CryptDecodeObject function directly.

    [byte[]] $ekuBlob = @(
        48
        $Bytes.Count
        $Bytes
    )

    $asnEncodedData = New-Object System.Security.Cryptography.AsnEncodedData(,$ekuBlob)
    $enhancedKeyUsage = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($asnEncodedData, $false)

    return $enhancedKeyUsage.EnhancedKeyUsages[0].Value
}

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

    if ($Certificate.PublicKey.Key -is [System.Security.Cryptography.RSACryptoServiceProvider])
    {
        Unprotect-KeyDataWithRsaCertificate -KeyData $KeyData -Certificate $Certificate
    }
    elseif ($Certificate.GetKeyAlgorithm() -eq $script:EccAlgorithmOid)
    {
        Unprotect-KeyDataWithEcdhCertificate -KeyData $KeyData -Certificate $Certificate
    }
}

function Unprotect-KeyDataWithEcdhCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $KeyData,

        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    $doFinallyBlock = $true
    $key = $null
    $iv = $null
    $derivedKey = $null
    $publicKey = $null
    $privateKey = $null
    $ecdh = $null

    try
    {
        $privateKey = [Security.Cryptography.X509Certificates.X509Certificate2ExtensionMethods]::GetCngPrivateKey($Certificate)

        if ($privateKey.AlgorithmGroup -ne [System.Security.Cryptography.CngAlgorithmGroup]::ECDiffieHellman)
        {
            throw "Certificate '$($Certificate.Thumbprint)' contains a non-ECDH key pair."
        }

        if ($null -eq $KeyData.EcdhPublicKey -or $null -eq $KeyData.EcdhIV)
        {
            throw "Certificate '$($Certificate.Thumbprint)' is a valid ECDH certificate, but the stored KeyData structure is missing the public key and/or IV used during encryption."
        }

        $publicKey = [System.Security.Cryptography.CngKey]::Import($KeyData.EcdhPublicKey, [System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
        $ecdh = [System.Security.Cryptography.ECDiffieHellmanCng]$privateKey

        $derivedKey = New-Object PowerShellUtils.PinnedArray[byte](,($ecdh.DeriveKeyMaterial($publicKey) | Select-Object -First 32))
        if ($derivedKey.Count -ne 32)
        {
            # This shouldn't happen, but just in case...
            throw "Error:  Key material derived from ECDH certificate $($Certificate.Thumbprint) was less than the required 32 bytes"
        }

        $key = (Unprotect-DataWithAes -CipherText $KeyData.Key -Key $derivedKey -IV $KeyData.EcdhIV).PlainText
        $iv = (Unprotect-DataWithAes -CipherText $KeyData.IV -Key $derivedKey -IV $KeyData.EcdhIV).PlainText

        $doFinallyBlock = $false

        return New-Object psobject -Property @{
            Key = $key
            IV = $iv
        }
    }
    catch
    {
        throw
    }
    finally
    {
        if ($doFinallyBlock)
        {
            if ($key -is [IDisposable]) { $key.Dispose() }
            if ($iv -is [IDisposable]) { $iv.Dispose() }
        }

        if ($derivedKey -is [IDisposable]) { $derivedKey.Dispose() }
        if ($privateKey -is [IDisposable]) { $privateKey.Dispose() }
        if ($publicKey -is [IDisposable]) { $publicKey.Dispose() }
        if ($null -ne $ecdh) { $ecdh.Clear() }
    }
}

function Unprotect-KeyDataWithRsaCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $KeyData,

        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate
    )

    $useOAEP = -not $keyData.LegacyPadding

    $key = $null
    $iv = $null
    $doFinallyBlock = $true

    try
    {
        $key = DecryptRsaData -Certificate $Certificate -CipherText $keyData.Key -UseOaepPadding:$useOAEP
        $iv = DecryptRsaData -Certificate $Certificate -CipherText $keyData.IV -UseOaepPadding:$useOAEP

        $doFinallyBlock = $false

        return New-Object psobject -Property @{
            Key = $key
            IV = $iv
        }
    }
    catch
    {
        throw
    }
    finally
    {
        if ($doFinallyBlock)
        {
            if ($key -is [IDisposable]) { $key.Dispose() }
            if ($iv -is [IDisposable]) { $iv.Dispose() }
        }
    }
}

function DecryptRsaData([System.Security.Cryptography.X509Certificates.X509Certificate2] $Certificate,
                     [byte[]] $CipherText,
                     [switch] $UseOaepPadding)
{
    if ($Certificate.PrivateKey -is [System.Security.Cryptography.RSACryptoServiceProvider])
    {
        return New-Object PowerShellUtils.PinnedArray[byte](
            ,$Certificate.PrivateKey.Decrypt($CipherText, $UseOaepPadding)
        )
    }

    # By the time we get here, we've already validated that either the certificate has an RsaCryptoServiceProvider
    # object in its PrivateKey property, or we can fetch an RSA CNG key.

    $cngKey = $null
    $cngRsa = $null
    try
    {
        $cngKey = [Security.Cryptography.X509Certificates.X509Certificate2ExtensionMethods]::GetCngPrivateKey($Certificate)
        $cngRsa = [Security.Cryptography.RSACng]$cngKey
        $cngRsa.EncryptionHashAlgorithm = [System.Security.Cryptography.CngAlgorithm]::Sha1

        if (-not $UseOaepPadding)
        {
            $cngRsa.EncryptionPaddingMode = [Security.Cryptography.AsymmetricPaddingMode]::Pkcs1
        }

        return New-Object PowerShellUtils.PinnedArray[byte](
            ,$cngRsa.DecryptValue($CipherText)
        )
    }
    catch
    {
        throw
    }
    finally
    {
        if ($cngKey -is [IDisposable]) { $cngKey.Dispose() }
        if ($null -ne $cngRsa) { $cngRsa.Clear() }
    }
}

function Protect-KeyDataWithPassword
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]
        $Password,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $Key,

        [Parameter(Mandatory = $true)]
        [byte[]]
        $IV,

        [ValidateRange(1,2147483647)]
        [int]
        $IterationCount = 1000
    )

    $keyGen = $null
    $ephemeralKey = $null
    $ephemeralIV = $null

    try
    {
        $keyGen = Get-KeyGenerator -Password $Password -IterationCount $IterationCount
        $ephemeralKey = New-Object PowerShellUtils.PinnedArray[byte](,$keyGen.GetBytes(32))
        $ephemeralIV = New-Object PowerShellUtils.PinnedArray[byte](,$keyGen.GetBytes(16))

        $hashSalt = Get-RandomBytes -Count 32
        $hash = Get-PasswordHash -Password $Password -Salt $hashSalt -IterationCount $IterationCount

        $encryptedKey = (Protect-DataWithAes -PlainText $Key -Key $ephemeralKey -IV $ephemeralIV).CipherText
        $encryptedIV = (Protect-DataWithAes -PlainText $IV -Key $ephemeralKey -IV $ephemeralIV).CipherText

        New-Object psobject -Property @{
            Key = $encryptedKey
            IV = $encryptedIV
            Salt = $keyGen.Salt
            IterationCount = $keyGen.IterationCount
            Hash = $hash
            HashSalt = $hashSalt
        }
    }
    catch
    {
        throw
    }
    finally
    {
        if ($keyGen -is [IDisposable]) { $keyGen.Dispose() }
        if ($ephemeralKey -is [IDisposable]) { $ephemeralKey.Dispose() }
        if ($ephemeralIV -is [IDisposable]) { $ephemeralIV.Dispose() }
    }

} # function Protect-KeyDataWithPassword

function Unprotect-KeyDataWithPassword
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $KeyData,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]
        $Password
    )

    $keyGen = $null
    $key = $null
    $iv = $null
    $ephemeralKey = $null
    $ephemeralIV = $null

    $doFinallyBlock = $true

    try
    {
        $params = @{
            Password = $Password
            Salt = $KeyData.Salt.Clone()
            IterationCount = $KeyData.IterationCount
        }

        $keyGen = Get-KeyGenerator @params
        $ephemeralKey = New-Object PowerShellUtils.PinnedArray[byte](,$keyGen.GetBytes(32))
        $ephemeralIV = New-Object PowerShellUtils.PinnedArray[byte](,$keyGen.GetBytes(16))

        $key = (Unprotect-DataWithAes -CipherText $KeyData.Key -Key $ephemeralKey -IV $ephemeralIV).PlainText
        $iv = (Unprotect-DataWithAes -CipherText $KeyData.IV -Key $ephemeralKey -IV $ephemeralIV).PlainText

        $doFinallyBlock = $false

        return New-Object psobject -Property @{
            Key = $key
            IV = $iv
        }
    }
    catch
    {
        throw
    }
    finally
    {
        if ($keyGen -is [IDisposable]) { $keyGen.Dispose() }
        if ($ephemeralKey -is [IDisposable]) { $ephemeralKey.Dispose() }
        if ($ephemeralIV -is [IDisposable]) { $ephemeralIV.Dispose() }

        if ($doFinallyBlock)
        {
            if ($key -is [IDisposable]) { $key.Dispose() }
            if ($iv -is [IDisposable]) { $iv.Dispose() }
        }
    }
} # function Unprotect-KeyDataWithPassword

function ConvertTo-PinnedByteArray
{
    [CmdletBinding()]
    [OutputType([PowerShellUtils.PinnedArray[byte]])]
    param (
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    try
    {
        switch ($InputObject.GetType().FullName)
        {
            ([string].FullName)
            {
                $pinnedArray = Convert-StringToPinnedByteArray -String $InputObject
                break
            }

            ([System.Security.SecureString].FullName)
            {
                $pinnedArray = Convert-SecureStringToPinnedByteArray -SecureString $InputObject
                break
            }

            ([System.Management.Automation.PSCredential].FullName)
            {
                $pinnedArray = Convert-PSCredentialToPinnedByteArray -Credential $InputObject
                break
            }

            default
            {
                $byteArray = $InputObject -as [byte[]]

                if ($null -eq $byteArray)
                {
                    throw 'Something unexpected got through our parameter validation.'
                }
                else
                {
                    $pinnedArray = New-Object PowerShellUtils.PinnedArray[byte](
                        ,$byteArray.Clone()
                    )
                }
            }

        }

        $pinnedArray
    }
    catch
    {
        throw
    }

} # function ConvertTo-PinnedByteArray

function ConvertFrom-ByteArray
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]
        $ByteArray,

        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($script:ValidTypes -notcontains $_)
            {
                throw "Invalid type specified. Type must be one of: $($script:ValidTypes -join ', ')"
            }

            return $true
        })]
        [type]
        $Type,

        [UInt32]
        $StartIndex = 0,

        [Nullable[UInt32]]
        $ByteCount = $null
    )

    if ($null -eq $ByteCount)
    {
        $ByteCount = $ByteArray.Count - $StartIndex
    }

    if ($StartIndex + $ByteCount -gt $ByteArray.Count)
    {
        throw 'The specified index and count values exceed the bounds of the array.'
    }

    switch ($Type.FullName)
    {
        ([string].FullName)
        {
            Convert-ByteArrayToString -ByteArray $ByteArray -StartIndex $StartIndex -ByteCount $ByteCount
            break
        }

        ([System.Security.SecureString].FullName)
        {
            Convert-ByteArrayToSecureString -ByteArray $ByteArray -StartIndex $StartIndex -ByteCount $ByteCount
            break
        }

        ([System.Management.Automation.PSCredential].FullName)
        {
            Convert-ByteArrayToPSCredential -ByteArray $ByteArray -StartIndex $StartIndex -ByteCount $ByteCount
            break
        }

        ([byte[]].FullName)
        {
            $array = New-Object byte[]($ByteCount)
            [Array]::Copy($ByteArray, $StartIndex, $array, 0, $ByteCount)

            ,$array
            break
        }

        default
        {
            throw 'Something unexpected got through parameter validation.'
        }
    }

} # function ConvertFrom-ByteArray

function Convert-StringToPinnedByteArray
{
    [CmdletBinding()]
    [OutputType([PowerShellUtils.PinnedArray[byte]])]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    New-Object PowerShellUtils.PinnedArray[byte](
        ,[System.Text.Encoding]::UTF8.GetBytes($String)
    )
}

function Convert-SecureStringToPinnedByteArray
{
    [CmdletBinding()]
    [OutputType([PowerShellUtils.PinnedArray[byte]])]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]
        $SecureString
    )

    try
    {
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
        $byteCount = $SecureString.Length * 2
        $pinnedArray = New-Object PowerShellUtils.PinnedArray[byte]($byteCount)

        [System.Runtime.InteropServices.Marshal]::Copy($ptr, $pinnedArray, 0, $byteCount)

        $pinnedArray
    }
    catch
    {
        throw
    }
    finally
    {
        if ($null -ne $ptr)
        {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr)
        }
    }

} # function Convert-SecureStringToPinnedByteArray

function Convert-PSCredentialToPinnedByteArray
{
    [CmdletBinding()]
    [OutputType([PowerShellUtils.PinnedArray[byte]])]
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    $passwordBytes = $null
    $pinnedArray = $null

    try
    {
        $passwordBytes = Convert-SecureStringToPinnedByteArray -SecureString $Credential.Password
        $usernameBytes = [System.Text.Encoding]::Unicode.GetBytes($Credential.UserName)
        $sizeBytes = [System.BitConverter]::GetBytes([uint32]$usernameBytes.Count)

        if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($sizeBytes) }

        $doFinallyBlock = $true

        try
        {
            $bufferSize = $passwordBytes.Count +
                          $usernameBytes.Count +
                          $script:PSCredentialHeader.Count +
                          $sizeBytes.Count
            $pinnedArray = New-Object PowerShellUtils.PinnedArray[byte]($bufferSize)

            $destIndex = 0

            [Array]::Copy(
                $script:PSCredentialHeader, 0, $pinnedArray.Array, $destIndex, $script:PSCredentialHeader.Count
            )
            $destIndex += $script:PSCredentialHeader.Count

            [Array]::Copy($sizeBytes, 0, $pinnedArray.Array, $destIndex, $sizeBytes.Count)
            $destIndex += $sizeBytes.Count

            [Array]::Copy($usernameBytes, 0, $pinnedArray.Array, $destIndex, $usernameBytes.Count)
            $destIndex += $usernameBytes.Count

            [Array]::Copy($passwordBytes.Array, 0, $pinnedArray.Array, $destIndex, $passwordBytes.Count)

            $doFinallyBlock = $false
            $pinnedArray
        }
        finally
        {
            if ($doFinallyBlock)
            {
                if ($pinnedArray -is [IDisposable]) { $pinnedArray.Dispose() }
            }
        }
    }
    catch
    {
        throw
    }
    finally
    {
        if ($passwordBytes -is [IDisposable]) { $passwordBytes.Dispose() }
    }

} # function Convert-PSCredentialToPinnedByteArray

function Convert-ByteArrayToString
{
    [CmdletBinding()]
    [OutputType([string])]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]
        $ByteArray,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $StartIndex,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $ByteCount
    )

    [System.Text.Encoding]::UTF8.GetString($ByteArray, $StartIndex, $ByteCount)
}

function Convert-ByteArrayToSecureString
{
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]
        $ByteArray,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $StartIndex,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $ByteCount
    )

    $chars = $null
    $memoryStream = $null
    $streamReader = $null

    try
    {
        $ss = New-Object System.Security.SecureString
        $memoryStream = New-Object System.IO.MemoryStream($ByteArray, $StartIndex, $ByteCount)
        $streamReader = New-Object System.IO.StreamReader($memoryStream, [System.Text.Encoding]::Unicode, $false)
        $chars = New-Object PowerShellUtils.PinnedArray[char](1024)

        while (($read = $streamReader.Read($chars, 0, $chars.Count)) -gt 0)
        {
            for ($i = 0; $i -lt $read; $i++)
            {
                $ss.AppendChar($chars[$i])
            }
        }

        $ss.MakeReadOnly()
        $ss
    }
    finally
    {
        if ($streamReader -is [IDisposable]) { $streamReader.Dispose() }
        if ($memoryStream -is [IDisposable]) { $memoryStream.Dispose() }
        if ($chars -is [IDisposable]) { $chars.Dispose() }
    }

} # function Convert-ByteArrayToSecureString

function Convert-ByteArrayToPSCredential
{
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]
        $ByteArray,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $StartIndex,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $ByteCount
    )

    $message = 'Byte array is not a serialized PSCredential object.'

    if ($ByteCount -lt $script:PSCredentialHeader.Count + 4) { throw $message }

    for ($i = 0; $i -lt $script:PSCredentialHeader.Count; $i++)
    {
        if ($ByteArray[$StartIndex + $i] -ne $script:PSCredentialHeader[$i]) { throw $message }
    }

    $i = $StartIndex + $script:PSCredentialHeader.Count

    $sizeBytes = $ByteArray[$i..($i+3)]
    if (-not [System.BitConverter]::IsLittleEndian) { [array]::Reverse($sizeBytes) }

    $i += 4
    $size = [System.BitConverter]::ToUInt32($sizeBytes, 0)

    if ($ByteCount -lt $i + $size) { throw $message }

    $userName = [System.Text.Encoding]::Unicode.GetString($ByteArray, $i, $size)
    $i += $size

    try
    {
        $params = @{
            ByteArray = $ByteArray
            StartIndex = $i
            ByteCount = $StartIndex + $ByteCount - $i
        }
        $secureString = Convert-ByteArrayToSecureString @params
    }
    catch
    {
        throw $message
    }

    New-Object System.Management.Automation.PSCredential($userName, $secureString)

} # function Convert-ByteArrayToPSCredential

function Test-IsProtectedData
{
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]
        $InputObject
    )

    $isValid = $true

    $cipherText = $InputObject.CipherText -as [byte[]]
    $type = $InputObject.Type -as [string]

    if ($null -eq $cipherText -or $cipherText.Count -eq 0 -or
        [string]::IsNullOrEmpty($type) -or
        $null -eq $InputObject.KeyData)
    {
        $isValid = $false
    }

    if ($isValid)
    {
        foreach ($object in $InputObject.KeyData)
        {
            if (-not (Test-IsKeyData -InputObject $object))
            {
                $isValid = $false
                break
            }
        }
    }

    return $isValid

} # function Test-IsProtectedData

function Test-IsKeyData
{
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]
        $InputObject
    )

    $isValid = $true

    $key = $InputObject.Key -as [byte[]]
    $iv = $InputObject.IV -as [byte[]]

    if ($null -eq $key -or $null -eq $iv -or $key.Count -eq 0 -or $iv.Count -eq 0)
    {
        $isValid = $false
    }

    if ($isValid)
    {
        $isCertificate = Test-IsCertificateProtectedKeyData -InputObject $InputObject
        $isPassword = Test-IsPasswordProtectedKeydata -InputObject $InputObject
        $isValid = $isCertificate -or $isPassword
    }

    return $isValid

} # function Test-IsKeyData

function Test-IsPasswordProtectedKeyData
{
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]
        $InputObject
    )

    $isValid = $true

    $salt = $InputObject.Salt -as [byte[]]
    $hash = $InputObject.Hash -as [string]
    $hashSalt = $InputObject.HashSalt -as [byte[]]
    $iterations = $InputObject.IterationCount -as [int]

    if ($null -eq $salt -or $salt.Count -eq 0 -or
        $null -eq $hashSalt -or $hashSalt.Count -eq 0 -or
        $null -eq $iterations -or $iterations -eq 0 -or
        $null -eq $hash -or $hash -notmatch '^[A-F\d]+$')
    {
        $isValid = $false
    }

    return $isValid

} # function Test-IsPasswordProtectedKeyData

function Test-IsCertificateProtectedKeyData
{
    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory = $true)]
        [psobject]
        $InputObject
    )

    $isValid = $true

    $thumbprint = $InputObject.Thumbprint -as [string]

    if ($null -eq $thumbprint -or $thumbprint -notmatch '^[A-F\d]+$')
    {
        $isValid = $false
    }

    return $isValid

} # function Test-IsCertificateProtectedKeyData

#endregion
