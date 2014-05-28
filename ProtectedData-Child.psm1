#requires -Version 2.0

if ($PSVersionTable.PSVersion.Major -eq 2)
{
    $IgnoreError = 'SilentlyContinue'
}
else
{
    $IgnoreError = 'Ignore'
}

$ValidTypes = @(
    [string],
    [System.Security.SecureString],
    [System.Management.Automation.PSCredential]
    [byte[]]
)

$PSCredentialHeader = [byte[]](5,12,19,75,80,20,19,11,11,6,11,13)

#region Exported functions

function Protect-Data
{
    <#
    .Synopsis
       Encrypts an object using one or more RSA certificates and/or passwords.
    .DESCRIPTION
       Encrypts an object using a randomly-generated AES key.  AES key information is encrypted using one or more RSA public keys and/or password-derived keys, allowing the data to be securely shared among multiple users and computers.
       If certificates are used, they must be installed in either the local computer or local user's certificate stores, and the certificates' Key Usage extension (if present) must allow Key Encipherment.  The private keys are not required for Protect-Data.
    .PARAMETER InputObject
       The object that is to be encrypted.  The object must be of one of the types returned by the Get-ProtectedDataSupportedTypes command.
    .PARAMETER CertificateThumbprint
       Zero or more certificate thumbprints that should be used to encrypt the data.  The certificates must be installed in the local computer or current user's certificate stores, and must be RSA certificates.  The data can later be decrypted by using the same certificate (with its private key.)
    .PARAMETER Password
       Zero or more SecureString objects containing password that will be used to derive encryption keys.  The data can later be decrypted by passing in a SecureString with the same value.
    .PARAMETER SkipCertificateValidation
       If specified, the command does not attempt to validate that the specified certificate(s) came from trusted publishers and have not been revoked or expired.
       This is primarily intended to allow the use of self-signed certificates.
    .PARAMETER PasswordIterationCount
       Optional positive integer value specifying the number of iteration that should be used when deriving encryption keys from the specified password(s).  Defaults to 1000.
       Higher values make it more costly to crack the passwords by brute force.
    .EXAMPLE
       $encryptedObject = Protect-Data -InputObject $myString -CertificateThumbprint CB04E7C885BEAE441B39BC843C85855D97785D25 -Password (Read-Host -AsSecureString -Prompt 'Enter password to encrypt')

       Encrypts a string using a single RSA certificate, and a password.  Either the certificate or the password can be used when decrypting the data.
    .EXAMPLE
       $credential | Protect-Data -CertificateThumbprint 'CB04E7C885BEAE441B39BC843C85855D97785D25', 'B5A04AB031C24BCEE220D6F9F99B6F5D376753FB'

       Encrypts a PSCredential object using two RSA certificates.  Either private key can be used to later decrypt the data.
    .INPUTS
       Object

       Object must be one of the types returned by the Get-ProtectedDataSupportedTypes command.
    .OUTPUTS
       [PowerShellUtils.Cryptography.ProtectedData]

       The ProtectedData type contains the following properties:

       CipherText : An array of bytes containing the encrypted data
       Type       : A string representation of the InputObject's original type (used when decrypting back to the original object later.)
       KeyData    : One or more KeyData structures which contain encrypted copies of the AES key used to protect the ciphertext, and other identifying information about the way this copy of the keys was protected, such as Certificate Thumbprint, Password Hash, Salt values, and Iteration count.
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
    [OutputType([PowerShellUtils.Cryptography.ProtectedData])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateScript({
            if ($ValidTypes -notcontains $_.GetType() -and $null -eq ($_ -as [byte[]]))
            {
                throw "InputObject must be one of the following types: $($ValidTypes -join ', ')"
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

        [ValidateNotNull()]
        [AllowEmptyCollection()]
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
                    Get-KeyEncryptionCertificate -CertificateThumbprint $thumbprint -SkipCertificateVerification:$SkipCertificateVerification -ErrorAction Stop |
                    Select-Object -First 1
                }
                catch
                {
                    Write-Error -ErrorRecord $_
                }                
            }
        )

        if ($certs.Count -eq 0 -and $Password.Count -eq 0)
        {
            throw 'None of the specified certificates could be used for encryption, and no passwords were specified.  Data protection cannot be performed.'
        }
    }

    process
    {
        $plainText = $null
        $aes       = $null
        $key       = $null
        $iv        = $null

        try
        {
            $plainText = ConvertTo-PinnedByteArray -InputObject $InputObject

            $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            $key = New-Object PowerShellUtils.Cryptography.PinnedArray[byte](,$aes.Key)
            $iv  = New-Object PowerShellUtils.Cryptography.PinnedArray[byte](,$aes.IV)

            $memoryStream = New-Object System.IO.MemoryStream
            $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $aes.CreateEncryptor(), 'Write')

            $cryptoStream.Write($plainText, 0, $plainText.Count)
            $cryptoStream.FlushFinalBlock()

            $protectedData = New-Object PowerShellUtils.Cryptography.ProtectedData -Property @{
                CipherText = $memoryStream.ToArray()
                Type       = $InputObject.GetType().FullName
                KeyData    = @()
            }

            $params = @{
                InputObject            = $protectedData
                Key                    = $key
                IV                     = $iv
                Certificate            = $certs
                Password               = $Password
                PasswordIterationCount = $PasswordIterationCount
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
            if ($null -ne $aes)                  { $aes.Clear() }
            if ($cryptoStream -is [IDisposable]) { $cryptoStream.Dispose() }
            if ($memoryStream -is [IDisposable]) { $memoryStream.Dispose() }
            if ($plainText -is [IDisposable])    { $plainText.Dispose() }
            if ($key -is [IDisposable])          { $key.Dispose() }
            if ($iv -is [IDisposable])           { $iv.Dispose() }
        }

    } # process

} # function Protect-Data

function Unprotect-Data
{
    <#
    .Synopsis
       Decrypts an object that was produced by the Protect-Data command.
    .DESCRIPTION
       Decrypts an object that was produced by the Protect-Data command.  If a Certificate is used to perform the decryption, it must be installed in either the local computer or current user's certificate stores (with its private key), and the current user must have permission to use that key.
    .PARAMETER InputObject
       The ProtectedData object that is to be decrypted.
    .PARAMETER CertificateThumbprint
       Thumbprint of an RSA certificate that will be used to decrypt the data.  This certificate must be present in either the local computer or current user's certificate stores, and the current user must have permission to use the certificate's private key.  One of the InputObject's KeyData objects must be protected with this certificate.
    .PARAMETER Password
       A SecureString containing a password that will be used to derive an encryption key.  One of the InputObject's KeyData objects must be protected with this password.
    .PARAMETER SkipCertificateValidation
       If specified, the command does not attempt to validate that the specified certificate(s) came from trusted publishers and have not been revoked or expired.
       This is primarily intended to allow the use of self-signed certificates.
    .EXAMPLE
       $decryptedObject = Unprotect-Data -InputObject $encryptedObject -CertificateThumbprint CB04E7C885BEAE441B39BC843C85855D97785D25

       Decrypts the contents of $encryptedObject and outputs either a String or SecureString (depending on what was originally encrypted.)
    .EXAMPLE
       $decryptedObject = $encryptedObject | Unprotect-Data -Password (Read-Host -AsSecureString -Prompt 'Enter password to decrypt the data')

       Decrypts the contents of $encryptedObject and outputs an object of the same type as what was originally passed to Protect-Data.  Uses a password to decrypt the object instead of a certificate.
    .INPUTS
       [PowerShellUtils.Cryptography.ProtectedData]
    .OUTPUTS
       Object

       Object may be any type returned by Get-ProtectedDataSupportedTypes.  Specifically, it will be an object of the type specified in the InputObject's Type property.
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
            if ($_ -isnot [PowerShellUtils.Cryptography.ProtectedData] -and
                $_.PSObject.TypeNames -notcontains 'Deserialized.PowerShellUtils.Cryptography.ProtectedData')
            {
                throw 'InputObject argument must be a ProtectedData object.'
            }

            if ($null -eq $_.CipherText -or $_.CipherText.Count -eq 0)
            {
                throw 'Protected data object contained no cipher text.'
            }

            $t = $_.Type -as [type]

            if ($null -eq $t -or $ValidTypes -notcontains $t)
            {
                throw "Protected data object specified an invalid type.  Type must be one of: $($ValidTypes -join ', ')"
            }
            
            return $true
        })]        
        $InputObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [ValidateScript({
            if ($_ -notmatch '^[A-F\d]+$')
            {
                throw 'Certificate thumbprints must only contain hexadecimal digits (0-9 and letters A-F).'
            }

            return $true
        })]
        [string]
        $CertificateThumbprint,

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
    }

    process
    {
        $plainText = $null
        $aes       = $null
        $key       = $null
        $iv        = $null

        if ($PSCmdlet.ParameterSetName -eq 'Certificate')
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
            $key    = $result.Key
            $iv     = $result.IV

            $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider -Property @{
                Key = $key
                IV  = $iv
            }

            # Not sure exactly how long of a buffer we'll need to hold the decrypted data.  Twice
            # the ciphertext length should be more than enough.
            $plainText    = New-Object PowerShellUtils.Cryptography.PinnedArray[byte](2 * $InputObject.CipherText.Count)

            $memoryStream = New-Object System.IO.MemoryStream(,$plainText)
            $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $aes.CreateDecryptor(), 'Write')

            $cryptoStream.Write($InputObject.CipherText, 0, $InputObject.CipherText.Count)
            $cryptoStream.FlushFinalBlock()

            # TODO: Slicing the plaintext array like this is probably copying it to a new array object in memory, which
            # defeats the purpose of pinning it in the first place.  Update ConvertFrom-ByteArray and its helper functions
            # to accept start / end index arguments instead.
            
            ConvertFrom-ByteArray -ByteArray $plainText[0..($memoryStream.Position - 1)] -Type $InputObject.Type
        }
        catch
        {
            Write-Error -ErrorRecord $_
            return
        }
        finally
        {
            if ($null -ne $aes)                  { $aes.Clear() }
            if ($cryptoStream -is [IDisposable]) { $cryptoStream.Dispose() }
            if ($memoryStream -is [IDisposable]) { $memoryStream.Dispose() }
            if ($plainText -is [IDisposable])    { $plainText.Dispose() }
            if ($key -is [IDisposable])          { $key.Dispose() }
            if ($iv -is [IDisposable])           { $iv.Dispose() }
        }

    } # process

} # function Unprotect-Data

function Add-ProtectedDataCredential
{
    <#
    .Synopsis
       Adds one or more new copies of an encryption key to an object generated by Protect-Data.
    .DESCRIPTION
       This command can be used to add new certificates and/or passwords to an object that was previously encrypted by Protect-Data.  The caller must provide one of the certificates or passwords that already exists in the ProtectedData object to perform this operation.
    .PARAMETER InputObject
       The ProtectedData object which was created by an earlier call to Protect-Data.
    .PARAMETER CertificateThumbprint
       The thumbprint of a certificate which was previously used to encrypt the ProtectedData structure's key.  This certificate must be installed in the local computer or current user's stores (with its private key), and the current user must have permission to use the private key.
    .PARAMETER Password
       A password which was previously used to encrypt the ProtectedData structure's key.
    .PARAMETER NewCertificateThumbprint
       Zero or more certificate thumbprints that should be used to encrypt the data.  The certificates must be installed in the local computer or current user's certificate stores, and must be RSA certificates.  The data can later be decrypted by using the same certificate (with its private key.)
    .PARAMETER NewPassword
       Zero or more SecureString objects containing password that will be used to derive encryption keys.  The data can later be decrypted by passing in a SecureString with the same value.
    .PARAMETER SkipCertificateValidation
       If specified, the command does not attempt to validate that the specified certificate(s) came from trusted publishers and have not been revoked or expired.
       This is primarily intended to allow the use of self-signed certificates.
    .PARAMETER PasswordIterationCount
       Optional positive integer value specifying the number of iteration that should be used when deriving encryption keys from the specified password(s).  Defaults to 1000.
       Higher values make it more costly to crack the passwords by brute force.
    .PARAMETER Passthru
       If this switch is used, the ProtectedData object is output to the pipeline after it is modified.
    .EXAMPLE
       Add-ProtectedDataCredential -InputObject $protectedData -CertificateThumbprint $oldThumbprint -NewCertificateThumbprint $newThumbprints -NewPassword $newPasswords

       Uses the certificate with thumbprint $oldThumbprint to add new key copies to the $protectedData object.  $newThumbprints would be a string array containing thumbprints, and $newPasswords would be an array of SecureString objects.
    .INPUTS
       [PowerShellUtils.Cryptography.ProtectedData]

       Object must be one of the types returned by the Get-ProtectedDataSupportedTypes command.
    .OUTPUTS
       None, or
       [PowerShellUtils.Cryptography.ProtectedData]
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
            if ($_ -isnot [PowerShellUtils.Cryptography.ProtectedData] -and
                $_.PSObject.TypeNames -notcontains 'Deserialized.PowerShellUtils.Cryptography.ProtectedData')
            {
                throw 'InputObject argument must be a ProtectedData object.'
            }

            return $true
        })]
        $InputObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [ValidateScript({
            if ($_ -notmatch '^[A-F\d]+$')
            {
                throw 'Certificate thumbprints must only contain hexadecimal digits (0-9 and letters A-F).'
            }

            return $true
        })]
        [string]
        $CertificateThumbprint,

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

        if ($PSCmdlet.ParameterSetName -eq 'Certificate')
        {
            try
            {
                $params = @{
                    CertificateThumbprint       = $CertificateThumbprint
                    SkipCertificateVerification = $SkipCertificateVerification
                    RequirePrivateKey           = $true
                }

                $decryptionCert = Get-KeyEncryptionCertificate @params -ErrorAction Stop |
                                  Select-Object -First 1
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
                    Get-KeyEncryptionCertificate -CertificateThumbprint $thumbprint -SkipCertificateVerification:$SkipCertificateVerification -ErrorAction Stop |
                    Select-Object -First 1
                }
                catch
                {
                    Write-Error -ErrorRecord $_
                }                
            }
        )

        if ($certs.Count -eq 0 -and $NewPassword.Count -eq 0)
        {
            throw 'None of the specified certificates could be used for encryption, and no passwords were specified.  Data protection cannot be performed.'
        }

    } # begin

    process
    {
        if ($PSCmdlet.ParameterSetName -eq 'Certificate')
        {
            $params = @{ Certificate = $decryptionCert }
        }
        else
        {
            $params = @{ Password = $Password }
        }

        $key = $null
        $iv  = $null

        try
        {
            $result = Unprotect-MatchingKeyData -InputObject $InputObject @params
            $key    = $result.Key
            $iv     = $result.IV

            Add-KeyData -InputObject $InputObject -Key $key -IV $iv -Certificate $certs -Password $NewPassword
        }
        catch
        {
            Write-Error -ErrorRecord $_
            return
        }
        finally
        {
            if ($key -is [IDisposable]) { $key.Dispose() }
            if ($iv -is [IDisposable])  { $iv.Dispose() }
        }

        if ($Passthru)
        {
            $InputObject
        }
    }
}

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
    .PARAMETER Password
       Passwords in SecureString form which are to be removed from this ProtectedData object.
    .PARAMETER Passthru
       If this switch is used, the ProtectedData object will be written to the pipeline after processing is complete.
    .EXAMPLE
       $protectedData | Remove-ProtectedDataCredential -CertificateThumbprint $thumbprints -Password $passwords

       Removes certificates and passwords from an existing ProtectedData object.
    .INPUTS
       [PowerShellUtils.Cryptography.ProtectedData]
    .OUTPUTS
       None, or
       [PowerShellUtils.Cryptography.ProtectedData]
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
            if ($_ -isnot [PowerShellUtils.Cryptography.ProtectedData] -and
                $_.PSObject.TypeNames -notcontains 'Deserialized.PowerShellUtils.Cryptography.ProtectedData')
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
        [System.Security.SecureString[]]
        $Password,

        [switch]
        $Passthru
    )

    process
    {
        $matchingKeyData = @(
            foreach ($keyData in $InputObject.KeyData)
            {
                if ($keyData.PSObject.TypeNames -match 'PowerShellUtils\.Cryptography\.CertificateProtectedKeyData$')
                {
                    if ($CertificateThumbprint -contains $keyData.Thumbprint) { $keyData }
                }
                elseif ($keyData.PSObject.TypeNames -match 'PowerShellUtils\.Cryptography\.PasswordProtectedKeyData$')
                {
                    foreach ($secureString in $Password)
                    {
                        if ($keyData.Hash -eq (Get-PasswordHash -Password $secureString -Salt $keyData.HashSalt -IterationCount $keyData.IterationCount))
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
}

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
       This function allows you to know which InputObject types are supported by the Protect-Data and Unprotect-Data commands in this version of the module.  This list may expand over time, will always be backwards-compatible with previously-encrypted data.
    .LINK
       Protect-Data
    .LINK
       Unprotect-Data
    #>

    [CmdletBinding()]
    [OutputType([Type[]])]
    param ( )

    # Not sure if the Clone() is strictly necessary here since PowerShell probably enumerates
    # the collection anyway, rather than returning a reference to the original array, but the
    # performance difference isn't really going to matter either way.

    $ValidTypes.Clone()
}

function Get-KeyEncryptionCertificate
{
    <#
    .Synopsis
       Finds certificates which can be used by Protect-Data and related commands.
    .DESCRIPTION
       Searches the given path, and all child paths, for certificates which can be used by Protect-Data.  Such certificates must support Key Encipherment usage, and by default, must not be expired and must be issued by a trusted authority.
    .PARAMETER Path
       Path which should be searched for the certifictes.  Defaults to the entire Cert: drive.
    .PARAMETER CertificateThumbprint
       Thumbprints which should be included in the search.  Wildcards are allowed.  Defaults to '*'.
    .PARAMETER SkipCertificateVerification
       If this switch is used, the command will include certificates which are not yet valid, expired, revoked, or issued by an untrusted authority.  This can be useful if you wish to use a self-signed certificate for encryption.
    .PARAMETER RequirePrivateKey
       If this switch is used, the command will only output certificates which have a usable private key on this computer.
    .EXAMPLE
       Get-KeyEncryptionCertificate -Path Cert:\CurrentUser -RequirePrivateKey -SkipCertificateVerification

       Searches for certificates which support key encipherment and have a private key installed.  All matching certificates are returned, and they do not need to be verified for trust, revocation or validity period.
    .EXAMPLE
       Get-KeyEncryptionCertificate -Path Cert:\CurrentUser\TrustedPeople

       Searches the current user's Trusted People store for certificates that can be used with Protect-Data.  Certificates must be current, issued by a trusted authority, and not revoked, but they do not need to have a private key available to the current user.
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
    # This is a little ugly, may rework this later now that I've made Get-KeyEncryptionCertificate public.  Originally
    # it was only used to search for a single thumbprint, and threw errors back to the caller if no suitable cert could
    # be found.  Now I want it to also be used as a search tool for users to identify suitable certificates.  Maybe just
    # needs to be two separate functions, one internal and one public.

    if (-not $PSBoundParameters.ContainsKey('ErrorAction') -and
        $CertificateThumbprint -notmatch '^[A-F\d]+$')
    {
        $ErrorActionPreference = $IgnoreError
    }

    # Locate and validate a suitable key encipherment certificate matching the specified thumbprint

    $certs = Get-ChildItem -Path $Path -Recurse -Include $CertificateThumbprint -ErrorAction $IgnoreError |
             Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] } |
             Sort-Object -Unique -Property Thumbprint
    
    if ($null -eq $certs)
    {
        throw "Certificate '$CertificateThumbprint' was not found."
    }
    
    $certs | ValidateKeyEncryptionCertificate -SkipCertificateVerification:$SkipCertificateVerification -RequirePrivateKey:$RequirePrivateKey

} # function Get-KeyEncryptionCertificate

#endregion

#region Helper functions

function Add-KeyData
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_ -isnot [PowerShellUtils.Cryptography.ProtectedData] -and
                $_.PSObject.TypeNames -notcontains 'Deserialized.PowerShellUtils.Cryptography.ProtectedData')
            {
                throw 'InputObject argument must be a ProtectedData object.'
            }

            return $true
        })]
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

    $InputObject.KeyData += @(
        foreach ($cert in $Certificate)
        {
            $match = $InputObject.KeyData |
                     Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
            
            if ($null -ne $match) { continue }

            try
            {
                New-Object PowerShellUtils.Cryptography.CertificateProtectedKeyData(
                    $cert.PublicKey.Key.Encrypt($key, $true),
                    $cert.PublicKey.Key.Encrypt($iv , $true),
                    $cert.Thumbprint
                )
            }
            catch
            {
                Write-Error -ErrorRecord $_
            }
        }

        foreach ($secureString in $Password)
        {
            $match = $InputObject.KeyData |
                     Where-Object {
                         $_.PSObject.TypeNames -match 'PowerShellUtils\.Cryptography\.PasswordProtectedKeyData$' -and
                         $_.Hash -eq (Get-PasswordHash -Password $secureString -Salt $_.HashSalt -IterationCount $_.IterationCount)
                     }
            
            if ($null -ne $match) { continue }
            
            Protect-KeyDataWithPassword -Password $secureString -Key $key -IV $iv -IterationCount $PasswordIterationCount
        }
    )
}

function Unprotect-MatchingKeyData
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_ -isnot [PowerShellUtils.Cryptography.ProtectedData] -and
                $_.PSObject.TypeNames -notcontains 'Deserialized.PowerShellUtils.Cryptography.ProtectedData')
            {
                throw 'InputObject argument must be a ProtectedData object.'
            }

            return $true
        })]
        $InputObject,

        [Parameter(Mandatory = $true, ParameterSetName = 'Certificate')]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(Mandatory = $true, ParameterSetName = 'Passwword')]
        [System.Security.SecureString]
        $Password
    )

    $doFinallyBlock = $true
    
    try
    {

        if ($PSCmdlet.ParameterSetName -eq 'Certificate')
        {
            $keyData = $InputObject.KeyData |
                        Where-Object {
                            $_.PSObject.TypeNames -match 'PowerShellUtils\.Cryptography\.CertificateProtectedKeyData$' -and
                            $_.Thumbprint -eq $Certificate.Thumbprint
                        } |
                        Select-Object -First 1

            if ($null -eq $keyData)
            {
                throw "Protected data object was not encrypted with certificate '$($Certificate.Thumbprint)'."
            }

            try
            {
                $key = New-Object PowerShellUtils.Cryptography.PinnedArray[byte](,$Certificate.PrivateKey.Decrypt($keyData.Key, $true))
                $iv  = New-Object PowerShellUtils.Cryptography.PinnedArray[byte](,$Certificate.PrivateKey.Decrypt($keyData.IV , $true))
            }
            catch
            {
                throw
            }
        }
        else
        {
            $keyData = $InputObject.KeyData |
                        Where-Object {
                            $_.PSObject.TypeNames -match 'PowerShellUtils\.Cryptography\.PasswordProtectedKeyData$' -and
                            (Get-PasswordHash -Password $Password -Salt $_.HashSalt -IterationCount $_.IterationCount) -eq $_.Hash
                        } |
                        Select-Object -First 1

            if ($null -eq $keyData)
            {
                throw 'Protected data object was not encrypted with the specified password.'
            }
            
            try
            {
                $result = Unprotect-KeyDataWithPassword -KeyData $keyData -Password $Password
                $key    = $result.Key
                $iv     = $result.IV
            }
            catch
            {
                throw
            }
        }
        
        $doFinallyBlock = $false

        New-Object psobject -Property @{
            Key = $key
            IV  = $iv
        }
    }
    finally
    {
        if ($doFinallyBlock)
        {
            if ($key -is [IDisposable]) { $key.Dispose() }
            if ($iv  -is [IDisposable]) { $iv.Dispose() }
        }
    }

}

function ValidateKeyEncryptionCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [switch]
        $SkipCertificateVerification,

        [switch]
        $RequirePrivateKey
    )

    process
    {
        if ($Certificate.PublicKey.Key -isnot [System.Security.Cryptography.RSACryptoServiceProvider])
        {
            Write-Error "Certficiate '$($Certificate.Thumbprint)' is not an RSA certificate."
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

        $keyUsageFound   = $false
        $keyEncipherment = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
        $keyUsageFlags   = 0

        foreach ($extension in $Certificate.Extensions)
        {
            if ($extension -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension])
            {
                $keyUsageFound = $true
                $keyUsageFlags = $keyUsageFlags -bor $extension.KeyUsages
            }
        }
        
        if ($keyUsageFound -and ($keyUsageFlags -band $keyEncipherment) -ne $keyEncipherment)
        {
            Write-Error "Certificate '$($Certificate.Thumbprint)' contains a Key Usage extension which does not allow Key Encipherment."
            return
        }
    
        if (-not $SkipCertificateVerification -and -not $Certificate.Verify())
        {
            Write-Error "Verification of certificate '$($Certificate.Thumbprint)' failed."
            return
        }
        
        if ($RequirePrivateKey)
        {
            $Certificate = Get-ChildItem -Path 'Cert:\' -Recurse -Include $Certificate.Thumbprint -ErrorAction $IgnoreError |
                           Where-Object { $_.PrivateKey -is [System.Security.Cryptography.RSACryptoServiceProvider] } |
                           Select-Object -First 1
        
            if ($null -eq $Certificate)
            {
                Write-Error "Could not find private key for certificate '$($Certificate.Thumbprint)'."
                return
            }
        }
    
        $Certificate
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
        $byteArray  = Convert-SecureStringToPinnedByteArray -SecureString $Password

        if ($PSCmdlet.ParameterSetName -eq 'RestoreExisting')
        {
            $saltBytes  = $Salt
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
        $rng   = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $bytes = New-Object byte[]($Count)
        $rng.GetBytes($bytes)

        ,$bytes
    }
    finally
    {
        if ($rng -is [IDisposable]) { $rng.Dispose() }
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
    
    $aes             = $null
    $keyStream       = $null
    $keyCryptoStream = $null
    $IVStream        = $null
    $IVCryptoStream  = $null
    $keyGen          = $null

    try
    {
        $keyGen          = Get-KeyGenerator -Password $Password -IterationCount $IterationCount
        $aes             = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key         = $keyGen.GetBytes(32)
        $aes.IV          = $keyGen.GetBytes($aes.BlockSize / 8)
        $keyStream       = New-Object System.IO.MemoryStream
        $IVStream        = New-Object System.IO.MemoryStream
        $keyCryptoStream = New-Object System.Security.Cryptography.CryptoStream($keyStream, $aes.CreateEncryptor(), 'Write')
        $IVCryptoStream  = New-Object System.Security.Cryptography.CryptoStream($IVStream, $aes.CreateEncryptor(), 'Write')
        $hashSalt        = Get-RandomBytes -Count 32

        $keyCryptoStream.Write($Key, 0, $Key.Count)
        $keyCryptoStream.FlushFinalBlock()
        $IVCryptoStream.Write($IV, 0, $IV.Count)
        $IVCryptoStream.FlushFinalBlock()

        $hash = Get-PasswordHash -Password $Password -Salt $hashSalt -IterationCount $IterationCount

        New-Object PowerShellUtils.Cryptography.PasswordProtectedKeyData(
            $keyStream.ToArray(),
            $IVStream.ToArray(),
            $keyGen.Salt,
            $keyGen.IterationCount,
            $hash,
            $hashSalt
        )
    }
    catch
    {
        throw
    }
    finally
    {
        if ($null -ne $aes)                     { $aes.Clear() }
        if ($keyCryptoStream -is [IDisposable]) { $keyCryptoStream.Dispose() }
        if ($IVCryptoStream -is [IDisposable])  { $IVCryptoStream.Dispose() }
        if ($keyStream -is [IDisposable])       { $keyStream.Dispose() }
        if ($IVStream -is [IDisposable])        { $IVStream.Dispose() }
        if ($keyGen -is [IDisposable])          { $keyGen.Dispose() }
    }

} # function Protect-KeyDataWithPassword

function Unprotect-KeyDataWithPassword
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_ -isnot [PowerShellUtils.Cryptography.PasswordProtectedKeyData] -and
                $_.PSObject.TypeNames -notcontains 'Deserialized.PowerShellUtils.Cryptography.PasswordProtectedKeyData')
            {
                throw 'InputObject argument must be a PasswordProtectedKeyData object.'
            }

            return $true
        })]
        $KeyData,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]
        $Password
    )

    # Derive an encryption key from the provided KeyData and Password parameters, and attempt to decrypt the
    # KeyData's Key and IV arrays using the derived key.  If successful, return an object containing the
    # decrypted key / IV, which will be used to initialize a crypto provider.

    $keyGen          = $null
    $aes             = $null
    $keyStream       = $null
    $keyCryptoStream = $null
    $IVStream        = $null
    $IVCryptoStream  = $null

    try
    {
        $keyGen          = Get-KeyGenerator -Password $Password -Salt $KeyData.Salt.Clone() -IterationCount $KeyData.IterationCount
        $aes             = New-Object System.Security.Cryptography.AesCryptoServiceProvider
        $aes.Key         = $keyGen.GetBytes(32)
        $aes.IV          = $keyGen.GetBytes($aes.BlockSize / 8)
        $keyStream       = New-Object System.IO.MemoryStream
        $IVStream        = New-Object System.IO.MemoryStream
        $keyCryptoStream = New-Object System.Security.Cryptography.CryptoStream($keyStream, $aes.CreateDecryptor(), 'Write')
        $IVCryptoStream  = New-Object System.Security.Cryptography.CryptoStream($IVStream, $aes.CreateDecryptor(), 'Write')

        $keyCryptoStream.Write($KeyData.Key, 0, $KeyData.Key.Count)
        $keyCryptoStream.FlushFinalBlock()
        $IVCryptoStream.Write($KeyData.IV, 0, $KeyData.IV.Count)
        $IVCryptoStream.FlushFinalBlock()

        $doFinallyBlock = $true
        
        try
        {
            $key = New-Object PowerShellUtils.Cryptography.PinnedArray[byte](,$keyStream.ToArray())
            $iv  = New-Object PowerShellUtils.Cryptography.PinnedArray[byte](,$IVStream.ToArray())
            
            $outputObject = New-Object psobject -Property @{
                Key = $key
                IV  = $iv
            }
            
            $doFinallyBlock = $false
        }
        finally
        {
            if ($doFinallyBlock)
            {
                if ($key -is [IDisposable]) { $key.Dispose() }
                if ($iv  -is [IDisposable]) { $iv.Dispose() }
            }
        }

        $outputObject
    }
    catch
    {
        throw
    }
    finally
    {
        if ($null -ne $aes)                     { $aes.Clear() }
        if ($keyCryptoStream -is [IDisposable]) { $keyCryptoStream.Dispose() }
        if ($IVCryptoStream -is [IDisposable])  { $IVCryptoStream.Dispose() }
        if ($keyStream -is [IDisposable])       { $keyStream.Dispose() }
        if ($IVStream -is [IDisposable])        { $IVStream.Dispose() }
        if ($keyGen -is [IDisposable])          { $keyGen.Dispose() }        
    }

} # function Unprotect-KeyDataWithPassword

function ConvertTo-PinnedByteArray
{
    [CmdletBinding()]
    [OutputType([PowerShellUtils.Cryptography.PinnedArray[byte]])]
    param (
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    try
    {
        switch ($InputObject.GetType())
        {
            ([string])
            {
                $pinnedArray = Convert-StringToPinnedByteArray -String $InputObject
            }

            ([System.Security.SecureString])
            {
                $pinnedArray = Convert-SecureStringToPinnedByteArray -SecureString $InputObject
            }

            ([System.Management.Automation.PSCredential])
            {
                $pinnedArray = Convert-PSCredentialToPinnedByteArray -Credential $InputObject
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
                    $pinnedArray = New-Object PowerShellUtils.Cryptography.PinnedArray[byte](
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
            if ($ValidTypes -notcontains $_)
            {
                throw "Invalid type specified.  Type must be one of: $($ValidTypes -join ', ')"
            }

            return $true
        })]
        [type]
        $Type
    )

    switch ($Type)
    {
        ([string])
        {
            Convert-ByteArrayToString -ByteArray $ByteArray
            break
        }

        ([System.Security.SecureString])
        {
            Convert-ByteArrayToSecureString -ByteArray $ByteArray
            break
        }

        ([System.Management.Automation.PSCredential])
        {
            Convert-ByteArrayToPSCredential -ByteArray $ByteArray
            break
        }

        ([byte[]])
        {
            ,$ByteArray.Clone()
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
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    New-Object PowerShellUtils.Cryptography.PinnedArray[byte](
        ,[System.Text.Encoding]::UTF8.GetBytes($String)
    )
}

function Convert-SecureStringToPinnedByteArray
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]
        $SecureString
    )

    try
    {
        $ptr         = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
        $byteCount   = $SecureString.Length * 2
        $pinnedArray = New-Object PowerShellUtils.Cryptography.PinnedArray[byte]($byteCount)

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
    param (
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]
        $Credential
    )

    $passwordBytes = $null
    $pinnedArray   = $null

    try
    {
        $passwordBytes = Convert-SecureStringToPinnedByteArray -SecureString $Credential.Password
        $usernameBytes = [System.Text.Encoding]::Unicode.GetBytes($Credential.UserName)
        $sizeBytes     = [System.BitConverter]::GetBytes([uint32]$usernameBytes.Count)

        if (-not [System.BitConverter]::IsLittleEndian) { [Array]::Reverse($sizeBytes) }

        $doFinallyBlock = $true

        try
        {
            $bufferSize   = $passwordBytes.Count + $usernameBytes.Count + $PSCredentialHeader.Count + $sizeBytes.Count
            $pinnedArray  = New-Object PowerShellUtils.Cryptography.PinnedArray[byte]($bufferSize)

            $destIndex = 0

            [Array]::Copy($PSCredentialHeader, 0, $pinnedArray.Array, $destIndex, $PSCredentialHeader.Count)
            $destIndex += $PSCredentialHeader.Count
        
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
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]
        $ByteArray
    )

    [System.Text.Encoding]::UTF8.GetString($ByteArray)
}

function Convert-ByteArrayToSecureString
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]
        $ByteArray
    )

    $chars        = $null
    $memoryStream = $null
    $streamReader = $null

    try
    {
        $ss           = New-Object System.Security.SecureString            
        $memoryStream = New-Object System.IO.MemoryStream(,$ByteArray)
        $streamReader = New-Object System.IO.StreamReader($memoryStream, [System.Text.Encoding]::Unicode, $false)
        $chars        = New-Object PowerShellUtils.Cryptography.PinnedArray[char](1024)

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
        if ($chars -is [IDisposable])        { $chars.Dispose() }
    }

} # function Convert-ByteArrayToSecureString

function Convert-ByteArrayToPSCredential
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]
        $ByteArray
    )

    $message = 'Byte array is not a serialized PSCredential object.'

    if ($ByteArray.Count -lt $PSCredentialHeader.Count + 2) { throw $message }

    for ($i = 0; $i -lt $PSCredentialHeader.Count; $i++)
    {
        if ($ByteArray[$i] -ne $PSCredentialHeader[$i]) { throw $message }
    }

    $i = $PSCredentialHeader.Count

    $sizeBytes = $ByteArray[$i..($i+3)]
    if (-not [System.BitConverter]::IsLittleEndian) { [array]::Reverse($sizeBytes) }

    $i += 4
    $size = [System.BitConverter]::ToUInt32($sizeBytes, 0)

    if ($ByteArray.Count -lt $i + $size) { throw $message }

    $userName = [System.Text.Encoding]::Unicode.GetString($ByteArray, $i, $size)
    $i += $size

    try
    {
        $secureString = Convert-ByteArrayToSecureString -ByteArray $ByteArray[$i..($ByteArray.Count - 1)]
    }
    catch
    {
        throw $message
    }

    New-Object System.Management.Automation.PSCredential($userName, $secureString)

} # function Convert-ByteArrayToPSCredential

#endregion

Export-ModuleMember -Function 'Protect-Data', 'Unprotect-Data', 'Get-ProtectedDataSupportedTypes',
                              'Add-ProtectedDataCredential', 'Remove-ProtectedDataCredential',
                              'Get-KeyEncryptionCertificate'
