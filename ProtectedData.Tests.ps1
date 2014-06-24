Import-Module Pester -ErrorAction Stop

$scriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent

$stringToEncrypt = 'This is my string.'
$secureStringToEncrypt = $stringToEncrypt | ConvertTo-SecureString -AsPlainText -Force

$userName = 'UserName'
$credentialToEncrypt = New-Object System.Management.Automation.PSCredential($userName, $secureStringToEncrypt)

$byteArrayToEncrypt = [byte[]](1..10)

$passwordForEncryption = 'p@ssw0rd' | ConvertTo-SecureString -AsPlainText -Force
$wrongPassword = 'wr0ngp@ssw0rd' | ConvertTo-SecureString -AsPlainText -Force

$testCertificateSubject = 'CN=ProtectedData Test Certificate, OU=Unit Tests, O=ProtectedData, L=Somewhere, S=Ontario, C=CA'

function Get-PlainTextFromSecureString
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.SecureString]
        $SecureString
    )

    process
    {
        $ptr = $null

        try
        {
            $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecureString)
            [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)
        }
        finally
        {
            if ($null -ne $ptr) { [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr) }
        }
    }
}

function New-TestCertificate
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Subject,

        [Nullable[DateTime]]
        $NotBefore,

        [Nullable[DateTime]]
        $NotAfter
    )

    if ($null -eq $NotBefore)
    {
        $NotBefore = (Get-Date).AddDays(-7)
    }

    if ($null -eq $NotAfter)
    {
        $NotAfter = (Get-Date).AddDays(7)
    }

    if ($NotBefore -ge $NotAfter)
    {
        throw 'NotAfter date/time must take place after NotBefore'
    }

    $notBeforeString = $NotBefore.ToString('G')
    $notAfterString = $NotAfter.ToString('G')

    $requestfile = [System.IO.Path]::GetTempFileName()
    $certFile = [System.IO.Path]::GetTempFileName()

    Set-Content -Path $requestfile -Encoding Ascii -Value @"
[Version]

Signature="`$Windows NT`$"

[NewRequest]

Subject = "$Subject"
KeyLength = 2048
; Can be 2048, 4096, 8192, or 16384.
; Larger key sizes are more secure, but have
; a greater impact on performance.
Exportable = TRUE
FriendlyName = "ProtectedData"
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = Cert
Silent = True
SuppressDefaults = True
KeySpec = AT_KEYEXCHANGE
KeyUsage = CERT_KEY_ENCIPHERMENT_KEY_USAGE
NotBefore = "$notBeforeString"
NotAfter = "$notAfterString"

"@
    
    try
    {
        $oldCerts = @(
            Get-ChildItem Cert:\CurrentUser\My |
            Where-Object { $_.Subject -eq $Subject } |
            Select-Object -ExpandProperty Thumbprint
        )

        $null = certreq -new -f -q $requestfile $certFile 2>&1

        $newCert = Get-ChildItem Cert:\CurrentUser\My -Exclude $oldCerts |
                   Where-Object { $_.Subject -eq $Subject } |
                   Select-Object -ExpandProperty Thumbprint

        return $newCert
    }
    finally
    {
        Remove-Item -Path $requestfile -Force -ErrorAction SilentlyContinue
        Remove-Item -Path $certFile -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Module Load' {
    It 'Loads the module without errors' {
        $moduleManifest = Join-Path -Path $scriptRoot -ChildPath ProtectedData.psd1
        { Import-Module $moduleManifest -Force -ErrorAction Stop } | Should Not Throw
    }
}

Describe 'Password-based encryption and decryption' {
    Context 'General Usage' {
        $blankSecureString = New-Object System.Security.SecureString
        $blankSecureString.MakeReadOnly()

        $secondPassword = 'Some other password' | ConvertTo-SecureString -AsPlainText -Force

        It 'Produces an error if a blank password is used' {
            { $null = Protect-Data -InputObject $stringToEncrypt -Password $blankSecureString -ErrorAction Stop } | Should Throw
        }

        It 'Does not produce an error when a non-blank password is used' {
            { $null = Protect-Data -InputObject $stringToEncrypt -Password $passwordForEncryption -ErrorAction Stop } | Should Not Throw
        }

        $protected = Protect-Data -InputObject $stringToEncrypt -Password $passwordForEncryption, $secondPassword

        It 'Produces an error if a decryption attempt with the wrong password is made.' {
            { $null = Unprotect-Data -InputObject $protected -Password $wrongPassword -ErrorAction Stop } | Should Throw
        }

        It 'Allows any of the passwords to be used when decrypting.  (First password test)' {
            { $null = Unprotect-Data -InputObject $protected -Password $passwordForEncryption -ErrorAction Stop } | Should Not Throw
        }

        It 'Allows any of the passwords to be used when decrypting.  (Second password test)' {
            { $null = Unprotect-Data -InputObject $protected -Password $secondPassword -ErrorAction Stop } | Should Not Throw
        }

        It 'Adds a new password to an existing object' {
            $scriptBlock = { Add-ProtectedDataCredential -InputObject $protected -Password $passwordForEncryption -NewPassword $wrongPassword }
            $scriptBlock | Should Not Throw
        }

        It 'Allows the object to be decrypted with the new password' {
            { $null = Unprotect-Data -InputObject $protected -Password $wrongPassword } | Should Not Throw
        }

        It 'Removes a password from the object' {
            { $null = Remove-ProtectedDataCredential -InputObject $protected -Password $secondPassword } | Should Not Throw
        }

        It 'No longer allows the data to be decrypted with the removed password' {
            { $null = Unprotect-Data -InputObject $protected -Password $secondPassword -ErrorAction Stop } | Should Throw
        }
    }

    Context 'Protecting strings' {
        $protectedData = $stringToEncrypt | Protect-Data -Password $passwordForEncryption
        $decrypted = $protectedData | Unprotect-Data -Password $passwordForEncryption

        It 'Does not return null' {
            $decrypted | Should Not Be $null
        }

        It 'Returns a String object' {
            $decrypted.GetType().FullName | Should Be System.String
        }

        It 'Decrypts the string properly.' {
            $decrypted | Should Be $stringToEncrypt
        }
    }

    Context 'Protecting SecureStrings' {
        $protectedData = $secureStringToEncrypt | Protect-Data -Password $passwordForEncryption
        $decrypted = $protectedData | Unprotect-Data -Password $passwordForEncryption

        It 'Does not return null' {
            $decrypted | Should Not Be $null
        }

        It 'Returns a SecureString object' {
            $decrypted.GetType().FullName | Should Be System.Security.SecureString
        }

        It 'Decrypts the SecureString properly.' {
            Get-PlainTextFromSecureString -SecureString $decrypted | Should Be $stringToEncrypt
        }
    }

    Context 'Protecting PSCredentials' {
        $protectedData = $credentialToEncrypt | Protect-Data -Password $passwordForEncryption
        $decrypted = $protectedData | Unprotect-Data -Password $passwordForEncryption

        It 'Does not return null' {
            $decrypted | Should Not Be $null
        }

        It 'Returns a PSCredential object' {
            $decrypted.GetType().FullName | Should Be System.Management.Automation.PSCredential
        }

        It 'Decrypts the PSCredential properly (username)' {
            $decrypted.UserName | Should Be $userName
        }

        It 'Decrypts the PSCredential properly (password)' {
            Get-PlainTextFromSecureString -SecureString $decrypted.Password | Should Be $stringToEncrypt
        }
    }

    Context 'Protecting Byte Arrays' {
        $protectedData = Protect-Data -InputObject $byteArrayToEncrypt -Password $passwordForEncryption
        $decrypted = Unprotect-Data -InputObject $protectedData -Password $passwordForEncryption

        It 'Does not return null' {
            ,$decrypted | Should Not Be $null
        }

        It 'Returns a byte array' {
            $decrypted.GetType().FullName | Should Be System.Byte[]
        }

        It 'Decrypts the byte array properly' {
            ($byteArrayToEncrypt.Length -eq $decrypted.Length -and (-join $byteArrayToEncrypt) -eq (-join $decrypted)) | Should Be $True
        }
    }
}

Describe 'Certificate-based encryption and decryption' {
    Get-ChildItem Cert:\CurrentUser\My |
    Where-Object { $_.Subject -eq $testCertificateSubject } |
    Remove-Item

    $certThumbprint = New-TestCertificate -Subject $testCertificateSubject
    $secondCertThumbprint = New-TestCertificate -Subject $testCertificateSubject
    $wrongCertThumbprint = New-TestCertificate -Subject $testCertificateSubject

    Context 'Finding suitable certificates for encryption and decryption' {
        $certificates = @(
            Get-KeyEncryptionCertificate -SkipCertificateVerification -RequirePrivateKey |
            Where-Object { ($certThumbprint, $secondCertThumbprint, $wrongCertThumbprint) -contains $_.Thumbprint }
        )

        It 'Find the test certificates' {
            $certificates.Count | Should Be 3
        }
    }

    Context 'General Usage' {
        It 'Produces an error if a self-signed certificate is used, without the -SkipCertificateVerification switch' {
            { $null = Protect-Data -InputObject $stringToEncrypt -CertificateThumbprint $certThumbprint -ErrorAction Stop } | Should Throw
        }

        It 'Does not produce an error when a self-signed certificate is used, if the -SkipCertificateVerification switch is also used.' {
            { $null = Protect-Data -InputObject $stringToEncrypt -CertificateThumbprint $certThumbprint -SkipCertificateVerification -ErrorAction Stop } | Should Not Throw
        }

        $protected = Protect-Data -InputObject $stringToEncrypt -CertificateThumbprint $certThumbprint, $secondCertThumbprint -SkipCertificateVerification

        It 'Produces an error if a decryption attempt with the wrong certificate is made.' {
            { $null = Unprotect-Data -InputObject $protected -CertificateThumbprint $wrongCertThumbprint -SkipCertificateVerification -ErrorAction Stop } | Should Throw
        }

        It 'Allows any of the specified certificates to be used during decryption (First thumbprint test)' {
            { $null = Unprotect-Data -InputObject $protected -CertificateThumbprint $certThumbprint -SkipCertificateVerification -ErrorAction Stop } | Should Not Throw            
        }

        It 'Allows any of the specified certificates to be used during decryption (Second thumbprint test)' {
            { $null = Unprotect-Data -InputObject $protected -CertificateThumbprint $secondCertThumbprint -SkipCertificateVerification -ErrorAction Stop } | Should Not Throw            
        }

        It 'Adds a new certificate to an existing object' {
            $scriptBlock = {
                Add-ProtectedDataCredential -InputObject $protected -CertificateThumbprint $secondCertThumbprint -NewCertificateThumbprint $wrongCertThumbprint -SkipCertificateVerification
            }

            $scriptBlock | Should Not Throw
        }

        It 'Allows the object to be decrypted with the new certificate' {
            { $null = Unprotect-Data -InputObject $protected -CertificateThumbprint $wrongCertThumbprint -SkipCertificateVerification -ErrorAction Stop } | Should Not Throw
        }

        It 'Removes a certificate from the object' {
            { $null = Remove-ProtectedDataCredential -InputObject $protected -CertificateThumbprint $secondCertThumbprint } | Should Not Throw
        }

        It 'No longer allows the data to be decrypted with the removed password' {
            { $null = Unprotect-Data -InputObject $protected -CertificateThumbprint $secondCertThumbprint -SkipCertificateVerification -ErrorAction Stop } | Should Throw
        }
    }

    Context 'Protecting strings' {
        $protectedData = $stringToEncrypt | Protect-Data -CertificateThumbprint $certThumbprint -SkipCertificateVerification
        $decrypted = $protectedData | Unprotect-Data -CertificateThumbprint $certThumbprint -SkipCertificateVerification

        It 'Does not return null' {
            $decrypted | Should Not Be $null
        }

        It 'Returns a String object' {
            $decrypted.GetType().FullName | Should Be System.String
        }

        It 'Decrypts the string properly.' {
            $decrypted | Should Be $stringToEncrypt
        }
    }

    Context 'Protecting SecureStrings' {
        $protectedData = $secureStringToEncrypt | Protect-Data -CertificateThumbprint $certThumbprint -SkipCertificateVerification
        $decrypted = $protectedData | Unprotect-Data -CertificateThumbprint $certThumbprint -SkipCertificateVerification

        It 'Does not return null' {
            $decrypted | Should Not Be $null
        }

        It 'Returns a SecureString object' {
            $decrypted.GetType().FullName | Should Be System.Security.SecureString
        }

        It 'Decrypts the SecureString properly.' {
            Get-PlainTextFromSecureString -SecureString $decrypted | Should Be $stringToEncrypt
        }
    }

    Context 'Protecting PSCredentials' {
        $protectedData = $credentialToEncrypt | Protect-Data -CertificateThumbprint $certThumbprint -SkipCertificateVerification
        $decrypted = $protectedData | Unprotect-Data -CertificateThumbprint $certThumbprint -SkipCertificateVerification

        It 'Does not return null' {
            $decrypted | Should Not Be $null
        }

        It 'Returns a PSCredential object' {
            $decrypted.GetType().FullName | Should Be System.Management.Automation.PSCredential
        }

        It 'Decrypts the PSCredential properly (username)' {
            $decrypted.UserName | Should Be $userName
        }

        It 'Decrypts the PSCredential properly (password)' {
            Get-PlainTextFromSecureString -SecureString $decrypted.Password | Should Be $stringToEncrypt
        }
    }

    Context 'Protecting Byte Arrays' {
        $protectedData = Protect-Data -InputObject $byteArrayToEncrypt -CertificateThumbprint $certThumbprint -SkipCertificateVerification
        $decrypted = Unprotect-Data -InputObject $protectedData -CertificateThumbprint $certThumbprint -SkipCertificateVerification

        It 'Does not return null' {
            ,$decrypted | Should Not Be $null
        }

        It 'Returns a byte array' {
            $decrypted.GetType().FullName | Should Be System.Byte[]
        }

        It 'Decrypts the byte array properly' {
            ($byteArrayToEncrypt.Length -eq $decrypted.Length -and (-join $byteArrayToEncrypt) -eq (-join $decrypted)) | Should Be $True
        }
    }
}