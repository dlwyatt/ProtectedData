Import-Module Pester -ErrorAction Stop

Set-StrictMode -Version Latest

$scriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$moduleManifest = Join-Path -Path $scriptRoot -ChildPath ProtectedData.psd1

. $scriptRoot\TestUtils.ps1

# Neat wildcard trick for removing a module if it's loaded, without producing errors if it's not.
Remove-Module [P]rotectedData
Import-Module $moduleManifest -Force -ErrorAction Stop

$stringToEncrypt = 'This is my string.'
$secureStringToEncrypt = $stringToEncrypt | ConvertTo-SecureString -AsPlainText -Force

$userName = 'UserName'
$credentialToEncrypt = New-Object System.Management.Automation.PSCredential($userName, $secureStringToEncrypt)

$byteArrayToEncrypt = [byte[]](1..10)

$passwordForEncryption = 'p@ssw0rd' | ConvertTo-SecureString -AsPlainText -Force
$wrongPassword = 'wr0ngp@ssw0rd' | ConvertTo-SecureString -AsPlainText -Force

$testCertificateSubject = 'CN=ProtectedData Test Certificate, OU=Unit Tests, O=ProtectedData, L=Somewhere, S=Ontario, C=CA'

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
            { Add-ProtectedDataCredential -InputObject $protected -Password $passwordForEncryption -NewPassword $wrongPassword } | 
            Should Not Throw
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

Describe 'Certificate-based encryption and decryption (By thumbprint)' {
    Remove-TestCertificate

    $path = @{}

    if ($PSVersionTable.PSVersion.Major -le 2)
    {
        # The certificate provider in PowerShell 2.0 is quite slow for some reason, and filtering
        # this test down to the store where we know the certs are located makes it less painful
        # to run this test.
        $path = @{ Path = 'Cert:\CurrentUser\My' }
    }

    $certThumbprint = New-TestCertificate -Subject $testCertificateSubject
    $secondCertThumbprint = New-TestCertificate -Subject $testCertificateSubject
    $wrongCertThumbprint = New-TestCertificate -Subject $testCertificateSubject

    Context 'Finding suitable certificates for encryption and decryption' {
        $certificates = @(
            Get-KeyEncryptionCertificate @path -SkipCertificateVerification -RequirePrivateKey |
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

        It 'No longer allows the data to be decrypted with the removed thumbprint' {
            { $null = Unprotect-Data -InputObject $protected -CertificateThumbprint $secondCertThumbprint -SkipCertificateVerification -ErrorAction Stop } | Should Throw
        }
    }

    Remove-TestCertificate
}

Describe 'Certificate-Based encryption and decryption (By certificate object)' {
    $certFromFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$scriptRoot\TestCertificateFile.pfx", 'password')
    $SecondCertFromFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$scriptRoot\TestCertificateFile2.pfx", 'password')
    $WrongCertFromFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$scriptRoot\TestCertificateFile3.pfx", 'password')

    Context 'General Usage' {
        It 'Produces an error if a self-signed certificate is used, without the -SkipCertificateVerification switch' {
            { $null = Protect-Data -InputObject $stringToEncrypt -Certificate $certFromFile -ErrorAction Stop } | Should Throw
        }

        It 'Does not produce an error when a self-signed certificate is used, if the -SkipCertificateVerification switch is also used.' {
            { $null = Protect-Data -InputObject $stringToEncrypt -Certificate $certFromFile -SkipCertificateVerification -ErrorAction Stop } | Should Not Throw
        }

        $protected = Protect-Data -InputObject $stringToEncrypt -Certificate $certFromFile, $secondCertFromFile -SkipCertificateVerification

        It 'Produces an error if a decryption attempt with the wrong certificate is made.' {
            { $null = Unprotect-Data -InputObject $protected -Certificate $wrongCertFromFile -SkipCertificateVerification -ErrorAction Stop } | Should Throw
        }

        It 'Allows any of the specified certificates to be used during decryption (First certificate test)' {
            { $null = Unprotect-Data -InputObject $protected -Certificate $certFromFile -SkipCertificateVerification -ErrorAction Stop } | Should Not Throw
        }

        It 'Allows any of the specified certificates to be used during decryption (Second certificate test)' {
            { $null = Unprotect-Data -InputObject $protected -Certificate $secondCertFromFile -SkipCertificateVerification -ErrorAction Stop } | Should Not Throw
        }

        It 'Adds a new certificate to an existing object' {
            $scriptBlock = {
                Add-ProtectedDataCredential -InputObject $protected -Certificate $secondCertFromFile -NewCertificate $wrongCertFromFile -SkipCertificateVerification
            }

            $scriptBlock | Should Not Throw
        }

        It 'Allows the object to be decrypted with the new certificate' {
            { $null = Unprotect-Data -InputObject $protected -Certificate $wrongCertFromFile -SkipCertificateVerification -ErrorAction Stop } | Should Not Throw
        }

        It 'Removes a certificate from the object' {
            { $null = Remove-ProtectedDataCredential -InputObject $protected -Certificate $secondCertFromFile } | Should Not Throw
        }

        It 'No longer allows the data to be decrypted with the removed certificate' {
            { $null = Unprotect-Data -InputObject $protected -Certificate $secondCertFromFile -SkipCertificateVerification -ErrorAction Stop } | Should Throw
        }
    }

    Context 'Protecting strings' {
        $protectedData = $stringToEncrypt | Protect-Data -Certificate $certFromFile -SkipCertificateVerification
        $decrypted = $protectedData | Unprotect-Data -Certificate $certFromFile -SkipCertificateVerification

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
        $protectedData = $secureStringToEncrypt | Protect-Data -Certificate $certFromFile -SkipCertificateVerification
        $decrypted = $protectedData | Unprotect-Data -Certificate $certFromFile -SkipCertificateVerification

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
        $protectedData = $credentialToEncrypt | Protect-Data -Certificate $certFromFile -SkipCertificateVerification
        $decrypted = $protectedData | Unprotect-Data -Certificate $certFromFile -SkipCertificateVerification

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
        $protectedData = Protect-Data -InputObject $byteArrayToEncrypt -Certificate $certFromFile -SkipCertificateVerification
        $decrypted = Unprotect-Data -InputObject $protectedData -Certificate $certFromFile -SkipCertificateVerification

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

Describe 'Legacy Padding Support' {
    $certFromFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$scriptRoot\TestCertificateFile.pfx", 'password')
    $stringToEncrypt = 'This is a test'

    Context 'Loading protected data from previous version of module' {
        $protectedData = Import-Clixml -Path $scriptRoot\V1.0.ProtectedWithTestCertificateFile.pfx.xml
        Set-StrictMode -Version Latest

        It 'Unprotects the data properly even with strict mode enabled' {
            { $protectedData | Unprotect-Data -Certificate $certFromFile -SkipCertificateVerification } | Should Not Throw
            $protectedData | Unprotect-Data -Certificate $certFromFile -SkipCertificateVerification | Should Be $stringToEncrypt
        }
    }

    Context 'Using legacy padding' {
        $protectedData = Protect-Data -InputObject $stringToEncrypt -Certificate $certFromFile -SkipCertificateVerification -UseLegacyPadding

        It 'Assigns the use legacy padding property' {
            $protectedData.KeyData[0].LegacyPadding | Should Be $true
        }

        It 'Decrypts data properly' {
            $protectedData |
            Unprotect-Data -Certificate $certFromFile -SkipCertificateVerification |
            Should Be $stringToEncrypt
        }
    }

    Context 'Using OAEP padding' {
        $protectedData = Protect-Data -InputObject $stringToEncrypt -Certificate $certFromFile -SkipCertificateVerification

        It 'Does not assign the use legacy padding property' {
            $protectedData.KeyData[0].LegacyPadding | Should Be $false
        }

        It 'Decrypts data properly' {
            $protectedData |
            Unprotect-Data -Certificate $certFromFile -SkipCertificateVerification |
            Should Be $stringToEncrypt
        }
    }
}

Describe 'RSA Certificates (CNG Key Storage Provider)' {
    Context 'RSA Certificates (CNG Key Storage Provider)' {
        $thumbprint = New-TestCertificate -Subject $testCertificateSubject -CertificateType RsaCng
        $testCert = Get-Item Cert:\CurrentUser\My\$thumbprint

        $protectedData = Protect-Data -InputObject $stringToEncrypt -Certificate $testCert -SkipCertificateVerification

        It 'Decrypts data successfully using an RSA cert using a CNG KSP' {
            Unprotect-Data -InputObject $protectedData -Certificate $testCert -SkipCertificateVerification |
            Should Be $stringToEncrypt
        }

        $protectedWithLegacyPadding = Protect-Data -InputObject $stringToEncrypt -Certificate $testCert -SkipCertificateVerification -UseLegacyPadding

        It 'Decrypts data successfully with legacy padding' {
            Unprotect-Data -InputObject $protectedWithLegacyPadding -Certificate $testCert -SkipCertificateVerification |
            Should Be $stringToEncrypt
        }
    }

    Remove-TestCertificate
}

Describe 'ECDH Certificates' {
    Context 'ECDH_P256' {
        $thumbprint = New-TestCertificate -Subject $testCertificateSubject -CertificateType Ecdh_P256
        $testCert = Get-Item Cert:\CurrentUser\My\$thumbprint

        $protectedData = Protect-Data -InputObject $stringToEncrypt -Certificate $testCert -SkipCertificateVerification

        It 'Decrypts data successfully using an ECDH_P256 certificate' {
            Unprotect-Data -InputObject $protectedData -Certificate $testCert -SkipCertificateVerification |
            Should Be $stringToEncrypt
        }
    }

    Context 'ECDH_P384' {
        $thumbprint = New-TestCertificate -Subject $testCertificateSubject -CertificateType Ecdh_P384
        $testCert = Get-Item Cert:\CurrentUser\My\$thumbprint

        $protectedData = Protect-Data -InputObject $stringToEncrypt -Certificate $testCert -SkipCertificateVerification

        It 'Decrypts data successfully using an ECDH_P384 certificate' {
            Unprotect-Data -InputObject $protectedData -Certificate $testCert -SkipCertificateVerification |
            Should Be $stringToEncrypt
        }
    }

    Context 'ECDH_P521' {
        $thumbprint = New-TestCertificate -Subject $testCertificateSubject -CertificateType Ecdh_P521
        $testCert = Get-Item Cert:\CurrentUser\My\$thumbprint

        $protectedData = Protect-Data -InputObject $stringToEncrypt -Certificate $testCert -SkipCertificateVerification

        It 'Decrypts data successfully using an ECDH certificate' {
            Unprotect-Data -InputObject $protectedData -Certificate $testCert -SkipCertificateVerification |
            Should Be $stringToEncrypt
        }
    }

    Remove-TestCertificate
}
