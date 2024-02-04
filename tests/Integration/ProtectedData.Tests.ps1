BeforeAll {
    $testPath = "$projectPath\tests"

    Import-Module -Name ProtectedData -Force -ErrorAction Stop

    . $testPath\TestHelpers\TestUtils.ps1

    $iterationCount = 20

    $stringToEncrypt = 'This is my string.'
    $secureStringToEncrypt = $stringToEncrypt | ConvertTo-SecureString -AsPlainText -Force

    $passwordForEncryption = 'p@ssw0rd' | ConvertTo-SecureString -AsPlainText -Force
    $wrongPassword = 'wr0ngp@ssw0rd' | ConvertTo-SecureString -AsPlainText -Force

    $secondPassword = 'Some other password' | ConvertTo-SecureString -AsPlainText -Force

    $blankSecureString = New-Object System.Security.SecureString
    $blankSecureString.MakeReadOnly()

    $testCertificateSubject = 'CN=ProtectedData Test Certificate, OU=Unit Tests, O=ProtectedData, L=Somewhere, S=Ontario, C=CA'

    $certFromFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$testPath\Assets\TestCertificateFile.pfx", 'password')
    $secondCertFromFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$testPath\Assets\TestCertificateFile2.pfx", 'password')
    $wrongCertFromFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$testPath\Assets\TestCertificateFile3.pfx", 'password')
    $protected = Protect-Data -InputObject $stringToEncrypt -Certificate $certFromFile, $secondCertFromFile

    $userName = 'UserName'
    $credentialToEncrypt = New-Object System.Management.Automation.PSCredential($userName, $secureStringToEncrypt)

    $byteArrayToEncrypt = [byte[]](1..10)
}

Describe 'Password-based encryption and decryption' {

    BeforeAll {
        $protected = Protect-Data -InputObject $stringToEncrypt -Password $passwordForEncryption, $secondPassword -PasswordIterationCount $iterationCount
    }

    Context 'General Usage' {
        It 'Produces an error if a blank password is used' {
            { $null = Protect-Data -InputObject $stringToEncrypt -Password $blankSecureString -ErrorAction Stop -PasswordIterationCount $iterationCount } | Should -Throw
        }

        It 'Does not produce an error when a non-blank password is used' {
            { $null = Protect-Data -InputObject $stringToEncrypt -Password $passwordForEncryption -ErrorAction Stop -PasswordIterationCount $iterationCount } | Should -Not -Throw
        }

        It 'Produces an error if a decryption attempt with the wrong password is made.' {
            { $null = Unprotect-Data -InputObject $protected -Password $wrongPassword -ErrorAction Stop } | Should -Throw
        }

        It 'Allows any of the passwords to be used when decrypting.  (First password test)' {
            { $null = Unprotect-Data -InputObject $protected -Password $passwordForEncryption -ErrorAction Stop } | Should -Not -Throw
        }

        It 'Allows any of the passwords to be used when decrypting.  (Second password test)' {
            { $null = Unprotect-Data -InputObject $protected -Password $secondPassword -ErrorAction Stop } | Should -Not -Throw
        }

        It 'Adds a new password to an existing object' {
            { Add-ProtectedDataCredential -InputObject $protected -Password $passwordForEncryption -NewPassword $wrongPassword -ErrorAction Stop -PasswordIterationCount $iterationCount } |
                Should -Not -Throw
        }

        It 'Uses the proper iteration count when Add-ProtectedDataCredential was called' {
            $wrong = $protected.KeyData | Where-Object { $null -ne $_.PSObject.Properties['IterationCount'] -and $_.IterationCount -ne $iterationCount }
            $wrong | Should -BeNullOrEmpty
        }

        It 'Allows the object to be decrypted with the new password' {
            { $null = Unprotect-Data -InputObject $protected -Password $wrongPassword -ErrorAction Stop } | Should -Not -Throw
        }

        It 'Removes a password from the object' {
            { $null = Remove-ProtectedDataCredential -InputObject $protected -Password $secondPassword -ErrorAction Stop } | Should -Not -Throw
        }

        It 'No longer allows the data to be decrypted with the removed password' {
            { $null = Unprotect-Data -InputObject $protected -Password $secondPassword -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Protecting strings' {

        BeforeAll {
            $protectedData = $stringToEncrypt | Protect-Data -Password $passwordForEncryption -PasswordIterationCount $iterationCount
            $decrypted = $protectedData | Unprotect-Data -Password $passwordForEncryption
        }

        It 'Does not return null' {
            $decrypted | Should -Not -BeNullOrEmpty
        }

        It 'Returns a String object' {
            $decrypted | Should -BeOfType System.String
        }

        It 'Decrypts the string properly.' {
            $decrypted | Should -Be $stringToEncrypt
        }
    }

    Context 'Protecting SecureStrings' {

        BeforeAll {
            $protectedData = $secureStringToEncrypt | Protect-Data -Password $passwordForEncryption -PasswordIterationCount $iterationCount
            $decrypted = $protectedData | Unprotect-Data -Password $passwordForEncryption
        }

        It 'Does not return null' {
            $decrypted | Should -Not -BeNullOrEmpty
        }

        It 'Returns a SecureString object' {
            $decrypted | Should -BeOfType System.Security.SecureString
        }

        It 'Decrypts the SecureString properly.' {
            Get-PlainTextFromSecureString -SecureString $decrypted | Should -Be $stringToEncrypt
        }
    }

    Context 'Protecting PSCredentials' {

        BeforeAll {
            $protectedData = $credentialToEncrypt | Protect-Data -Password $passwordForEncryption -PasswordIterationCount $iterationCount
            $decrypted = $protectedData | Unprotect-Data -Password $passwordForEncryption
        }

        It 'Does not return null' {
            $decrypted | Should -Not -BeNullOrEmpty
        }

        It 'Returns a PSCredential object' {
            $decrypted | Should -BeOfType System.Management.Automation.PSCredential
        }

        It 'Decrypts the PSCredential properly (username)' {
            $decrypted.UserName | Should -Be $userName
        }

        It 'Decrypts the PSCredential properly (password)' {
            Get-PlainTextFromSecureString -SecureString $decrypted.Password | Should -Be $stringToEncrypt
        }
    }

    Context 'Protecting Byte Arrays' {

        BeforeAll {
            $protectedData = Protect-Data -InputObject $byteArrayToEncrypt -Password $passwordForEncryption -PasswordIterationCount $iterationCount
            $decrypted = Unprotect-Data -InputObject $protectedData -Password $passwordForEncryption
        }

        It 'Does not return null' {
            , $decrypted | Should -Not -BeNullOrEmpty
        }

        It 'Returns a byte array' {
            Should -ActualValue $decrypted -BeOfType 'System.Byte[]'
        }

        It 'Decrypts the byte array properly' {
            ($byteArrayToEncrypt.Length -eq $decrypted.Length -and (-join $byteArrayToEncrypt) -eq (-join $decrypted)) | Should -Be $True
        }
    }
}

Describe 'Certificate-based encryption and decryption (By thumbprint)' {

    BeforeAll {
        Import-Module -Name ProtectedData -Force -ErrorAction Stop

        . $projectPath\tests\TestHelpers\TestUtils.ps1

        Remove-TestCertificate

        $path = @{}

        $certThumbprint = New-TestCertificate -Subject $testCertificateSubject
        $secondCertThumbprint = New-TestCertificate -Subject $testCertificateSubject
        $wrongCertThumbprint = New-TestCertificate -Subject $testCertificateSubject

        $stringToEncrypt = 'This is my string.'
        $secureStringToEncrypt = $stringToEncrypt | ConvertTo-SecureString -AsPlainText -Force
    }

    Context 'Finding suitable certificates for encryption and decryption' {

        BeforeAll {
            $certificates = @(
                Get-KeyEncryptionCertificate @path -RequirePrivateKey |
                    Where-Object { ($certThumbprint, $secondCertThumbprint, $wrongCertThumbprint) -contains $_.Thumbprint }
            )
        }

        It 'Find the test certificates' {
            $certificates.Count | Should -Be 3
        }
    }

    Context 'General Usage' {

        BeforeAll {
            $protected = Protect-Data -InputObject $stringToEncrypt -Certificate $certThumbprint
        }

        It 'Decrypts data successfully' {
            Unprotect-Data -InputObject $protected -Certificate $certThumbprint -ErrorAction Stop | Should -Be $stringToEncrypt
        }
    }

    AfterAll {
        Remove-TestCertificate
    }
}

Describe 'Certificate-Based encryption and decryption (By certificate object)' {


    Context 'General Usage' {
        It 'Does not produce an error when a self-signed or otherwise invalid certificate is used.' {
            { $null = Protect-Data -InputObject $stringToEncrypt -Certificate $certFromFile -ErrorAction Stop } | Should -Not -Throw
        }



        It 'Produces an error if a decryption attempt with the wrong certificate is made.' {
            { $null = Unprotect-Data -InputObject $protected -Certificate $wrongCertFromFile -ErrorAction Stop } | Should -Throw
        }

        It 'Allows any of the specified certificates to be used during decryption (First certificate test)' {
            { $null = Unprotect-Data -InputObject $protected -Certificate $certFromFile -ErrorAction Stop } | Should -Not -Throw
        }

        It 'Allows any of the specified certificates to be used during decryption (Second certificate test)' {
            { $null = Unprotect-Data -InputObject $protected -Certificate $secondCertFromFile -ErrorAction Stop } | Should -Not -Throw
        }

        It 'Adds a new certificate to an existing object' {
            $scriptBlock = {
                Add-ProtectedDataCredential -InputObject $protected -Certificate $secondCertFromFile -NewCertificate $wrongCertFromFile -ErrorAction Stop
            }

            $scriptBlock | Should -Not -Throw
        }

        It 'Allows the object to be decrypted with the new certificate' {
            { $null = Unprotect-Data -InputObject $protected -Certificate $wrongCertFromFile -ErrorAction Stop } | Should -Not -Throw
        }

        It 'Removes a certificate from the object' {
            { $null = Remove-ProtectedDataCredential -InputObject $protected -Certificate $secondCertFromFile -ErrorAction Stop } | Should -Not -Throw
        }

        It 'No longer allows the data to be decrypted with the removed certificate' {
            { $null = Unprotect-Data -InputObject $protected -Certificate $secondCertFromFile -ErrorAction Stop } | Should -Throw
        }
    }

    Context 'Protecting strings' {
        BeforeAll {
            $protectedData = $stringToEncrypt | Protect-Data -Certificate $certFromFile
            $decrypted = $protectedData | Unprotect-Data -Certificate $certFromFile
        }

        It 'Does not return null' {
            $decrypted | Should -Not -Be $null
        }

        It 'Returns a String object' {
            $decrypted.GetType().FullName | Should -Be System.String
        }

        It 'Decrypts the string properly.' {
            $decrypted | Should -Be $stringToEncrypt
        }
    }

    Context 'Protecting SecureStrings' {
        BeforeAll {
            $protectedData = $secureStringToEncrypt | Protect-Data -Certificate $certFromFile
            $decrypted = $protectedData | Unprotect-Data -Certificate $certFromFile
        }

        It 'Does not return null' {
            $decrypted | Should -Not -Be $null
        }

        It 'Returns a SecureString object' {
            $decrypted.GetType().FullName | Should -Be System.Security.SecureString
        }

        It 'Decrypts the SecureString properly.' {
            Get-PlainTextFromSecureString -SecureString $decrypted | Should -Be $stringToEncrypt
        }
    }

    Context 'Protecting PSCredentials' {
        BeforeAll {
            $protectedData = $credentialToEncrypt | Protect-Data -Certificate $certFromFile
            $decrypted = $protectedData | Unprotect-Data -Certificate $certFromFile
        }

        It 'Does not return null' {
            $decrypted | Should -Not -Be $null
        }

        It 'Returns a PSCredential object' {
            $decrypted.GetType().FullName | Should -Be System.Management.Automation.PSCredential
        }

        It 'Decrypts the PSCredential properly (username)' {
            $decrypted.UserName | Should -Be $userName
        }

        It 'Decrypts the PSCredential properly (password)' {
            Get-PlainTextFromSecureString -SecureString $decrypted.Password | Should -Be $stringToEncrypt
        }
    }

    Context 'Protecting Byte Arrays' {
        BeforeAll {
            $protectedData = Protect-Data -InputObject $byteArrayToEncrypt -Certificate $certFromFile
            $decrypted = Unprotect-Data -InputObject $protectedData -Certificate $certFromFile
        }

        It 'Does not return null' {
            , $decrypted | Should -Not -Be $null
        }

        It 'Returns a byte array' {
            $decrypted.GetType().FullName | Should -Be System.Byte[]
        }

        It 'Decrypts the byte array properly' {
            ($byteArrayToEncrypt.Length -eq $decrypted.Length -and (-join $byteArrayToEncrypt) -eq (-join $decrypted)) | Should -Be $True
        }
    }
}


Describe 'Certificate-based encryption / decryption (by file system path)' {

    BeforeAll {
        $hash = @{
            ProtectedData = $null
        }
    }

    It 'Encrypts data successfully with a relative filesystem path to a certificate file' {
        { $hash.ProtectedData = Protect-Data -InputObject $stringToEncrypt -Certificate "$testPath\Assets\TestCertificateFile.cer" -ErrorAction Stop } |
            Should -Not -Throw
    }

    It 'Decrypts the data successfully' {
        Unprotect-Data -InputObject $hash.ProtectedData -Certificate $certFromFile | Should -Be $stringToEncrypt
    }
}

Describe 'Certificate-based encryption / decryption (by certificate path)' {

    BeforeAll {

        $testThumbprint = New-TestCertificate -Subject $testCertificateSubject
        $hash = @{}

    }

    It 'Encrypts data successfully with a relative certificate provider path' {
        BeforeAll {
            $hash.ProtectedData = Protect-Data $stringToEncrypt -Certificate "$testPath\Assets\TestCertificateFile.cer" -ErrorAction Stop
        }

        try
        {
            { $hash.ProtectedData = Protect-Data $stringToEncrypt -Certificate "Cert:\CurrentUser\My\$testThumbprint" -ErrorAction Stop } |
                Should -Not -Throw
        }
        finally
        {
            Pop-Location
        }
    }

    It 'Decrypts the data successfully' {
        try
        {
            Unprotect-Data -InputObject $hash.ProtectedData -Certificate "Cert:\CurrentUser\My\$testThumbprint" |
                Should -Be $stringToEncrypt
        }
        finally
        {
            Pop-Location
        }
    }
}


Describe 'Certificate-based decryption (automatic detection of cert)' {

    BeforeAll {
        Remove-TestCertificate
        $certThumbprint = New-TestCertificate -Subject $testCertificateSubject
        $protectedData = $stringToEncrypt | Protect-Data -Certificate Cert:\CurrentUser\My\$certThumbprint
    }

    It 'Successfully finds the matching certificate and decrypts the data' {
        $hash = @{}
        { $hash.Decrypted = Unprotect-Data $protectedData } | Should -Not -Throw
        $hash.Decrypted | Should -Be $stringToEncrypt
    }

    It 'Gives a useful error message when no matching certificate is found' {
        Remove-TestCertificate
        { $null = Unprotect-Data $protectedData -ErrorAction Stop } | Should -Throw 'No decryption certificate for the specified InputObject was found.'
    }
}

Describe 'HMAC authentication of AES data' {

    BeforeAll {
        $protectedData = $stringToEncrypt | Protect-Data -Password $passwordForEncryption

        $cipherText = $protectedData.CipherText.Clone()
    }

    It 'Throws an error if the ciphertext has been modified' {
        $protectedData.CipherText[0] = ($protectedData.CipherText[0] + 12) % 256
        { $protectedData | Unprotect-Data -Password $passwordForEncryption -ErrorAction Stop } | Should -Throw 'Decryption failed due to invalid HMAC.'
    }

    It 'Throws an error if the HMAC has been modified' {
        $protectedData.CipherText = $cipherText.Clone()

        $protectedData.HMAC[0] = ($protectedData.HMAC[0] + 12) % 256
        { $protectedData | Unprotect-Data -Password $passwordForEncryption -ErrorAction Stop } | Should -Throw 'Decryption failed due to invalid HMAC.'
    }
}

Describe 'Legacy Padding Support' {

    BeforeAll {
        $certFromFile = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("$PSScriptRoot\..\Assets\TestCertificateFile.pfx", 'password')
        $stringToEncrypt = 'This is a test'
    }

    Context 'Loading protected data from previous version of module' {

        BeforeAll {
            $protectedData = Import-Clixml -Path "$PSScriptRoot\..\Assets\V1.0.ProtectedWithTestCertificateFile.pfx.xml"
            Set-StrictMode -Version Latest
        }

        It 'Throws an error if the HMAC code is missing' {
            { $protectedData | Unprotect-Data -Certificate $certFromFile -ErrorAction Stop } | Should -Throw 'Input Object contained no HMAC code.'
        }

        It 'Adds an HMAC to the legacy object' {
            $protectedData | Add-ProtectedDataHmac -Certificate $certFromFile
            , $protectedData.HMAC | Should -Not -BeNullOrEmpty
        }

        It 'Unprotects the data properly even with strict mode enabled' {
            { $protectedData | Unprotect-Data -Certificate $certFromFile -ErrorAction Stop } | Should -Not -Throw
            $protectedData | Unprotect-Data -Certificate $certFromFile | Should -Be $stringToEncrypt
        }
    }

    Context 'Using legacy padding' {

        BeforeAll {
            $protectedData = Protect-Data -InputObject $stringToEncrypt -Certificate $certFromFile -UseLegacyPadding
        }

        It 'Assigns the use legacy padding property' {
            $protectedData.KeyData[0].LegacyPadding | Should -Be $true
        }

        It 'Decrypts data properly' {
            $protectedData | Unprotect-Data -Certificate $certFromFile | Should -Be $stringToEncrypt
        }
    }

    Context 'Using OAEP padding' {

        BeforeAll {
            $protectedData = Protect-Data -InputObject $stringToEncrypt -Certificate $certFromFile
        }

        It 'Does not assign the use legacy padding property' {
            $protectedData.KeyData[0].LegacyPadding | Should -Be $false
        }

        It 'Decrypts data properly' {
            $protectedData |
                Unprotect-Data -Certificate $certFromFile | Should -Be $stringToEncrypt
        }
    }
}

Describe 'RSA Certificates (CNG Key Storage Provider)' {

    Context 'RSA Certificates (CNG Key Storage Provider)' {

        BeforeAll {
            $thumbprint = New-TestCertificate -Subject $testCertificateSubject -CertificateType RsaCng
            $testCert = Get-Item Cert:\CurrentUser\My\$thumbprint

            $protectedData = Protect-Data -InputObject $stringToEncrypt -Certificate $testCert
            $protectedWithLegacyPadding = Protect-Data -InputObject $stringToEncrypt -Certificate $testCert -UseLegacyPadding
        }

        It 'Decrypts data successfully using an RSA cert using a CNG KSP' {
            Unprotect-Data -InputObject $protectedData -Certificate $testCert | Should -Be $stringToEncrypt
        }

        It 'Decrypts data successfully with legacy padding' {
            Unprotect-Data -InputObject $protectedWithLegacyPadding -Certificate $testCert | Should -Be $stringToEncrypt
        }

        AfterAll {
            Remove-TestCertificate
        }
    }

}

Describe 'ECDH Certificates' {

    Context 'ECDH_P256' {

        BeforeAll {
            $thumbprint = New-TestCertificate -Subject $testCertificateSubject -CertificateType Ecdh_P256
            $testCert = Get-Item Cert:\CurrentUser\My\$thumbprint

            $protectedData = Protect-Data -InputObject $stringToEncrypt -Certificate $testCert
        }

        It 'Decrypts data successfully using an ECDH_P256 certificate' {
            Unprotect-Data -InputObject $protectedData -Certificate $testCert | Should -Be $stringToEncrypt
        }
    }

    Context 'ECDH_P384' {

        BeforeAll {
            $thumbprint = New-TestCertificate -Subject $testCertificateSubject -CertificateType Ecdh_P384
            $testCert = Get-Item Cert:\CurrentUser\My\$thumbprint

            $protectedData = Protect-Data -InputObject $stringToEncrypt -Certificate $testCert
        }

        It 'Decrypts data successfully using an ECDH_P384 certificate' {
            Unprotect-Data -InputObject $protectedData -Certificate $testCert | Should -Be $stringToEncrypt
        }
    }

    Context 'ECDH_P521' {

        BeforeAll {
            $thumbprint = New-TestCertificate -Subject $testCertificateSubject -CertificateType Ecdh_P521
            $testCert = Get-Item Cert:\CurrentUser\My\$thumbprint

            $protectedData = Protect-Data -InputObject $stringToEncrypt -Certificate $testCert
        }

        It 'Decrypts data successfully using an ECDH_P521 certificate' {
            Unprotect-Data -InputObject $protectedData -Certificate $testCert | Should -Be $stringToEncrypt
        }
    }

    AfterAll {
        Remove-TestCertificate
    }
}
