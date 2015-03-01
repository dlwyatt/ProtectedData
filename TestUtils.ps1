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
        $NotAfter,

        [ValidateSet('Rsa', 'RsaCng', 'Ecdh_P256', 'Ecdh_P384', 'Ecdh_P521')]
        [string]
        $CertificateType = 'Rsa',

        [switch]
        $NoKeyUsageExtension
    )

    if ($null -ne $NotBefore -and $null -ne $NotAfter -and $NotBefore -ge $NotAfter)
    {
        throw 'NotAfter date/time must take place after NotBefore'
    }

    $notBeforeString = $notAfterString = ''

    if ($null -ne $NotBefore)
    {
        $notBeforeString = "NotBefore = ""$($NotBefore.ToString('G'))"""
    }

    if ($null -ne $NotAfter)
    {
        $notAfterString = "NotAfter = ""$($NotAfter.ToString('G'))"""
    }

    $requestfile = [System.IO.Path]::GetTempFileName()
    $certFile = [System.IO.Path]::GetTempFileName()

    switch ($CertificateType)
    {
        'Rsa'
        {
            $providerName = 'Microsoft RSA SChannel Cryptographic Provider'
            $keyLength = 2048
            $keyAlgorithm = ''
            $keySpec = 'KeySpec = AT_KEYEXCHANGE'
            $keyUsage = 'CERT_KEY_ENCIPHERMENT_KEY_USAGE'
            $providerType = 12

            break
        }

        'RsaCng'
        {
            $providerName = 'Microsoft Software Key Storage Provider'
            $keyLength = 2048
            $keyAlgorithm = ''
            $keySpec = 'KeySpec = AT_KEYEXCHANGE'
            $keyUsage = 'CERT_KEY_ENCIPHERMENT_KEY_USAGE'
            $providerType = 0

            break
        }

        'Ecdh_P256'
        {
            $providerName = 'Microsoft Software Key Storage Provider'
            $keyLength = 256
            $keyAlgorithm = 'KeyAlgorithm = ECDH_P256'
            $keySpec = ''
            $keyUsage = 'CERT_KEY_AGREEMENT_KEY_USAGE'
            $providerType = 0

            break
        }

        'Ecdh_P384'
        {
            $providerName = 'Microsoft Software Key Storage Provider'
            $keyLength = 384
            $keyAlgorithm = 'KeyAlgorithm = ECDH_P384'
            $keySpec = ''
            $keyUsage = 'CERT_KEY_AGREEMENT_KEY_USAGE'
            $providerType = 0

            break
        }

        'Ecdh_P521'
        {
            $providerName = 'Microsoft Software Key Storage Provider'
            $keyLength = 521
            $keyAlgorithm = 'KeyAlgorithm = ECDH_P521'
            $keySpec = ''
            $keyUsage = 'CERT_KEY_AGREEMENT_KEY_USAGE'
            $providerType = 0

            break
        }
    }

    Set-Content -Path $requestfile -Encoding Ascii -Value @"
[Version]
Signature="`$Windows NT`$"

[NewRequest]
Subject = "$Subject"
KeyLength = $keyLength
Exportable = TRUE
FriendlyName = "ProtectedData"
ProviderName = "$providerName"
ProviderType = $providerType
RequestType = Cert
Silent = True
SuppressDefaults = True
$keySpec
$keyAlgorithm
$(
    if (-not $NoKeyUsageExtension)
    {
        "KeyUsage = $keyUsage"
    }
)
$notBeforeString
$notAfterString

[EnhancedKeyUsageExtension]
OID = 1.3.6.1.4.1.311.80.1
"@

    try
    {
        $oldCerts = @(
            Get-ChildItem Cert:\CurrentUser\My |
            Where-Object { $_.Subject -eq $Subject } |
            Select-Object -ExpandProperty Thumbprint
        )

        $result = certreq.exe -new -f -q $requestfile $certFile

        if ($LASTEXITCODE -ne 0)
        {
            throw $result
        }

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

function Remove-TestCertificate
{
    $pathsToCheck = @(
        'Cert:\CurrentUser\My'
        'Cert:\CurrentUser\CA'
    )

    foreach ($path in $pathsToCheck)
    {
        $oldCerts = @(
            Get-ChildItem $path |
            Where-Object { $_.Subject -eq $testCertificateSubject }
        )

        if ($oldCerts.Count -gt 0)
        {
            $store = Get-Item $path
            $store.Open('ReadWrite')

            foreach ($oldCert in $oldCerts)
            {
                $store.Remove($oldCert)
            }

            $store.Close()
        }
    }
}
