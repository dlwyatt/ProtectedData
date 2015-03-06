Task default -depends Build,Sign

Properties {
    $source               = $psake.build_script_dir
    $buildTarget          = "$home\Documents\WindowsPowerShell\Modules\ProtectedData"
    $signerCertThumbprint = 'A2E6B086AC438B5480365B2D5E48BB25F9BE69B3'
    $signerTimestampUrl   = 'http://timestamp.digicert.com'

    $filesToExclude = @(
        'README.md'
        'ProtectedData.Tests.ps1'
        'TestUtils.ps1'
        'build.cmd'
        'build.psake.ps1'
        'TestCertificateFile.cer'
        'TestCertificateFile.pfx'
        'TestCertificateFile2.pfx'
        'TestCertificateFile3.pfx'
        'V1.0.ProtectedWithTestCertificateFile.pfx.xml'
    )
}

Task Test {
    $result = Invoke-Pester -Path $source -PassThru
    $failed = $result.FailedCount

    if ($failed -gt 0)
    {
        throw "$failed unit tests failed; build aborting."
    }
}

Task Build -depends Test {
    if (Test-Path -Path $buildTarget -PathType Container)
    {
        Remove-Item -Path $buildTarget -Recurse -Force -ErrorAction Stop
    }

    $null = New-Item -Path $buildTarget -ItemType Directory -ErrorAction Stop

    Copy-Item -Path $source\* -Exclude $filesToExclude -Destination $buildTarget -Recurse -ErrorAction Stop
}

Task Sign {
    if (-not $signerCertThumbprint)
    {
        throw 'Sign task cannot run without a value in the signerCertThumbprint property.'
    }

    $paths = @(
        'Cert:\CurrentUser\My'
        'Cert:\LocalMachine\My'
    )

    $cert = Get-ChildItem -Path $paths |
            Where-Object { $_.Thumbprint -eq $signerCertThumbprint -and $_.PrivateKey -is [System.Security.Cryptography.RSACryptoServiceProvider] } |
            Select-Object -First 1

    if ($cert -eq $null) {
        throw "Code signing certificate with thumbprint '$signerCertThumbprint' was not found, or did not have a usable private key."
    }

    $properties = @(
        @{ Label = 'Name'; Expression = { Split-Path -Path $_.Path -Leaf } }
        'Status'
        @{ Label = 'SignerCertificate'; Expression = { $_.SignerCertificate.Thumbprint } }
        @{ Label = 'TimeStamperCertificate'; Expression = { $_.TimeStamperCertificate.Thumbprint } }
    )

    $splat = @{
        Certificate  = $cert
        IncludeChain = 'All'
        Force        = $true
    }

    if ($signerTimestampUrl) { $splat['TimestampServer'] = $signerTimestampUrl }

    Get-ChildItem -Path $buildTarget\* -Include *.ps1, *.psm1, *.psd1, *.dll |
    Set-AuthenticodeSignature @splat -ErrorAction Stop |
    Format-Table -Property $properties -AutoSize
}
