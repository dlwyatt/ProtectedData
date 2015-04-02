Task default -depends Build,Sign

Properties {
    $source               = $psake.build_script_dir
    $buildTarget          = "$home\Documents\WindowsPowerShell\Modules\ProtectedData"
    $signerCertThumbprint = '20164DCA86BDFBB5B345AF85F5DB54E9AFFA3F30'
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
    Copy-Folder -Source $source -Destination $buildTarget -ErrorAction Stop

    Remove-Item $buildTarget\.git -Force -Recurse

    Get-ChildItem -LiteralPath $buildTarget -Recurse -Force |
    Where Name -In $filesToExclude |
    Remove-Item -Force
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

    Get-ChildItem -Path $buildTarget\* -Include *.ps1, *.psm1, *.psd1 |
    Set-AuthenticodeSignature @splat -ErrorAction Stop |
    Format-Table -Property $properties -AutoSize
}

# Quick and dirty implementation of what is basically Robocopy.exe /MIR, except instead of relying on file sizes and modified dates, it
# calculates file hashes instead.  Not intended for use over the network; this is for local installation scripts in nuget packages.

# This will help us to avoid "file in use" errors for dlls that haven't changed, and that sort of thing.

function Copy-Folder
{
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({
            if (-not (Test-Path -LiteralPath $_) -or
                (Get-Item -LiteralPath $_) -isnot [System.IO.DirectoryInfo])
            {
                throw "Path '$_' does not refer to a Directory on the FileSystem provider."
            }

            return $true
        })]
        [string] $Source,

        [Parameter(Mandatory)]
        [ValidateScript({
            if (Test-Path -LiteralPath $_)
            {
                $destFolder = Get-Item -LiteralPath $_ -ErrorAction Stop -Force

                if ($destFolder -isnot [System.IO.DirectoryInfo])
                {
                    throw "Destination '$_' exists, and is not a directory on the file system."
                }
            }

            return $true
        })]
        [string] $Destination
    )

    # Everything here that's destructive is done via cmdlets that already support ShouldProcess, so we don't need to make our own calls
    # to it here.  Those cmdlets will inherit our local $WhatIfPreference / $ConfirmPreference anyway.

    $sourceFolder = Get-Item -LiteralPath $Source
    $sourceRootPath = $sourceFolder.FullName

    if (Test-Path -LiteralPath $Destination)
    {
        $destFolder = Get-Item -LiteralPath $Destination -ErrorAction Stop -Force

        # ValidateScript already made sure that we're looking at a [DirectoryInfo], but just in case there's a weird race condition
        # with some other process, we'll check again here to be sure.
        
        if ($destFolder -isnot [System.IO.DirectoryInfo])
        {
            throw "Destination '$Destination' exists, and is not a directory on the file system."
        }

        # First, clear out anything in the destination that doesn't exist in the source.  By doing this first, we can ensure that
        # there aren't existing directories with the name of a file we need to copy later, or vice versa.

        foreach ($fsInfo in Get-ChildItem -LiteralPath $destFolder.FullName -Recurse -Force)
        {
            # just in case we've already nuked the parent folder of something earlier in the loop.
            if (-not $fsInfo.Exists) { continue }

            $fsInfoRelativePath = Get-RelativePath -Path $fsInfo.FullName -RelativeTo $destFolder.FullName
            $sourcePath = Join-Path $sourceRootPath $fsInfoRelativePath

            if ($fsInfo -is [System.IO.DirectoryInfo])
            {
                $pathType = 'Container'
            }
            else
            {
                $pathType = 'Leaf'
            }

            if (-not (Test-Path -LiteralPath $sourcePath -PathType $pathType))
            {
                Remove-Item $fsInfo.FullName -Force -Recurse -ErrorAction Stop
            }
        }
    }

    # Now copy over anything from source that's either missing or different.
    foreach ($fsInfo in Get-ChildItem -LiteralPath $sourceRootPath -Recurse -Force)
    {
        $fsInfoRelativePath = Get-RelativePath -Path $fsInfo.FullName -RelativeTo $sourceRootPath
        $targetPath = Join-Path $Destination $fsInfoRelativePath
        $parentPath = Split-Path $targetPath -Parent

        if ($fsInfo -is [System.IO.FileInfo])
        {
            EnsureFolderExists -Path $parentPath

            if (-not (Test-Path -LiteralPath $targetPath) -or
                -not (FilesAreIdentical $fsInfo.FullName $targetPath))
            {
                Copy-Item -LiteralPath $fsInfo.FullName -Destination $targetPath -Force -ErrorAction Stop
            }
        }
        else
        {
            EnsureFolderExists -Path $targetPath
        }
    }
}

function EnsureFolderExists([string] $Path)
{
    if (-not (Test-Path -LiteralPath $Path -PathType Container))
    {
        $null = New-Item -Path $Path -ItemType Directory -ErrorAction Stop
    }
}

function FilesAreIdentical([string] $FirstPath, [string] $SecondPath)
{
    $first = Get-Item -LiteralPath $FirstPath -Force -ErrorAction Stop
    $second = Get-Item -LiteralPath $SecondPath -Force -ErrorAction Stop

    if ($first.Length -ne $second.Length) { return $false }

    $firstHash = Get-FileHash -LiteralPath $FirstPath -Algorithm SHA512 -ErrorAction Stop
    $secondHash = Get-FileHash -LiteralPath $SecondPath -Algorithm SHA512 -ErrorAction Stop

    return $firstHash.Hash -eq $secondHash.Hash
}

function Get-RelativePath([string] $Path, [string]$RelativeTo )
{
    $RelativeTo = $RelativeTo -replace '\\+$'
    return $Path -replace "^$([regex]::Escape($RelativeTo))\\?"
}
