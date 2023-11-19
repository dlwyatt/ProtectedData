if ($PSVersionTable.PSVersion.Major -eq 2)
{
    $IgnoreError = 'SilentlyContinue'
}
else
{
    $IgnoreError = 'Ignore'
}

$script:PSCredentialHeader = [byte[]](5, 12, 19, 75, 80, 20, 19, 11, 11, 6, 11, 13)

$script:EccAlgorithmOid = '1.2.840.10045.2.1'

$here = $PSScriptRoot

#Access a type in the System.Security.Cryptography namespace to load the assembly into the PowerShell runspace.
[void][Security.Cryptography.RSACng].Module

Add-Type -Path $here\Lib\Security.Cryptography.dll -ErrorAction Stop

. $here\Classes\PinnedArray.ps1
. $path\Classes\HMAC.ps1
