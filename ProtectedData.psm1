$path = Split-Path $MyInvocation.MyCommand.Path

#Access a type in the System.Security.Cryptography namespace to load the assembly into the PowerShell runspace.
[void][Security.Cryptography.RSACng].Module

Add-Type -Path $path\Security.Cryptography.dll -ErrorAction Stop

. $path\PinnedArray.ps1
. $path\HMAC.ps1
. $path\Commands.ps1
