function Get-KeyEncryptionCertificate
{
    <#
    .Synopsis
       Finds certificates which can be used by Protect-Data and related commands.
    .DESCRIPTION
       Searches the given path, and all child paths, for certificates which can be used by Protect-Data. Such certificates must support Key Encipherment (for RSA) or Key Agreement (for ECDH) usage, and by default, must not be expired and must be issued by a trusted authority.
    .PARAMETER Path
       Path which should be searched for the certifictes. Defaults to the entire Cert: drive.
    .PARAMETER CertificateThumbprint
       Thumbprints which should be included in the search. Wildcards are allowed. Defaults to '*'.
    .PARAMETER SkipCertificateVerification
       Deprecated parameter, which will be removed in a future release.  Specifying this switch will generate a warning.
    .PARAMETER RequirePrivateKey
       If this switch is used, the command will only output certificates which have a usable private key on this computer.
    .EXAMPLE
       Get-KeyEncryptionCertificate -Path Cert:\CurrentUser -RequirePrivateKey

       Searches for certificates which support key encipherment (RSA) or key agreement (ECDH) and have a private key installed. All matching certificates are returned.
    .EXAMPLE
       Get-KeyEncryptionCertificate -Path Cert:\CurrentUser\TrustedPeople

       Searches the current user's Trusted People store for certificates that can be used with Protect-Data. Certificates do not need to have a private key available to the current user.
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

    if ($PSBoundParameters.ContainsKey('SkipCertificateVerification'))
    {
        Write-Warning 'The -SkipCertificateVerification switch has been deprecated, and the module now treats that as its default behavior.  This switch will be removed in a future release.'
    }

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

    $certGroups = Get-CertificateByThumbprint -Path $Path -Thumbprint $CertificateThumbprint -ErrorAction $IgnoreError |
        Group-Object -Property Thumbprint

    if ($null -eq $certGroups)
    {
        throw "Certificate '$CertificateThumbprint' was not found."
    }

    foreach ($group in $certGroups)
    {
        Test-KeyEncryptionCertificate -CertificateGroup $group.Group -RequirePrivateKey:$RequirePrivateKey
    }

}
