function Get-CertificateByThumbprint
{
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param (
        [Parameter(Mandatory = $true)]
        [string] $Thumbprint,

        [ValidateNotNullOrEmpty()]
        [string]
        $Path = 'Cert:\'
    )

    return Get-ChildItem -Path $Path -Recurse -Include $Thumbprint |
        Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] } |
            Sort-Object -Property HasPrivateKey -Descending
}
