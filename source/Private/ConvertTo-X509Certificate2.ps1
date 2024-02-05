function ConvertTo-X509Certificate2
{
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param (
        [Parameter(ValueFromPipeline = $true)]
        [object[]]
        $InputObject = @()
    )

    process
    {
        foreach ($object in $InputObject)
        {
            if ($null -eq $object)
            {
                continue
            }

            $possibleCerts = @(
                $object -as [System.Security.Cryptography.X509Certificates.X509Certificate2]
                Get-CertificateFromPSPath -Path $object
            ) -ne $null

            if ($object -match '^[A-F\d]+$' -and $possibleCerts.Count -eq 0)
            {
                $possibleCerts = @(Get-CertificateByThumbprint -Thumbprint $object)
            }

            $cert = $possibleCerts | Select-Object -First 1

            if ($null -ne $cert)
            {
                $cert
            }
            else
            {
                Write-Error "No certificate with identifier '$object' of type $($object.GetType().FullName) was found."
            }
        }
    }
}
