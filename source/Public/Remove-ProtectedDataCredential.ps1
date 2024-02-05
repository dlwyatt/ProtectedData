function Remove-ProtectedDataCredential
{
    <#
    .Synopsis
       Removes copies of encryption keys from a ProtectedData object.
    .DESCRIPTION
       The KeyData copies in a ProtectedData object which are associated with the specified Certificates and/or Passwords are removed from the object, unless that removal would leave no KeyData copies behind.
    .PARAMETER InputObject
       The ProtectedData object which is to be modified.
    .PARAMETER Certificate
       RSA or ECDH certificates that you wish to remove from this ProtectedData object.  You can pass an X509Certificate2 object to this parameter, or you can pass in a string which contains either a path to a certificate file on the file system, a path to the certificate in the Certificate provider, or a certificate thumbprint (in which case the certificate provider will be searched to find the certificate.)
    .PARAMETER Password
       Passwords in SecureString form which are to be removed from this ProtectedData object.
    .PARAMETER Passthru
       If this switch is used, the ProtectedData object will be written to the pipeline after processing is complete.
    .EXAMPLE
       $protectedData | Remove-ProtectedDataCredential -Certificate $thumbprints -Password $passwords

       Removes certificates and passwords from an existing ProtectedData object.
    .INPUTS
       [PSObject]

       The input object should be a copy of an object that was produced by Protect-Data.
    .OUTPUTS
       None, or
       [PSObject]
    .LINK
       Protect-Data
    .LINK
       Unprotect-Data
    .LINK
       Add-ProtectedDataCredential
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidateScript({
                if (-not (Test-IsProtectedData -InputObject $_))
                {
                    throw 'InputObject argument must be a ProtectedData object.'
                }

                return $true
            })]
        $InputObject,

        [Parameter()]
        [ValidateNotNull()]
        [AllowEmptyCollection()]
        [object[]]
        $Certificate,

        [Parameter()]
        [ValidateNotNull()]
        [AllowEmptyCollection()]
        [System.Security.SecureString[]]
        $Password,

        [Parameter()]
        [switch]
        $Passthru
    )

    begin
    {
        $thumbprints = @(
            $Certificate |
                ConvertTo-X509Certificate2 |
                    Select-Object -ExpandProperty Thumbprint
        )

        $thumbprints = $thumbprints | Get-Unique
    }

    process
    {
        $matchingKeyData = @(
            foreach ($keyData in $InputObject.KeyData)
            {
                if (Test-IsCertificateProtectedKeyData -InputObject $keyData)
                {
                    if ($thumbprints -contains $keyData.Thumbprint)
                    {
                        $keyData
                    }
                }
                elseif (Test-IsPasswordProtectedKeyData -InputObject $keyData)
                {
                    foreach ($secureString in $Password)
                    {
                        $params = @{
                            Password       = $secureString
                            Salt           = $keyData.HashSalt
                            IterationCount = $keyData.IterationCount
                        }
                        if ($keyData.Hash -eq (Get-PasswordHash @params))
                        {
                            $keyData
                        }
                    }
                }
            }
        )

        if ($matchingKeyData.Count -eq $InputObject.KeyData.Count)
        {
            Write-Error 'You must leave at least one copy of the ProtectedData object''s keys.'
            return
        }

        $InputObject.KeyData = $InputObject.KeyData | Where-Object { $matchingKeyData -notcontains $_ }

        if ($Passthru)
        {
            $InputObject
        }
    }

}
