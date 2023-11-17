function ConvertTo-PinnedByteArray
{
    [CmdletBinding()]
    [OutputType([PowerShellUtils.PinnedArray[byte]])]
    param (
        [Parameter(Mandatory = $true)]
        $InputObject
    )

    try
    {
        switch ($InputObject.GetType().FullName)
        {
            ([string].FullName)
            {
                $pinnedArray = Convert-StringToPinnedByteArray -String $InputObject
                break
            }

            ([System.Security.SecureString].FullName)
            {
                $pinnedArray = Convert-SecureStringToPinnedByteArray -SecureString $InputObject
                break
            }

            ([System.Management.Automation.PSCredential].FullName)
            {
                $pinnedArray = Convert-PSCredentialToPinnedByteArray -Credential $InputObject
                break
            }

            default
            {
                $byteArray = $InputObject -as [byte[]]

                if ($null -eq $byteArray)
                {
                    throw 'Something unexpected got through our parameter validation.'
                }
                else
                {
                    $pinnedArray = New-Object PowerShellUtils.PinnedArray[byte](
                        , $byteArray.Clone()
                    )
                }
            }

        }

        $pinnedArray
    }
    catch
    {
        throw
    }

}
