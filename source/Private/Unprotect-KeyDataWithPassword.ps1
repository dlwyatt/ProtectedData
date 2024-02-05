function Unprotect-KeyDataWithPassword
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        $KeyData,

        [Parameter(Mandatory = $true)]
        [System.Security.SecureString]
        $Password
    )

    $keyGen = $null
    $key = $null
    $iv = $null
    $ephemeralKey = $null
    $ephemeralIV = $null

    $doFinallyBlock = $true

    try
    {
        $params = @{
            Password       = $Password
            Salt           = $KeyData.Salt.Clone()
            IterationCount = $KeyData.IterationCount
        }

        $keyGen = Get-KeyGenerator @params
        $ephemeralKey = New-Object PowerShellUtils.PinnedArray[byte](, $keyGen.GetBytes(32))
        $ephemeralIV = New-Object PowerShellUtils.PinnedArray[byte](, $keyGen.GetBytes(16))

        $key = (Unprotect-DataWithAes -CipherText $KeyData.Key -Key $ephemeralKey -InitializationVector $ephemeralIV).PlainText
        $iv = (Unprotect-DataWithAes -CipherText $KeyData.IV -Key $ephemeralKey -InitializationVector $ephemeralIV).PlainText

        $doFinallyBlock = $false

        return New-Object psobject -Property @{
            Key = $key
            IV  = $iv
        }
    }
    catch
    {
        throw
    }
    finally
    {
        if ($keyGen -is [IDisposable])
        {
            $keyGen.Dispose()
        }
        if ($ephemeralKey -is [IDisposable])
        {
            $ephemeralKey.Dispose()
        }
        if ($ephemeralIV -is [IDisposable])
        {
            $ephemeralIV.Dispose()
        }

        if ($doFinallyBlock)
        {
            if ($key -is [IDisposable])
            {
                $key.Dispose()
            }
            if ($iv -is [IDisposable])
            {
                $iv.Dispose()
            }
        }
    }
}
