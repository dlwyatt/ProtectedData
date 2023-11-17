function Convert-ByteArrayToSecureString
{
    [CmdletBinding()]
    [OutputType([System.Security.SecureString])]
    param (
        [Parameter(Mandatory = $true)]
        [byte[]]
        $ByteArray,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $StartIndex,

        [Parameter(Mandatory = $true)]
        [UInt32]
        $ByteCount
    )

    $chars = $null
    $memoryStream = $null
    $streamReader = $null

    try
    {
        $ss = New-Object System.Security.SecureString
        $memoryStream = New-Object System.IO.MemoryStream($ByteArray, $StartIndex, $ByteCount)
        $streamReader = New-Object System.IO.StreamReader($memoryStream, [System.Text.Encoding]::Unicode, $false)
        $chars = New-Object PowerShellUtils.PinnedArray[char](1024)

        while (($read = $streamReader.Read($chars, 0, $chars.Count)) -gt 0)
        {
            for ($i = 0; $i -lt $read; $i++)
            {
                $ss.AppendChar($chars[$i])
            }
        }

        $ss.MakeReadOnly()
        $ss
    }
    finally
    {
        if ($streamReader -is [IDisposable])
        {
            $streamReader.Dispose()
        }
        if ($memoryStream -is [IDisposable])
        {
            $memoryStream.Dispose()
        }
        if ($chars -is [IDisposable])
        {
            $chars.Dispose()
        }
    }

}
