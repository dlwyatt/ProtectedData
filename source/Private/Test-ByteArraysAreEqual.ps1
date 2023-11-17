function Test-ByteArraysAreEqual([byte[]] $First, [byte[]] $Second)
{
    if ($null -eq $First)
    {
        $First = @()
    }
    if ($null -eq $Second)
    {
        $Second = @()
    }

    if ($First.Length -ne $Second.Length)
    {
        return $false
    }

    $length = $First.Length
    for ($i = 0; $i -lt $length; $i++)
    {
        if ($First[$i] -ne $Second[$i])
        {
            return $false
        }
    }

    return $true
}
