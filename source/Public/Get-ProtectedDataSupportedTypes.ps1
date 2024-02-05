function Get-ProtectedDataSupportedTypes
{
   <#
    .Synopsis
       Returns a list of types that can be used as the InputObject in the Protect-Data command.
    .EXAMPLE
       $types = Get-ProtectedDataSupportedTypes
    .INPUTS
       None.
    .OUTPUTS
       Type[]
    .NOTES
       This function allows you to know which InputObject types are supported by the Protect-Data and Unprotect-Data commands in this version of the module. This list may expand over time, will always be backwards-compatible with previously-encrypted data.
    .LINK
       Protect-Data
    .LINK
       Unprotect-Data
    #>

   [CmdletBinding()]
   [OutputType([Type[]])]
   param ( )

   return [string],
   [System.Security.SecureString],
   [System.Management.Automation.PSCredential],
   [byte[]]

}
