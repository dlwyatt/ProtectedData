__Build Status:__ [![Build status](https://build.powershell.org/guestAuth/app/rest/builds/buildType:(id:ProtectedData_PublishStatusToGitHub)/statusIcon)](https://build.powershell.org/project.html?projectId=ProtectedData&tab=projectOverview&guest=1)

ProtectedData
=============

PowerShell Module for securely encrypting and sharing secret data.

Passwords, other encryption keys, your secret family recipe for baked beans, whatever!  If you don't want to store something in the clear, and need to be able to decrypt the data as more than one user (or on more than one computer), this module can help.

Special thanks to Vadims Podāns ([PowerShell Crypto Guy](http://en-us.sysadmins.lv/default.aspx)), whose feedback, ideas and code contributed greatly to the features that have been added to this module since its v1.0 release - in particular, support for CNG certificates and keys.

## Isn't this just like Protect-CmsMessage and Unprotect-CmsMessage?

Very similar, yes!  I was writing this module pretty much at the same time that the PowerShell team was working on the v5 previews that first gave us the CmsMessage cmdlets.  The timing was unfortunate; had I known what the PS team was working on, I'd have simply backported their commands to work on older versions of PowerShell.

Here are the basic pros and cons comparing the built-in CmsMessage commands and the ProtectedData modle:

- The CmsMessage commands produce standards-based output, which can enable some cross-platform interaction with your PowerShell scripts.  The ProtectedData module, on the other hand, produces PowerShell objects that are intended to be decrypted by the same PS module.
- The CmsMessage commands are only available in PowerShell v4 (with latest patches) and v5.  ProtectedData is compatible down to PowerShell v2.
- The CmsMessage commands are really only useful for encrypting strings of text.  If you pass them a complex object, what gets encrypted is the string that results from piping that object to `Out-String`.  Most of the time you can get around this by running your object through something like ConvertTo-Json first, but SecureString and PSCredential objects are a bit more of a pain (as you must decrypt the SecureString to plain text before passing it on to Protect-CmsMessage for encryption.)  ProtectedData, on the other hand, supports strings, SecureStrings, PSCredentials, and byte arrays without any additional effort from the caller.
- ProtectedData supports CNG (Crypto Next Generation) certificate and keys, and Elliptic Curve encryption.  As of this writing, the CmsMessage commands do not support these types of certificates / keys, mainly because the underlying .NET framework still doesn't have built-in support for them.  However, I believe that CNG support is coming to the .NET framework as of v4.6, and the CmsMessage commands may simply "inherit" CNG support from .NET at some point in the future.

I gave a presentation at the PowerShell Summit which includes demonstrations of both of these modules, with comparisons of functionality.  It's available on YouTube at https://www.youtube.com/watch?v=Ta2hQHVKauo
