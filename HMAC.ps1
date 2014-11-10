Add-Type -ReferencedAssemblies System.Core -WarningAction SilentlyContinue -TypeDefinition @'
    namespace PowerShellUtils
    {
        using System;
        using System.Reflection;
        using System.Security.Cryptography;

        public class FipsHmacSha256 : HMAC
        {
            // Class exists to guarantee FIPS compliant SHA-256 HMAC, which isn't
            // the case in the built-in HMACSHA256 class in older version of the
            // .NET Framework and PowerShell.

            private static RNGCryptoServiceProvider rng;

            private static RNGCryptoServiceProvider Rng
            {
                get
                {
                    if (rng == null)
                    {
                        rng = new RNGCryptoServiceProvider();
                    }

                    return rng;
                }
            }

            private static byte[] GetRandomBytes(int keyLength)
            {
                byte[] array = new byte[keyLength];
                Rng.GetBytes(array);
                return array;
            }

            public FipsHmacSha256() : this(GetRandomBytes(64)) { }

            public FipsHmacSha256(byte[] key)
            {
                BindingFlags flags = BindingFlags.Instance | BindingFlags.NonPublic;

                typeof(HMAC).GetField("m_hashName", flags).SetValue(this, "SHA256");
                typeof(HMAC).GetField("m_hash1", flags).SetValue(this, new SHA256CryptoServiceProvider());
                typeof(HMAC).GetField("m_hash2", flags).SetValue(this, new SHA256CryptoServiceProvider());

                HashSizeValue = 256;
                Key = key;
            }
        }
    }
'@
