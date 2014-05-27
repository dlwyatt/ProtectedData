# PowerShell 2.0 doesn't like having types used in the same script psm1 file where they're defined
# via Add-Type.  Splitting the Add-Type into its own file which gets loaded first seems to work.

Add-Type -TypeDefinition @'
    namespace PowerShellUtils.Cryptography
    {
        using System;
        using System.Runtime.InteropServices;

        public abstract class KeyData
        {
            private readonly byte[] key;
            private readonly byte[] iv;

            public byte[] Key
            {
                get { return key == null ? null : (byte[]) key.Clone(); }
            }
            
            public byte[] IV
            {
                get { return iv == null ? null : (byte[]) iv.Clone(); }
            }

            public KeyData(byte[] key, byte[] iv)
            {
                this.key = key == null ? null : (byte[]) key.Clone();
                this.iv = iv == null ? null : (byte[]) iv.Clone();
            }
        }

        public sealed class PasswordProtectedKeyData : KeyData
        {
            private readonly byte[] salt;
            private readonly int iterationCount;
            private readonly string hash;
            private readonly byte[] hashSalt;

            public int IterationCount
            {
                get { return iterationCount; }
            }

            public byte[] Salt {
                get { return salt == null ? null : (byte[]) salt.Clone(); }
            }

            public string Hash
            {
                get { return hash; }
            }

            public byte[] HashSalt
            {
                get { return hashSalt == null ? null : (byte[]) hashSalt.Clone(); }
            }

            public PasswordProtectedKeyData(byte[] key, byte[] iv, byte[] salt, int iterationCount, string hash, byte[] hashSalt) : base(key, iv)
            {
                this.iterationCount = iterationCount;
                this.salt           = salt == null ? null : (byte[]) salt.Clone();
                this.hash           = hash;
                this.hashSalt       = hashSalt == null ? null : (byte[]) hashSalt.Clone();
            }

            public override string ToString()
            {
                return "Password-protected key";
            }
        }

        public sealed class CertificateProtectedKeyData : KeyData
        {
            private readonly string thumbprint;

            public string Thumbprint
            {
                get { return thumbprint; }
            }

            public CertificateProtectedKeyData(byte[] key, byte[] iv, string thumbprint) : base (key, iv)
            {
                this.thumbprint = thumbprint;
            }
            
            public override string ToString()
            {
                return Thumbprint;
            }
        }

        public sealed class ProtectedData
        {
            public byte[] CipherText;
            public KeyData[] KeyData;
            public string Type;
        }

        public sealed class PinnedArray<T> : IDisposable
        {
            private readonly T[] array;
            private readonly GCHandle gcHandle;
            public readonly bool ClearOnDispose = true;

            private bool isDisposed = false;

            public static implicit operator T[](PinnedArray<T> pinnedArray)
            {
                return pinnedArray.Array;
            }

            public T this[int key]
            {
                get
                {
                    if (isDisposed) { throw new ObjectDisposedException("PinnedArray"); }
                    return array[key];
                }

                set
                {
                    if (isDisposed) { throw new ObjectDisposedException("PinnedArray"); }
                    array[key] = value;
                }
            }

            public T[] Array
            {
                get
                {
                    if (isDisposed) { throw new ObjectDisposedException("PinnedArray"); }
                    return array;
                }
            }

            public int Length
            {
                get
                {
                    if (isDisposed) { throw new ObjectDisposedException("PinnedArray"); }
                    return array.Length;
                }
            }

            public int Count
            {
                get { return Length; }
            }

            public PinnedArray(uint byteCount)
            {
                array = new T[byteCount];
                gcHandle = GCHandle.Alloc(Array, GCHandleType.Pinned);
            }

            public PinnedArray(uint byteCount, bool clearOnDispose) : this(byteCount)
            {
                ClearOnDispose = clearOnDispose;
            }

            public PinnedArray(T[] array)
            {
                if (array == null) { throw new ArgumentNullException("array"); }

                this.array = array;
                gcHandle = GCHandle.Alloc(this.array, GCHandleType.Pinned);
            }

            public PinnedArray(T[] array, bool clearOnDispose) : this(array)
            {
                ClearOnDispose = clearOnDispose;
            }

            ~PinnedArray()
            {
                Dispose();
            }

            public void Dispose()
            {
                if (isDisposed) { return; }

                if (array != null && ClearOnDispose) { System.Array.Clear(array, 0, array.Length); }
                if (gcHandle != null) { gcHandle.Free(); }

                isDisposed = true;
            }
        }
    }
'@
