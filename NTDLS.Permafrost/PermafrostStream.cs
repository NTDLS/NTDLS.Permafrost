using System;
using System.IO;

namespace NTDLS.Permafrost
{
    /// <summary>
    /// Stream implementation of the NASCCL/Permafrost (NetworkDLS Algorithmic Symmetric Cipher Cryptography Library).
    /// </summary>
    public class PermafrostStream : Stream, IDisposable
    {
        private readonly PermafrostCipher _permafrost;

        private readonly Stream? _innerStream = null;
        private readonly bool _leaveOpen;
        private bool _disposed;

        /// <summary>
        /// Whether the stream can be read.
        /// </summary>
        public override bool CanRead => _innerStream?.CanRead == true;

        /// <summary>
        /// Whether the stream can be written.
        /// </summary>
        public override bool CanWrite => _innerStream?.CanWrite == true;

        /// <summary>
        /// Whether a seek can be performed on the stream. This is not supported.
        /// </summary>
        public override bool CanSeek => false;

        /// <summary>
        /// The length of the stream. This is not supported.
        /// </summary>
        public override long Length => throw new NotSupportedException();

        /// <summary>
        /// The position of the stream. This is not supported.
        /// </summary>
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        #region Constructors.

        /// <summary>
        /// Initializes a new instance of the Permafrost stream using a string key.
        /// </summary>
        /// <param name="innerStream">Stream from outside operation.</param>
        /// <param name="key">The UTF8 string to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="seed">Byte array used to generate key schedules. Uses a built-in default when null.</param>
        /// <param name="keyScheduleCount">The number of key schedules to generate. Uses <see cref="PermafrostCipher.DefaultKeyScheduleCount"/> when 0.</param>
        /// <param name="leaveOpen">Whether the inner stream should be left open on dispose.</param>
        public PermafrostStream(Stream innerStream, string key, PermafrostMode mode = PermafrostMode.Continuous,
            byte[]? seed = null, int keyScheduleCount = PermafrostCipher.DefaultKeyScheduleCount, bool leaveOpen = false)
        {
            _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
            _leaveOpen = leaveOpen;
            _permafrost = new PermafrostCipher(key, mode, seed, keyScheduleCount);
        }

        /// <summary>
        /// Initializes a new instance of the Permafrost stream using a byte array key.
        /// </summary>
        /// <param name="innerStream">Stream from outside operation.</param>
        /// <param name="key">The bytes to use as the encryption/decryption key.</param>
        /// <param name="mode">Whether to use AutoReset mode or Continuous mode. In AutoReset mode the order of encryption and decryption do not matter, but in Continuous mode, the encryption is expected to be continuous and each call to Cipher() depends on the call before it.</param>
        /// <param name="seed">Byte array used to generate key schedules. Uses a built-in default when null.</param>
        /// <param name="keyScheduleCount">The number of key schedules to generate. Uses <see cref="PermafrostCipher.DefaultKeyScheduleCount"/> when 0.</param>
        /// <param name="leaveOpen">Whether the inner stream should be left open on dispose.</param>
        public PermafrostStream(Stream innerStream, byte[] key, PermafrostMode mode = PermafrostMode.Continuous,
            byte[]? seed = null, int keyScheduleCount = PermafrostCipher.DefaultKeyScheduleCount, bool leaveOpen = false)
        {
            _innerStream = innerStream ?? throw new ArgumentNullException(nameof(innerStream));
            _leaveOpen = leaveOpen;
            _permafrost = new PermafrostCipher(key, mode, seed, keyScheduleCount);
        }

        #endregion

        /// <summary>
        /// Flushes the stream.
        /// </summary>
        public override void Flush()
            => _innerStream?.Flush();

        /// <summary>
        /// Reads from the stream and encrypts/decrypts the bytes.
        /// </summary>
        public override int Read(byte[] buffer, int offset, int count)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(Permafrost));
            }
            if (_innerStream == null)
            {
                throw new InvalidOperationException("Stream is not readable.");
            }

            byte[] temp = new byte[count];
            int bytesRead = _innerStream.Read(temp, 0, count);
            _permafrost.CipherInPlace(temp, bytesRead);
            Array.Copy(temp, 0, buffer, offset, bytesRead);
            return bytesRead;
        }

        /// <summary>
        /// Encrypts or decrypts the bytes and writes to the stream.
        /// </summary>
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(nameof(Permafrost));
            }
            if (_innerStream == null)
            {
                throw new InvalidOperationException("Stream is not writable.");
            }

            byte[] encrypted = new byte[count];
            Array.Copy(buffer, offset, encrypted, 0, count);
            _permafrost.CipherInPlace(encrypted, count);
            _innerStream.Write(encrypted, 0, count);
        }

        /// <summary>
        /// Unsupported stream seek operation.
        /// </summary>
        public override long Seek(long offset, SeekOrigin origin)
            => throw new NotSupportedException();

        /// <summary>
        /// Unsupported stream set length operation.
        /// </summary>
        /// <param name="value"></param>
        /// <exception cref="NotSupportedException"></exception>
        public override void SetLength(long value)
            => throw new NotSupportedException();

        /// <summary>
        /// Clears out the variables used for encryption.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    if (!_leaveOpen && _innerStream != null)
                    {
                        _innerStream.Dispose();
                    }
                }

                _permafrost.Destroy();
                _disposed = true;
            }

            base.Dispose(disposing);
        }
    }
}
