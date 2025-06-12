using System.Security.Cryptography;

namespace Opaque;

public static class SecretBox
{
    private const int NonceSizeInBytes = 12;
    private const int ReservedBytes = 1;
    private const int TagSizeInBytes = 16;

    /// <summary>
    /// The number of bytes required in addition to the plaintext length.
    /// <para/>
    /// <code>
    /// Nonce (12 bytes) || Reserved (2 bytes) || Plaintext || Tag (16 bytes)
    /// </code>
    /// </summary>
    public const int OverheadInBytes = NonceSizeInBytes + ReservedBytes + TagSizeInBytes;

    /// <summary>
    /// Encrypts plaintext using ChaCha20-Poly1305 and writes the result to the <paramref name="output"/> buffer.
    /// </summary>
    /// <param name="key">The key.</param>
    /// <param name="plaintext">The plaintext.</param>
    /// <param name="output">The buffer to write the </param>
    /// <exception cref="ArgumentException">The specified <paramref name="output"/> buffer is too small.</exception>
    /// <exception cref="CryptographicException">Specified <paramref name="key"/> is not a valid size for the encryption algorithm.</exception>
    /// <returns>The number of bytes written into <paramref name="output"/> buffer.</returns>
    public static int Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, Span<byte> output)
    {
        if (output.Length < plaintext.Length + OverheadInBytes)
        {
            throw new ArgumentException("The specified output buffer is too small.", nameof(output));
        }

        using var chaCha20Poly1305 = new ChaCha20Poly1305(key);

        // We store the random nonce alongside the alongside the encrypted message. We're okay with birthday-bound collision probability.
        Span<byte> nonce = output.Slice(0, NonceSizeInBytes);
        RandomNumberGenerator.Fill(nonce);

        // Version
        Span<byte> version = output.Slice(NonceSizeInBytes, ReservedBytes);
        version[0] = 0;

        Span<byte> ciphertext = output.Slice(NonceSizeInBytes + ReservedBytes, plaintext.Length);
        Span<byte> tag = output.Slice(NonceSizeInBytes + ReservedBytes + plaintext.Length, TagSizeInBytes);

        chaCha20Poly1305.Encrypt(nonce, plaintext, ciphertext, tag, associatedData: version);

        return plaintext.Length + OverheadInBytes;
    }

    /// <summary>
    /// Attempts to decrypt and authenticate ciphertext using ChaCha20-Poly1305.
    /// </summary>
    /// <param name="key">The decryption key.</param>
    /// <param name="input">The input buffer containing the encrypted data, including nonce and tag.</param>
    /// <param name="output">The output buffer to write the decrypted plaintext to.</param>
    /// <returns><see langword="true"/> if decryption and authentication are successful; otherwise, <see langword="false"/>.</returns>
    public static bool TryUnseal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, Span<byte> output)
    {
        if (input.Length < OverheadInBytes)
        {
            return false;
        }

        int cipherTextLength = input.Length - OverheadInBytes;
        if (output.Length < cipherTextLength)
        {
            return false;
        }

        using var chaCha20Poly1305 = new ChaCha20Poly1305(key);

        ReadOnlySpan<byte> nonce = input.Slice(0, NonceSizeInBytes);
        ReadOnlySpan<byte> version = input.Slice(NonceSizeInBytes, ReservedBytes);
        ReadOnlySpan<byte> ciphertext = input.Slice(NonceSizeInBytes + ReservedBytes, cipherTextLength);
        ReadOnlySpan<byte> tag = input.Slice(NonceSizeInBytes + ReservedBytes + cipherTextLength, TagSizeInBytes);

        try
        {
            chaCha20Poly1305.Decrypt(nonce, ciphertext, tag, output.Slice(0, cipherTextLength), associatedData: version);
            return true;
        }
        catch (CryptographicException)
        {
            return false; // Authentication failed.
        }
    }
}
