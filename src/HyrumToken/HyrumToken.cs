using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace HyrumToken;

public static class HyrumToken
{
    public static bool IsSupported => ChaCha20Poly1305.IsSupported;

    internal const string SerializationUnreferencedCodeMessage = "JSON serialization and deserialization might require types that cannot be statically analyzed. Use the overload that takes a JsonTypeInfo or JsonSerializerContext, or make sure all of the required types are preserved.";
    internal const string SerializationRequiresDynamicCodeMessage = "JSON serialization and deserialization might require types that cannot be statically analyzed and might need runtime code generation. Use System.Text.Json source generation for native AOT applications.";

    private const int NonceSizeInBytes = 12;
    private const int ReservedBytes = 1;
    private const int TagSizeInBytes = 16;

    /// <summary>
    /// The number of bytes required in addition to the plaintext length.
    /// <para/>
    /// <code>
    /// Nonce (12 bytes) || Reserved (1 byte) || Plaintext || Tag (16 Bytes)
    /// </code>
    /// </summary>
    public const int OverheadInBytes = NonceSizeInBytes + ReservedBytes + TagSizeInBytes;

    /// <summary>
    /// Serializes and encrypts a value into a byte array as an opaque token.
    /// </summary>
    /// <typeparam name="T">The type of the value to encode.</typeparam>
    /// <param name="key">The encryption key.</param>
    /// <param name="value">The value to encode.</param>
    /// <param name="output">The output buffer to write the encoded data to.</param>
    /// <returns>The number of bytes written into <paramref name="output"/> buffer.</returns>
    [RequiresUnreferencedCode(SerializationUnreferencedCodeMessage)]
    [RequiresDynamicCode(SerializationRequiresDynamicCodeMessage)]
    public static int Encode<T>(ReadOnlySpan<byte> key, T value, Span<byte> output)
    {
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(value);
        return Seal(key, plaintext, output);
    }

    /// <inheritdoc cref="Encode{T}(ReadOnlySpan{byte}, T, Span{byte})"/>
    public static int Encode<T>(ReadOnlySpan<byte> key, T value, JsonTypeInfo<T> typeInfo, Span<byte> output)
    {
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(value, typeInfo);
        return Seal(key, plaintext, output);
    }

    /// <summary>
    /// Attempts to decrypt and deserailize a value from an "opaque" byte array.
    /// </summary>
    /// <param name="key">The decryption key.</param>
    /// <param name="input">The input buffer containing the encoded data.</param>
    /// <param name="value">When this method returns, contains the decoded value, or <see langword="default"/> if decoding fails.</param>
    /// <returns><see langword="true"/> if decryption, authentication and deserialization are successful; otherwise, <see langword="false"/>.</returns>
    [RequiresUnreferencedCode(SerializationUnreferencedCodeMessage)]
    [RequiresDynamicCode(SerializationRequiresDynamicCodeMessage)]
    public static bool TryDecode<T>(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, out T? value)
    {
        value = default;

        if (input.Length < OverheadInBytes)
        {
            return false; // Input too short.
        }

        int plaintextLength = input.Length - OverheadInBytes;
        byte[] plaintext = new byte[plaintextLength]; // TODO: stackalloc/pooling and check if the crypto API contract allows in-place.

        bool success = TryUnseal(key, input, plaintext);
        if (!success) return false;

        value = JsonSerializer.Deserialize<T>(plaintext);
        return true;
    }

    /// <inheritdoc cref="TryDecode{T}(ReadOnlySpan{byte}, ReadOnlySpan{byte}, out T?)"/>
    public static bool TryDecode<T>(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, JsonTypeInfo<T> typeInfo, out T? value)
    {
        value = default;

        if (input.Length < OverheadInBytes)
        {
            return false; // Input too short.
        }

        int plaintextLength = input.Length - OverheadInBytes;
        byte[] plaintext = new byte[plaintextLength]; // TODO: stackalloc/pooling and check if the crypto API contract allows in-place.

        bool success = TryUnseal(key, input, plaintext);
        if (!success) return false;

        value = JsonSerializer.Deserialize(plaintext, typeInfo);
        return true;
    }

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

        // We store the random nonce alongside the alongside the encrypted message.
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
