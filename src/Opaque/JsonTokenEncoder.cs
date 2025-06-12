using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

namespace Opaque;

public static class JsonTokenEncoder
{
    public static bool IsSupported => ChaCha20Poly1305.IsSupported;

    internal const string SerializationUnreferencedCodeMessage = "JSON serialization and deserialization might require types that cannot be statically analyzed. Use the overload that takes a JsonTypeInfo or JsonSerializerContext, or make sure all of the required types are preserved.";
    internal const string SerializationRequiresDynamicCodeMessage = "JSON serialization and deserialization might require types that cannot be statically analyzed and might need runtime code generation. Use System.Text.Json source generation for native AOT applications.";

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
        return SecretBox.Seal(key, plaintext, output);
    }

    /// <inheritdoc cref="Encode{T}(ReadOnlySpan{byte}, T, Span{byte})"/>
    public static int Encode<T>(ReadOnlySpan<byte> key, T value, JsonTypeInfo<T> typeInfo, Span<byte> output)
    {
        byte[] plaintext = JsonSerializer.SerializeToUtf8Bytes(value, typeInfo);
        return SecretBox.Seal(key, plaintext, output);
    }

    /// <summary>
    /// Attempts to decrypt and deserialize a value from an "opaque" byte array.
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

        if (input.Length < SecretBox.OverheadInBytes) return false; // Input too short.

        int plaintextLength = input.Length - SecretBox.OverheadInBytes;
        byte[] plaintext = new byte[plaintextLength]; // TODO: stackalloc/pooling and check if the crypto API contract allows in-place.

        if (!SecretBox.TryUnseal(key, input, plaintext)) return false;

        value = JsonSerializer.Deserialize<T>(plaintext);
        return true;
    }

    /// <inheritdoc cref="TryDecode{T}(ReadOnlySpan{byte}, ReadOnlySpan{byte}, out T?)"/>
    public static bool TryDecode<T>(ReadOnlySpan<byte> key, ReadOnlySpan<byte> input, JsonTypeInfo<T> typeInfo, out T? value)
    {
        value = default;

        if (input.Length < SecretBox.OverheadInBytes) return false; // Input too short.

        int plaintextLength = input.Length - SecretBox.OverheadInBytes;
        byte[] plaintext = new byte[plaintextLength]; // TODO: stackalloc/pooling and check if the crypto API contract allows in-place.

        if (!SecretBox.TryUnseal(key, input, plaintext)) return false;

        value = JsonSerializer.Deserialize(plaintext, typeInfo);
        return true;
    }
}
