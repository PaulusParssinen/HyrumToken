namespace Opaque.Tests;

public class JsonTokenTests
{
    private static ReadOnlySpan<byte> Key => "TESTINGKEY123456TESTINGKEY123456"u8;

    private record FooBar(string Foo);

    [Fact]
    public void EncodeAndDecode_SimpleObject_Succeeds()
    {
        Span<byte> buffer = stackalloc byte[128];
        var value = new FooBar(Foo: "Bar");

        int bytesWritten = JsonTokenEncoder.Encode(Key, value, buffer);
        bool success = JsonTokenEncoder.TryDecode(Key, buffer.Slice(0, bytesWritten), out FooBar? decodedValue);

        Assert.True(success);
        Assert.Equivalent(value, decodedValue);
    }

    [Fact]
    public void EncodeAndDecode_Integer_Succeeds()
    {
        Span<byte> buffer = stackalloc byte[128];
        int value = 1033;

        int bytesWritten = JsonTokenEncoder.Encode(Key, value, buffer);
        bool success = JsonTokenEncoder.TryDecode(Key, buffer.Slice(0, bytesWritten), out int? decodedValue);

        Assert.True(success);
        Assert.Equivalent(value, decodedValue);
    }


    [Fact]
    public void EncodeAndDecode_Array_Succeeds()
    {
        Span<byte> buffer = stackalloc byte[128];
        string[] value = ["foo", "bar"];

        int bytesWritten = JsonTokenEncoder.Encode(Key, value, buffer);
        bool success = JsonTokenEncoder.TryDecode(Key, buffer.Slice(0, bytesWritten), out string[]? decodedValue);

        Assert.True(success);
        Assert.Equivalent(value, decodedValue);
    }
}
