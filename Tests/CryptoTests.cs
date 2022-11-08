using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Tests;
public class CryptoTests
{
    private const string text = "Animi a velit et totam ut cupiditate occaecati. At quia quaerat quia magnam quas ut veniam laborum. Et qui ut quos. Odio nihil quis est. Itaque consectetur eos ducimus ratione est nobis mollitia nam.";
    [Fact]
    public void EncryptThenDecryptWithAES()
    {
        using var aes = Aes.Create();
        using var originStream = new MemoryStream(Encoding.Default.GetBytes(text));
        using var destinationStream = new MemoryStream();
        Crypto.EncryptStream(aes, originStream, destinationStream);

        Assert.NotEqual(0, destinationStream.Position);
        destinationStream.Position = 0;

        using var decryptedStream = new MemoryStream();
        Crypto.DecryptStream(aes, destinationStream, decryptedStream);
        Assert.NotEqual(0, destinationStream.Position);
        Assert.NotEqual(0, decryptedStream.Position);
        var decryptedText = Encoding.Default.GetString(decryptedStream.ToArray());
        Assert.Equal(text, decryptedText);
    }

    /// <remarks>
    /// to create the x509 certs:
    /// openssl req -nodes -new -x509 -keyout private.x509 -out public.x509
    /// </remarks>
    [Fact]
    public void EncryptThenDecryptWithAESAndCert()
    {
        using var publicKeyCert = new X509Certificate2(Path.Combine(Environment.CurrentDirectory, "public.x509"));
        using var originStream = new MemoryStream(Encoding.Default.GetBytes(text));
        using var destinationStream = new MemoryStream();
        Crypto.EncryptStreamWithCert(publicKeyCert, originStream, destinationStream);

        Assert.NotEqual(0, destinationStream.Position);
        destinationStream.Position = 0;

        using var privateKeyCert = X509Certificate2.CreateFromPemFile(Path.Combine(Environment.CurrentDirectory, "public.x509"), Path.Combine(Environment.CurrentDirectory, "private.x509"));
        using var decryptedStream = new MemoryStream();
        Crypto.DecryptStreamWithCert(privateKeyCert, destinationStream, decryptedStream);
        Assert.NotEqual(0, destinationStream.Position);
        Assert.NotEqual(0, decryptedStream.Position);
        var decryptedText = Encoding.Default.GetString(decryptedStream.ToArray());
        Assert.Equal(text, decryptedText);
    }
}
