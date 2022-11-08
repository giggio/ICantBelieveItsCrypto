using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace ICantBelieveItsCrypto;

public interface ICrypto
{
    static abstract void EncryptStream(Aes aes, Stream originStream, Stream destinationStream);
    static abstract void DecryptStream(Aes aes, Stream originStream, Stream destinationStream);
    static abstract void EncryptStreamWithCert(X509Certificate2 publicKeyCert, Stream originStream, Stream destinationStream);
    static abstract void DecryptStreamWithCert(X509Certificate2 privateKeyCert, Stream originStream, Stream destinationStream);
}

public class Crypto : ICrypto
{
    public static void EncryptFileWithCert(X509Certificate2 cert, string filePath)
    {
        using var originFileStream = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        using var destinationFileStream = new FileStream(filePath + ".enc", FileMode.OpenOrCreate, FileAccess.Write);
        EncryptStreamWithCert(cert, originFileStream, destinationFileStream);
    }

    public static void DecryptFileWithCert(X509Certificate2 cert, string encryptedFilePath)
    {
        var encryptedFile = new FileInfo(encryptedFilePath);
        if (encryptedFile.Extension != ".enc")
            throw new ArgumentException("The file is not encrypted, it must end with .enc.");
        using var originFileStream = new FileStream(encryptedFilePath, FileMode.Open, FileAccess.Read);
        using var destinationFileStream = new FileStream(encryptedFilePath[..^4], FileMode.OpenOrCreate, FileAccess.Write);
        DecryptStreamWithCert(cert, originFileStream, destinationFileStream);
    }

    public static void EncryptStreamWithCert(X509Certificate2 cert, Stream originStream, Stream destinationStream)
    {
        var key = cert.PublicKey.GetRSAPublicKey();
        if (key == null)
            throw new Exception("No public key found");
        var aes = Aes.Create();
        var keysBytes = key.Encrypt(aes.Key, RSAEncryptionPadding.Pkcs1);
        var IVBytes = key.Encrypt(aes.IV, RSAEncryptionPadding.Pkcs1);
        using (var streamWriter = new BinaryWriter(destinationStream, Encoding.Default, true))
        {
            streamWriter.Write(keysBytes);
            streamWriter.Write(IVBytes);
        }
        EncryptStream(aes, originStream, destinationStream);
    }

    public static void DecryptStreamWithCert(X509Certificate2 cert, Stream originStream, Stream destinationStream)
    {
        var key = cert.GetRSAPrivateKey();
        if (key == null)
            throw new Exception("No private key found");
        var encryptedKeyBytes = new byte[256];
        originStream.ReadExactly(encryptedKeyBytes, 0, 256);
        var encryptedIVBytes = new byte[256];
        originStream.ReadExactly(encryptedIVBytes, 0, 256);
        var keysBytes = key.Decrypt(encryptedKeyBytes, RSAEncryptionPadding.Pkcs1);
        var IVBytes = key.Decrypt(encryptedIVBytes, RSAEncryptionPadding.Pkcs1);
        var aes = Aes.Create();
        aes.IV = IVBytes;
        aes.Key = keysBytes;
        DecryptStream(aes, originStream, destinationStream);
    }

    public static void EncryptStream(Aes aes, Stream originStream, Stream destinationStream)
    {
        var encryptor = aes.CreateEncryptor();
        using var cryptoStream = new CryptoStream(destinationStream, encryptor, CryptoStreamMode.Write, true);
        originStream.CopyTo(cryptoStream);
        cryptoStream.Flush();
    }

    public static void DecryptStream(Aes aes, Stream originStream, Stream destinationStream)
    {
        var decryptor = aes.CreateDecryptor();
        using var cryptoStream = new CryptoStream(originStream, decryptor, CryptoStreamMode.Read, true);
        cryptoStream.CopyTo(destinationStream);
        cryptoStream.Flush();
    }
}
