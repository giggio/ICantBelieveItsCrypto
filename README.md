# I can't believe it's crypto

[![NuGet version (ICantBelieveItsCrypto)](https://img.shields.io/nuget/v/ICantBelieveItsCrypto?color=blue)](https://www.nuget.org/packages/ICantBelieveItsCrypto/)
[![Build app](https://github.com/giggio/ICantBelieveItsCrypto/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/giggio/ICantBelieveItsCrypto/actions/workflows/build.yml)

Some helper methods to help encrypt with a X509 certificate.
Methods are static but there is also an interface, now that C# 11 supports that.
This library demands .NET 7.

```csharp
using var cert = new X509Certificate2(public);
Crypto.EncryptFileWithCert(cert, file);
//or
using var cert = X509Certificate2.CreateFromPemFile(public, private);
Crypto.DecryptFileWithCert(cert, file);
```

See the [tests](Tests/CryptoTests.cs) to learn how to use the lib.

## Contributing

Questions, comments, bug reports, and pull requests are all welcome.  Submit them at
[the project on GitHub](https://github.com/giggio/ICantBelieveItsCrypto).

Bug reports that include steps-to-reproduce (including code) are the
best. Even better, make them in the form of pull requests.

## Author

[Giovanni Bassi](https://github.com/giggio).

## License

Licensed under the MIT License.
