using System.IO.Abstractions.TestingHelpers;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using KeyAttestation.Client;
using KeyAttestation.Client.Abstractions;
using KeyAttestation.Client.Entities;
using KeyAttestation.Client.Extensions;
using KeyAttestation.Client.Services;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Tpm2Lib;

namespace KeyAttestation.Tests.Client;

public class KeyAttestationClient
{
    private const string Csr =
        "-----BEGIN CERTIFICATE REQUEST-----\nMIICgTCCAWkCAQAwPDENMAsGA1UEAwwEdGVzdDEUMBIGCgmSJomT8ixkARkWBHRl\nc3QxFTATBgoJkiaJk/IsZAEZFgVsb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEP\nADCCAQoCggEBAMDOT5B0q6XLaQkXV1Ryt22TM2lM+RnVXkqzzO3BZiHIwSWa/FCc\nCTbicVB6WDAVAH/8wk7INkxvjLT9U7NAtrdVjOcJsa1T71WNwYQLprTB0uvWFwiv\nhAUnr4DdortYsKC62y1wXEygJ9ymO93uYwN9VWz7JUwGJvXLWehpls6p/IfHcKbb\nyhW8xGhCKb0WWjlkdu6nCA62h+cnH84T/4unoLfvs0BrpreS4MzFxcN8ivvGaAYA\nhy/8gXp+Vje5yIEpQUqDHeYorzZfq/IUiWm82qaELF3XN4fEsG5ZJGajCrOJVpsd\npgXxGDI6X8i+eWkpuyB85fLPsybxhfV1VhUCAwEAAaAAMA0GCSqGSIb3DQEBCwUA\nA4IBAQAiVE18IbwIpo/4MAAVN+1ZXNUxNEuV1bF/jrm67PAoOaNIBK3b2Isj2n+x\nTHG2xMLFBku5usgFG135lWgTHqznVgyYPaDPwDq3kbHkRv3+R2loPI1DTm7dxqbZ\nWOh9w8QwbLZm74zuqn4V80EM4vCXR2oLahhebmhCmqy8DGMw+NXm1xqBsttEDbda\nPf2acgib/VQ6XLgCcOYFZ8oW7i9GMm7gxEt9HjgFqUeKfLGoYRQF32BptFjKVmqn\nohG62kH1SdaWIAeB3qehGgG/YsnrRI3NtM7j1nDV/r12132VDi3DXkZDeKOofVUO\narAQnYyOiQ41ye3/FsHWosDiPpUr\n-----END CERTIFICATE REQUEST-----";

    [Theory]
    [InlineData("test.csr")]
    public async Task ShouldWriteValidCsrInPem(string fileName)
    {
        // Arrange
        var fileSystemMock = new MockFileSystem(new MockFileSystemOptions
        {
            CurrentDirectory = Directory.GetCurrentDirectory(),
            CreateDefaultTempDir = false
        });
        using var textReader = new StringReader(Csr);
        using var pemReader = new PemReader(textReader);
        
        // Act
        var csr = (Pkcs10CertificationRequest)pemReader.ReadObject();
        await csr.WriteCsrAsync(fileName, fileSystemMock.File);
        
        // Assert
        Assert.True(fileSystemMock.FileExists(fileName));
    }

    [Fact]
    [Trait(Traits.Category, Traits.PlatformDependent)]
    public void ShouldImportProvidedSeed_WithPin()
    {
        // Arrange
        var loggerSeed = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<SeedTpmService>();
        var seedTpmService = new SeedTpmService(loggerSeed);
        var seed = RandomNumberGenerator.GetBytes(32);
        ITpm2Facade facade;
        TpmHandle srkHandle;
        if(RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            facade = new Tpm2Facade<LinuxTpmDevice>(loggerSeed, new Tpm2DeviceCreationProperties() { DeviceName = "/dev/tpmrm0"});
            srkHandle = TpmHandle.Persistent(5);
        }
        else if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            facade = new Tpm2Facade<TbsDevice>(loggerSeed, new Tpm2DeviceCreationProperties());
            var ek = facade.CreateEk();
            srkHandle = ek.Handle;
        }
        else
        {
            throw new PlatformNotSupportedException("Current operating system not supported!");
        }
        
        // Act
        var result = seedTpmService.ImportSeedToTpm(facade, srkHandle, seed, "123456");
        
        // Assert
        Assert.NotNull(result);
    }

    [Fact]
    [Trait(Traits.Category, Traits.PlatformDependent)]
    public void GetPemEncodedEkCert_ShouldReturnX509Certificate()
    {
        // Arrange
        var logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<KeyAttestationService>();
                ITpm2Facade facade;
        if(RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            facade = new Tpm2Facade<LinuxTpmDevice>(logger, new Tpm2DeviceCreationProperties() { DeviceName = "/dev/tpmrm0"});
        }
        else if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            facade = new Tpm2Facade<TbsDevice>(logger, new Tpm2DeviceCreationProperties());
        }
        else
        {
            throw new PlatformNotSupportedException("Current operation system not supported!");
        }
        X509Certificate2? x509Cert = null;

        // Act
        try
        {
            x509Cert = new X509Certificate2(facade.GetEkCert());
        }
        catch {}

        // Assert
        Assert.NotNull(x509Cert);
    }
}