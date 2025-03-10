using System.IO.Abstractions.TestingHelpers;
using Attestation.Shared;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace KeyAttestation.Tests;

public class HelpersClient
{
    private const string Csr =
        "-----BEGIN CERTIFICATE REQUEST-----\nMIICgTCCAWkCAQAwPDENMAsGA1UEAwwEdGVzdDEUMBIGCgmSJomT8ixkARkWBHRl\nc3QxFTATBgoJkiaJk/IsZAEZFgVsb2NhbDCCASIwDQYJKoZIhvcNAQEBBQADggEP\nADCCAQoCggEBAMDOT5B0q6XLaQkXV1Ryt22TM2lM+RnVXkqzzO3BZiHIwSWa/FCc\nCTbicVB6WDAVAH/8wk7INkxvjLT9U7NAtrdVjOcJsa1T71WNwYQLprTB0uvWFwiv\nhAUnr4DdortYsKC62y1wXEygJ9ymO93uYwN9VWz7JUwGJvXLWehpls6p/IfHcKbb\nyhW8xGhCKb0WWjlkdu6nCA62h+cnH84T/4unoLfvs0BrpreS4MzFxcN8ivvGaAYA\nhy/8gXp+Vje5yIEpQUqDHeYorzZfq/IUiWm82qaELF3XN4fEsG5ZJGajCrOJVpsd\npgXxGDI6X8i+eWkpuyB85fLPsybxhfV1VhUCAwEAAaAAMA0GCSqGSIb3DQEBCwUA\nA4IBAQAiVE18IbwIpo/4MAAVN+1ZXNUxNEuV1bF/jrm67PAoOaNIBK3b2Isj2n+x\nTHG2xMLFBku5usgFG135lWgTHqznVgyYPaDPwDq3kbHkRv3+R2loPI1DTm7dxqbZ\nWOh9w8QwbLZm74zuqn4V80EM4vCXR2oLahhebmhCmqy8DGMw+NXm1xqBsttEDbda\nPf2acgib/VQ6XLgCcOYFZ8oW7i9GMm7gxEt9HjgFqUeKfLGoYRQF32BptFjKVmqn\nohG62kH1SdaWIAeB3qehGgG/YsnrRI3NtM7j1nDV/r12132VDi3DXkZDeKOofVUO\narAQnYyOiQ41ye3/FsHWosDiPpUr\n-----END CERTIFICATE REQUEST-----";
    
    [Theory]
    [InlineData(2164260861, @"^0x\w{8}$")]
    public void ShouldReturnValidHexString(uint value, string pattern)
    {
        // Act
        var result = Helpers.ToHexString(value);
        
        // Assert
        Assert.NotEmpty(result);
        Assert.Matches(pattern, result);
    }

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
        await Helpers.WriteCsrAsync(csr, fileName, fileSystemMock.File);
        
        // Assert
        Assert.True(fileSystemMock.FileExists(fileName));
    }
}