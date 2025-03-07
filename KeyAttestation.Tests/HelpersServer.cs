using KeyAttestation.Server.Entities;
using KeyAttestation.Server.Utils;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace KeyAttestation.Tests;

public class HelpersServer
{
    private const string Csr =
        "-----BEGIN CERTIFICATE REQUEST-----\nMIIIbjCCB1YCAQAwgZ8xETAPBgNVBAMMCDE4NDk3MzIwMQ4wDAYDVQQLDAVVc2Vy\nczESMBAGA1UECwwJTGludXhVc2VyMSUwIwYJKoZIhvcNAQkBFhZlZWFuaXNpbW92\nQHNiZXJiYW5rLnJ1MRUwEwYKCZImiZPyLGQBGRYFc2lnbWExFDASBgoJkiaJk/Is\nZAEZFgRzYnJmMRIwEAYKCZImiZPyLGQBGRYCcnUwggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQDj8W431PORupVZpz/ravvjzN+lZp8jBZrvQucIoKb7m8rP\nMWXnq7PFWnis9rbNBjfs5zzPaI6mz/HtueZLg1tuoGYmXeL5wwsfWpVn+2gRh1YW\nbR/yl45Ny5MkSORGqdayNOMIMzugE8x4hY7NV84CVvJX95h868WkKdW8ksfBFtvH\nuAL+HEarDXKQFOQ/BRqN3IO8MgOGSTOG6LOrRsTizPVh949a4wKa32a+7DOZyOiX\nwOg7aemWnqAlqrYJHZZmUNhAIwsiEjnFUr4l+o4YPcGEqaBiwtqvmlv24K+go+2o\n1++GXyVHXNgWc4MuMjgmqvDT7OG4FCD9+UAFvm5XAgMBAAGgggWHMBwGCisGAQQB\ngjcNAgMxDhYMMTAuMC4xOTA0NS4yMD4GCSqGSIb3DQEJDjExMC8wHQYDVR0OBBYE\nFCKlgZMXVnbgwA57tYNZj453tDljMA4GA1UdDwEB/wQEAwIFIDBcBgkrBgEEAYI3\nFRQxTzBNAgEJDA9DQUItV1NOLTAwMjcyODMMHFNJR01BXDE4NDk3MzIwQHNpZ21h\nLnNicmYucnUMGWF0dGVzdGF0aW9uX2dlbmVyYXRvci5leGUwZwYKKwYBBAGCNw0C\nAjFZMFcCAQEeUgBNAGkAYwByAG8AcwBvAGYAdAAgAEIAYQBzAGUAIABTAG0AYQBy\nAHQAIABDAGEAcgBkACAAQwByAHkAcAB0AG8AIABQAHIAbwB2AGkAZABlAHIwggRe\nBgkrBgEEAYI3FRgxggRPMIIESwYJKoZIhvcNAQcCMIIEPAIBATELBglghkgBZQME\nAgEwgZ4GCSqGSIb3DQEHAaCBkASBjf9UQ0eAFwAiAAvIwzt7Qn54qbpCZRyhhVyR\n5pTxVCjvDSC/EZfqEdXI/wAAAAAACVpe2zAAAAL1AAAAAAEABwACAAEAAAAiAAtZ\n8awd7EOHyt6ja5yn+lwz8ZLCK/fN2+4M96ItGN0QqQAiAAtoZszKcHxhBAGOBl4o\nycSsMEbljwqgqu9wTbb6XhNJ86CCAkIwggEZBgVngQUIAwSCAQ4wggEKAoIBAQD9\nmj8AShm6zcqJ8SaDNP6ugga3p4S6YLHhMFgDWNELA8eHnEBLpZo950Auef606UqG\n8Wy+9Jlgwrnk81uxhDp5K4Sjb1EGwcx/G+AzVZVAvCPnbzW4BZ4KX4/anO3fXpKo\n33R5YDO0Qv4vu1RoLL0st4tODfMW7jgXFRfSfS/YHxunNHcVtxisbvY8f6SAVdhW\n5Jvqgt0wlCLoCteGixDx5bFcKCNDLJgzhXmCIfq6flCkyRFYVjXuPvAsCKgg3LDT\ni3TdxyJt/xsG8rZUFQ3fEf8rja9+cBo3xubvBljzkJi7VWgAiTDRmRxQ5nSZHv9U\n6wpZvfBkkvZ4OdCgXIlpAgMBAAEwggEhBgVngQUIDASCARYAAQALAAYAcgAAABAA\nEAgAAAEAAQEA4/FuN9TzkbqVWac/62r748zfpWafIwWa70LnCKCm+5vKzzFl56uz\nxVp4rPa2zQY37Oc8z2iOps/x7bnmS4NbbqBmJl3i+cMLH1qVZ/toEYdWFm0f8peO\nTcuTJEjkRqnWsjTjCDM7oBPMeIWOzVfOAlbyV/eYfOvFpCnVvJLHwRbbx7gC/hxG\nqw1ykBTkPwUajdyDvDIDhkkzhuizq0bE4sz1YfePWuMCmt9mvuwzmcjol8DoO2np\nlp6gJaq2CR2WZlDYQCMLIhI5xVK+JfqOGD3BhKmgYsLar5pb9uCvoKPtqNfvhl8l\nR1zYFnODLjI4Jqrw0+zhuBQg/flABb5uV6EAMYIBPzCCATsCAQEEFAGdJCurP7ZN\npiVeF9VpqHwnhbkUMAsGCWCGSAFlAwQCAaAAMAsGCSqGSIb3DQEBAQSCAQC9I3Ej\n2tXkS3k7WHnUgLy3mPFnLPGQwyRYjROiWSRIklZMjlKl3I4zryrICCsHxHlbzaKA\n2ntzfLCBqnqLCnrbd2rB4ngdBh25Lk+1Fu6igXLsCzTnBzqRSFit4L+MJd3XnQEn\nfSL3PQc0pMoHoZSikqP5XGV7pN5OCWI1J2ekB2HA2Lky1wkg3UMgO4hO1jeV61q4\nOn/K/vyJmksxOoMq7dphYcEd44zKEnCbTI0T+DwCZUmLBqJDPAO3b8fnIWHr2K/5\n5xCvX2cCOvMgui1DPealqt0swdUc9H2BlPbEp+QlVlu30biPDT+1nKOaKHIEA09g\nEoFOX96KknVXZ1fNoQAwDQYJKoZIhvcNAQEFBQADggEBAAiFnc6mDwp+9sL2PJVf\nUYxPbBjE5MTSEVD6lagnzBPBZL8qs5wY7+poGqml77LjpZB7pFRrXjPcZQgVfUY4\nQv6zMYisyj5SstCxu/S7qoVGQEfaul1fRfM1yEoiJDjm2Fbp4IbL1m4Wgve1anpO\nPMMJEccyk8XFAXpUx+QgaOgPhS67WdiRGjj2af4UqfOTYObpF/nf65kUu70zZoiB\n2xiQMHC2L5iyWddn4pTocGsVtKxAaw2FDuvpvvXzBPfFCc/BVVwXPQscIPuVpNvN\nFturo7amOtpCoolAH6vlY7+Cyhdp0Saj4f8HhwJDtWtRYj66au9yIofkQM4HMONG\nokI=\n-----END CERTIFICATE REQUEST-----\n";
        
    [Fact]
    public void ShouldGenerateValidAttestationRequest_IfCCertificationRequestIsValid()
    {
        // Arrange
        var logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger("Helpers");
        using var textReader = new StringReader(Csr);
        using var pemReader = new PemReader(textReader);
        var pkcs10Request = (Pkcs10CertificationRequest)pemReader.ReadObject();
        
        // Act
        var attestationRequest = Helpers.GetAttestationRequest(pkcs10Request, logger);
        
        // Arrange
        Assert.IsType<AttestationData>(attestationRequest);
        Assert.NotNull(attestationRequest.Attestation);
        Assert.NotNull(attestationRequest.Signature);
        Assert.NotNull(attestationRequest.AikRsaPublic);
        Assert.NotNull(attestationRequest.ClientTpmPublic);
    }
}