using Attestation.Shared;
using Attestation.Shared.Entities;
using KeyAttestation.Server.Services;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Tpm2Lib;

namespace KeyAttestation.Tests;

public class HelpersServer
{
    private const string Csr =
        "-----BEGIN CERTIFICATE REQUEST-----\nMIIIeDCCB2ACAQAwgZ8xETAPBgNVBAMMCDE4NDk3MzIwMQ4wDAYDVQQLDAVVc2Vy\nczESMBAGA1UECwwJTGludXhVc2VyMSUwIwYJKoZIhvcNAQkBFhZlZWFuaXNpbW92\nQHNiZXJiYW5rLnJ1MRUwEwYKCZImiZPyLGQBGRYFc2lnbWExFDASBgoJkiaJk/Is\nZAEZFgRzYnJmMRIwEAYKCZImiZPyLGQBGRYCcnUwggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQCxswEONqUuM2n5T0JgTJgctviBLYm7QpMEPczDe5G3QMCt\niG1QgzGneH42g3vNZ2+fT4XBZXyoISmkdoTZtx/4YKvvzRf3sdo2JjOgk2caQmta\nJLFgrwJTjSyEBl948mfF/z0OX/4oR6ujWaupqICUKwTE1JmYw8VRLoziUZPWOBT+\nED2cpzXsYwRMKS6590PaWRRQjCh2LWPJaQVsHb8ycBQ9ZcmAP1YLffd5rCmxHGjz\ngHCRUC9vjg4YkqRG+EAl0D1pK+F1E3FQ6y6nIWRjKYhbE9E5TsdcJoq59d/NXxp5\n5wOGHIOypEWUVIFNsVrhdF0WpC2075EhiRT89DJ1AgMBAAGgggWRMBwGCisGAQQB\ngjcNAgMxDhYMMTAuMC4xOTA0NS4yMD4GCSqGSIb3DQEJDjExMC8wHQYDVR0OBBYE\nFHQubgtxiInP69UwIYJJ+H8xZbO9MA4GA1UdDwEB/wQEAwIFIDBcBgkrBgEEAYI3\nFRQxTzBNAgEJDA9DQUItV1NOLTAwMjcyODMMHFNJR01BXDE4NDk3MzIwQHNpZ21h\nLnNicmYucnUMGWF0dGVzdGF0aW9uX2dlbmVyYXRvci5leGUwZwYKKwYBBAGCNw0C\nAjFZMFcCAQEeUgBNAGkAYwByAG8AcwBvAGYAdAAgAEIAYQBzAGUAIABTAG0AYQBy\nAHQAIABDAGEAcgBkACAAQwByAHkAcAB0AG8AIABQAHIAbwB2AGkAZABlAHIwggRo\nBgkrBgEEAYI3FRgxggRZMIIEVQYJKoZIhvcNAQcCMIIERgIBATELBglghkgBZQME\nAgEwgZ4GCSqGSIb3DQEHAaCBkASBjf9UQ0eAFwAiAAuKuO/NmUj/0rPpJ6r78bZ+\nq6Dk+71dvdLBVq5sdkvSHQAAAAAACWopZ/YAAAL1AAAAAAEABwACAAEAAAAiAAvx\n4rPc7uay1957Vj9buKCCb6R3aJu2wR/x03juIVXg4QAiAAv9OV8LQH9Fjsvl4GkV\nRCN3jvFH9SyscOfjpNu2lakFn6CCAkwwggEhBgVngQUIDASCARYAAQALAAYAcgAA\nABAAEAgAAAEAAQEAsbMBDjalLjNp+U9CYEyYHLb4gS2Ju0KTBD3Mw3uRt0DArYht\nUIMxp3h+NoN7zWdvn0+FwWV8qCEppHaE2bcf+GCr780X97HaNiYzoJNnGkJrWiSx\nYK8CU40shAZfePJnxf89Dl/+KEero1mrqaiAlCsExNSZmMPFUS6M4lGT1jgU/hA9\nnKc17GMETCkuufdD2lkUUIwodi1jyWkFbB2/MnAUPWXJgD9WC333eawpsRxo84Bw\nkVAvb44OGJKkRvhAJdA9aSvhdRNxUOsupyFkYymIWxPROU7HXCaKufXfzV8aeecD\nhhyDsqRFlFSBTbFa4XRdFqQttO+RIYkU/PQydTCCASMGBWeBBQgDBIIBGAABAAsA\nBQByAAAAEAAUAAsIAAABAAEBALa/hbMk1crMXYkXDsqIktLrIBjwaBGToXobqAEo\nKvmyPm1ytlC3oV+gA0RwrULeI5cd9QQjNX/JuB191aYQU9YfnKiiUWyM1JDIu3tY\nq49xXiBRjCaJKqLpu8vXY/wZgEe7fCBkJJ0Xd5qH+JIVCa0dsP5oAbRnz+HyoCKY\n4YL1AlOmp7zvjh1J0FY9MrLn2Z2d1jAMDzGOtKA0bAoCSDMdr+S5Ct9cxIam3XoV\nX/6gGLy9Lq9zsG7r9OMSJrPLYuq1pEXmePp+UAV23eUFNN/UHB01622Xr+OBF9Xh\nKBD9oywDRu6iPx5ZhSjAslr5gNtkxpfNy8ravHHLfWDOAH2hADGCAT8wggE7AgEB\nBBQj18HNzx80nOBCRyon/S9XWyL/NzALBglghkgBZQMEAgGgADALBgkqhkiG9w0B\nAQEEggEAltcO6iNgF+wmfrWrxYf2W/c7wkkGUU8HNVfoFLR5dWBQEI4Wkk0Q8sxa\neeGzvZOKH9itGKOOcHpEf5UvGSvwwxTO5zzDsMVjuEcpi/3gaUDju8+ScCjYP9q+\nX6zoWhVwjz5yh9OSIG5gHLA3SrkOrgB2w2VHpY30vR92JQ9qVei3pVoUwlj7/xbx\n+m2QLa4ueaueGtMdFwwKVBID/iUQN6L8ZHrTG2GvhoYjKWDgd6FDwE9xGI8HPvC8\nGpybuHjpTFvS3YnnhwLIHd5heTVencXbRNcHS9TUnxH1S4XNrz8gQ4mS4bq2+hwM\ntklhcaTcxRHwrzM15ejNJ6WpynGzPqEAMA0GCSqGSIb3DQEBBQUAA4IBAQA9nJS8\n3Gw9CvQFE9wVAh2h5rnW87AGVKEPlfylpiwWLcYjYUPhHEKNQj1+qbPZ1kmsKYWD\nTBGSI0qONxIe0H7G/ovZMyvtOT+XBwCsIXrhkSjeVRq/QpyHk3xfPS5nnOTHRuRa\nDCs8qFLvDd6w5R4tL0OvRN0tAEoBUi/k6tJUntIF6JCmb/fhpd5I5MR6oDjoIChw\nbXFKmIo2hyIPhmYkDFueZyAMFKbT3B9oa1rTcnYQE5LnS89LBlgyF3opxtEOK29A\npoZiJ7O/s/nJIBo+BcQ+9KRpDLVMn4dqomQhOxUIGIX5cClt6JdB9/squaAfP6lm\nkG+SiHaSKQ4l6fJ7\n-----END CERTIFICATE REQUEST-----";

    private const string EkPub =
        "AAEACwADALIAIINxl2dEhLP4GpDMjUal1yT9UtduBlILZPKh2hszFGmqAAYAgABDABAIAAAAAAAB\nAK47ninXU/If3wBLp1n7mWIiEJimgcKNezNvV1TcbACprCXHK7ebHAdjZprnoPmm9H1i1hCyZBOa\nXSyyb5aA7ImvgXgOHSpCNNpW18vzHbdDEPL3QMN9HVsauWFIJ0lRSU4WPjqbNavsMYiIGbO01CGp\nQBpLYn0LL0pALugx+VnivOR13HurIZn7E6G6RRc6JPjp8rmDWD+FQtPgrVpqHovbSvibMyNsMoST\nXvRNshvgNCDIF46kMPIeR2AYguvk9pJugAz27+XI+4VMssLRgcvvFUWV8CxFBMj6mGtelER0Kwr5\nfIAFCp1LbHUkb8iWnP8eh0TQyCaYKoDLFCPmgGM=";
        
    [Fact]
    public void ShouldGenerateValidAttestationRequest_IfCsrIsValid()
    {
        // Arrange
        var logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<KeyAttestationService>();
        var keyAttestationService = new KeyAttestationService(logger);
        
        // Act
        var attestationData = keyAttestationService.GetAttestationDataAsync(Csr);
        
        // Arrange
        Assert.IsType<AttestationData>(attestationData);
        Assert.NotNull(attestationData.Attestation);
        Assert.NotNull(attestationData.Signature);
        Assert.NotNull(attestationData.AikTpmPublic);
        Assert.NotNull(attestationData.ClientTpmPublic);
    }

    [Fact]
    public void ShouldMakeValidIdObject_IfAttestDataIsCorrect()
    {
        // Arrange
        var logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<KeyAttestationService>();
        var keyAttestationService = new KeyAttestationService(logger);
        
        // Act
        var ekPub = Convert.FromBase64String(EkPub);
        var attestationData = keyAttestationService.GetAttestationDataAsync(Csr);
        var attestBlob = keyAttestationService.MakeCredentialsAsync(attestationData, ekPub);
        
        // Assert
        Assert.NotEmpty(attestBlob);
    }
}