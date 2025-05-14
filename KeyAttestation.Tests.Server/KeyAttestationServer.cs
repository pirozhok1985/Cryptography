using Tpm2Lib;

namespace KeyAttestation.Tests.Server;

public class KeyAttestationServer : IClassFixture<KeyAttestationServerFixture>
{
    private readonly KeyAttestationServerFixture _keyAttestationServerFixture;

    public KeyAttestationServer(KeyAttestationServerFixture keyAttestationServerFixture)
    {
        _keyAttestationServerFixture = keyAttestationServerFixture;
    }

    private const string ForgedCsr =
        "-----BEGIN CERTIFICATE REQUEST-----\nMIIIeDCCB2ACAQAwgZ8xETAPBgNVBAMMCDE4NDk3MzIwMQ4wDAYDVQQLDAVVc2Vy\nczESMBAGA1UECwwJTGludXhVc2VyMSUwIwYJKoZIhvcNAQkBFhZlZWFuaXNpbW92\nQHNiZXJiYW5rLnJ1MRUwEwYKCZImiZPyLGQBGRYFc2lnbWExFDASBgoJkiaJk/Is\nZAEZFgRzYnJmMRIwEAYKCZImiZPyLGQBGRYCcnUwggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQCxswEONqUuM2n5T0JgTJgctviBLYm7QpMEPczDe5G3QMCt\niG1QgzGneH42g3vNZ2+fT4XBZXyoISmkdoTZtx/4YKvvzRf3sdo2JjOgk2caQmta\nJLFgrwJTjSyEBl948mfF/z0OX/4oR6ujWaupqICUKwTE1JmYw8VRLoziUZPWOBT+\nED2cpzXsYwRMKS6590PaWRRQjCh2LWPJaQVsHb8ycBQ9ZcmAP1YLffd5rCmxHGjz\ngHCRUC9vjg4YkqRG+EAl0D1pK+F1E3FQ6y6nIWRjKYhbE9E5TsdcJoq59d/NXxp5\n5wOGHIOypEWUVIFNsVrhdF0WpC2075EhiRT89DJ1AgMBAAGgggWRMBwGCisGAQQB\ngjcNAgMxDhYMMTAuMC4xOTA0NS4yMD4GCSqGSIb3DQEJDjExMC8wHQYDVR0OBBYE\nFHQubgtxiInP69UwIYJJ+H8xZbO9MA4GA1UdDwEB/wQEAwIFIDBcBgkrBgEEAYI3\nFRQxTzBNAgEJDA9DQUItV1NOLTAwMjcyODMMHFNJR01BXDE4NDk3MzIwQHNpZ21h\nLnNicmYucnUMGWF0dGVzdGF0aW9uX2dlbmVyYXRvci5leGUwZwYKKwYBBAGCNw0C\nAjFZMFcCAQEeUgBNAGkAYwByAG8AcwBvAGYAdAAgAEIAYQBzAGUAIABTAG0AYQBy\nAHQAIABDAGEAcgBkACAAQwByAHkAcAB0AG8AIABQAHIAbwB2AGkAZABlAHIwggRo\nBgkrBgEEAYI3FRgxggRZMIIEVQYJKoZIhvcNAQcCMIIERgIBATELBglghkgBZQME\nAgEwgZ4GCSqGSIb3DQEHAaCBkASBjf9UQ0eAFwAiAAuKuO/NmUj/0rPpJ6r78bZ+\nq6Dk+71dvdLBVq5sdkvSHQAAAAAACWopZ/YAAAL1AAAAAAEABwACAAEAAAAiAAvx\n4rPc7uay1957Vj9buKCCb6R3aJu2wR/x03juIVXg4QAiAAv9OV8LQH9Fjsvl4GkV\nRCN3jvFH9SyscOfjpNu2lakFn6CCAkwwggEhBgVngQUIDASCARYAAQALAAYAcgAA\nABAAEAgAAAEAAQEAsbMBDjalLjNp+U9CYEyYHLb4gS2Ju0KTBD3Mw3uRt0DArYht\nUIMxp3h+NoN7zWdvn0+FwWV8qCEppHaE2bcf+GCr780X97HaNiYzoJNnGkJrWiSx\nYK8CU40shAZfePJnxf89Dl/+KEero1mrqaiAlCsExNSZmMPFUS6M4lGT1jgU/hA9\nnKc17GMETCkuufdD2lkUUIwodi1jyWkFbB2/MnAUPWXJgD9WC333eawpsRxo84Bw\nkVAvb44OGJKkRvhAJdA9aSvhdRNxUOsupyFkYymIWxPROU7HXCaKufXfzV8aeecD\nhhyDsqRFlFSBTbFa4XRdFqQttO+RIYkU/PQydTCCASMGBWeBBQgDBIIBGAABAAsA\nBQByAAAAEAAUAAsIAAABAAEBALa/hbMk1crMXYkXDsqIktLrIBjwaBGToXobqAEo\nKvmyPm1ytlC3oV+gA0RwrULeI5cd9QQjNX/JuB191aYQU9YfnKiiUWyM1JDIu3tY\nq49xXiBRjCaJKqLpu8vXY/wZgEe7fCBkJJ0Xd5qH+JIVCa0dsP5oAbRnz+HyoCKY\n4YL1AlOmp7zvjh1J0FY9MrLn2Z2d1jAMDzGOtKA0bAoCSDMdr+S5Ct9cxIam3XoV\nX/6gGLy9Lq9zsG7r9OMSJrPLYuq1pEXmePp+UAV23eUFNN/UHB01622Xr+OBF9Xh\nKBD9oywDRu6iPx5ZhSjAslr5gNtkxpfNy8ravHHLfWDOAH2hADGCAT8wggE7AgEB\nBBQj18HNzx80nOBCRyon/S9XWyL/NzALBglghkgBZQMEAgGgADALBgkqhkiG9w0B\nAQEEggEAltcO6iNgF+wmfrWrxYf2W/c7wkkGUU8HNVfoFLR5dWBQEI4Wkk0Q8sxa\neeGzvZOKH9itGKOOcHpEf5UvGSvwwxTO5zzDsMVjuEcpi/3gaUDju8+ScCjYP9q+\nX6zoWhVwjz5yh9OSIG5gHLA3SrkOrgB2w2VHpY30vR92JQ9qVei3pVoUwlj7/xbx\n+m2QLa4ueaueGtMdFwwKVBID/iUQN6L8ZHrTG2GvhoYjKWDgd6FDwE9xGI8HPvC8\nGpybuHjpTFvS3YnnhwLIHd5heTVencXbRNcHS9TUnxH1S4XNrz8gQ4mS4bq2+hwM\ntklhcaTcxRHwrzM15ejNJ6WpynGzPqEAMA0GCSqGSIb3DQEBBQUAA4IBAQA9nJS8\n3Gw9CvQFE9wVAh2h5rnW87AGVKEPlfylpiwWLcYjYUPhHEKNQj1+qbPZ1kmsKYWD\nTBGSI0qONxIe0H7G/ovZMyvtOT+XBwCsIXrhkSjeVRq/QpyHk3xfPS5nnOTHRuRa\nDCs8qFLvDd6w5R4tL0OvRN0tAEoBUi/k6tJUntIF6JCmb/fhpd5I5MR6oDjoIChw\nbXFKmIo2hyIPhmYkDFueZyAMFKbT3B9oa1rTcnYQE5LnS89LBlgyF3opxtEOK29A\npoZiJ7O/s/nJIBo+BcQ+9KRpDLVMn4dqomQhOxUIGIX5cClt6JdB9/squaAfP6lm\nkG+SiHaSKQ4l6fJ7\n-----END CERTIFICATE REQUEST-----";

    private const string ValidCsr = "-----BEGIN CERTIFICATE REQUEST-----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-----END CERTIFICATE REQUEST-----";

    private const string IncorrectCsr = "-----BEGIN CERTIFICATE REQUEST-----\nlkfdljvlnwlfnvlwnvflnkkwfKLLKNKNNLKLKKNLNlndfklgnNKNKNLKLNbGDHDHG=\n-----END CERTIFICATE REQUEST-----";
    
    private const string EkPubCorrect =
        "AAEACwADALIAIINxl2dEhLP4GpDMjUal1yT9UtduBlILZPKh2hszFGmqAAYAgABDABAIAAAAAAAB\nAK47ninXU/If3wBLp1n7mWIiEJimgcKNezNvV1TcbACprCXHK7ebHAdjZprnoPmm9H1i1hCyZBOa\nXSyyb5aA7ImvgXgOHSpCNNpW18vzHbdDEPL3QMN9HVsauWFIJ0lRSU4WPjqbNavsMYiIGbO01CGp\nQBpLYn0LL0pALugx+VnivOR13HurIZn7E6G6RRc6JPjp8rmDWD+FQtPgrVpqHovbSvibMyNsMoST\nXvRNshvgNCDIF46kMPIeR2AYguvk9pJugAz27+XI+4VMssLRgcvvFUWV8CxFBMj6mGtelER0Kwr5\nfIAFCp1LbHUkb8iWnP8eh0TQyCaYKoDLFCPmgGM=";

    private const string EkPubIncorrect = "Zmxka2ZtY2xudmt3amVubGtuY2x3a2VuZGxjbmx3ZW5jbG53ZWxqa2Nud2VkbGtqbHdlZGNuZGtqbG53ZWRkY2prbmprZWRjamtlY2RlY2Rqa2V3ZGprZWRjamtlZGNqa25uandlYw==";
    
    [Fact]
    public void ShouldGenerateAttestationData_IfCsrIsCorrect()
    {
        // Arrange
        var keyAttestationService = _keyAttestationServerFixture.KeyAttestationService;
        
        // Act
        var attestationDataCorrect = keyAttestationService.GetAttestationData(ValidCsr);
        var attestationDataIncorrect = keyAttestationService.GetAttestationData(IncorrectCsr);
        
        // Arrange
        Assert.NotNull(attestationDataCorrect);
        Assert.Null(attestationDataIncorrect);
    }
    
    [Fact]
    public void ShouldGenerateCredential_IfAttestationDataIsNotNull_And_EkPubIsCorrect()
    {
        // Arrange
        var keyAttestationService = _keyAttestationServerFixture.KeyAttestationService;
        var ekPubCorrect = Convert.FromBase64String(EkPubCorrect);
        var ekPubIncorrect = Convert.FromBase64String(EkPubIncorrect);
        
        // Act
        var attestationData = keyAttestationService.GetAttestationData(ValidCsr);
        var credentialValid = keyAttestationService.MakeCredential(attestationData!.AikTpmPublic.GetName(), ekPubCorrect);
        var credentialInvalid = keyAttestationService.MakeCredential(attestationData!.AikTpmPublic.GetName(), ekPubIncorrect);

        // Assert
        Assert.NotNull(credentialValid);
        Assert.Null(credentialInvalid);
    }
    
    [Fact]
    public void ShouldVerifyAttestData_IfCsrIsCorrect()
    {
        // Arrange
        var keyAttestationService = _keyAttestationServerFixture.KeyAttestationService;
        
        // Act
        var attestationDataWithInValidCsr = keyAttestationService.GetAttestationData(ForgedCsr);
        var attestationDataWithValidCsr = keyAttestationService.GetAttestationData(ValidCsr);
        var attestResultInvalid = keyAttestationService.Attest(attestationDataWithInValidCsr!);
        var attestResultValid = keyAttestationService.Attest(attestationDataWithValidCsr!);

        // Assert
        Assert.False(attestResultInvalid!.Result);
        Assert.True(attestResultValid!.Result);
    }
    
    [Fact]
    public void ShouldGenerateRandomHmacKey_IfOtpSeedServiceIsInitialised()
    {
        // Arrange
        var keyAttestationService = _keyAttestationServerFixture.KeyAttestationService;
        var otpSeedService = _keyAttestationServerFixture.OtpSeedService;
        var ekPubCorrect = Convert.FromBase64String(EkPubCorrect);
        
        // Act
        var attestationData = keyAttestationService.GetAttestationData(ValidCsr);
        var seed = otpSeedService.MakeSeedBasedCredential(
            attestationData!.AikTpmPublic.GetName(),
            Marshaller.FromTpmRepresentation<TpmPublic>(ekPubCorrect));
        
        //Assert
        Assert.NotNull(seed);
    }
}