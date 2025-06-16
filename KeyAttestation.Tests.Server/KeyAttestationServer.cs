using System.Runtime.InteropServices;
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

    private const string ValidCsr = "-----BEGIN CERTIFICATE REQUEST-----\nMIINhTCCDG0CAQAwgYgxEjAQBgNVBAMMCXRlc3RfdXNlcjEOMAwGA1UECwwFVXNl\ncnMxEjAQBgNVBAsMCUxpbnV4VXNlcjEiMCAGCSqGSIb3DQEJARYTdGVzdF91c2Vy\nQGxhYi5sb2NhbDETMBEGCgmSJomT8ixkARkWA2xhYjEVMBMGCgmSJomT8ixkARkW\nBWxvY2FsMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgFZDTSWvGNv6\n9MGAjzNKh0qMX+gyNs4UT2DyFSJPKGvbyC1AaRNCQgpCUTDQYhi59cgze4SI8k3P\nWVnXlRqWhTuVLMMhS9wB4GgyxHSmlgSSaNAizx2gQQjIjmOBa1PM/adaXgmxuNCo\nbOxqwyoPWV5epOpnKZVPvZC+SwtA/+iLc9+UxzF1DYuHpHLqmfhyFWHbqSvPdhYX\npgKo1fNwfMUG8/RUptS5L164RQHjwqrTg9Lf4+JZwywH0WfV8MifjNGREGPq5U3Q\n/lIMB6Ie+WurZ2YEq3SgdKgReEq2hueoJ/xG1LpBK4QN9rv3InJtTFKWx94aAnaP\nRe2UexCXEQIDAQABoIIKtTAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDUuMjA+\nBgkqhkiG9w0BCQ4xMTAvMB0GA1UdDgQWBBT0sxOHIm6pI6DTYCyh4MR+wdiPuTAO\nBgNVHQ8BAf8EBAMCBSAwTAYJKwYBBAGCNxUUMT8wPQIBCQwPREVWRUxPUEVSLUxB\nUFRPDAxMQUJccGlyb3pob2sMGWF0dGVzdGF0aW9uX2dlbmVyYXRvci5leGUwZwYK\nKwYBBAGCNw0CAjFZMFcCAQEeUgBNAGkAYwByAG8AcwBvAGYAdAAgAEIAYQBzAGUA\nIABTAG0AYQByAHQAIABDAGEAcgBkACAAQwByAHkAcAB0AG8AIABQAHIAbwB2AGkA\nZABlAHIwggmcBgkrBgEEAYI3FRgxggmNMIIJiTCCBfcGCSqGSIb3DQEHAqCCBegw\nggXkAgEBMQsGCWCGSAFlAwQCATCBngYJKoZIhvcNAQcBoIGQBIGN/1RDR4AXACIA\nC0rJ/c8xIwKSgxXKIREL4GgHFUOXlNK8ZwcdtP06YFsuAAAAAAABYm2gXQAAABAA\nAAABAQAKAAUAAAABACIAC+wrJo6RQtb52QzE4acWmphSWh5t/9lLs6a5z+qs9CMe\nACIAC4JiVAanZWUjdyv+TR8m2ErFpPNyMo1N+rmomhWAf313oIID5jCCA+IGBWeB\nBQgBBIID1zCCA9MwggNZoAMCAQICEQRduuxu+Ur3VOhG9oYAsg9AMAoGCCqGSM49\nBAMDMIGaMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UE\nBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSQwIgYD\nVQQLExtGSVJNV0FSRSBFS0lDQSBERklEMDBCMjBGNDAxHjAcBgNVBAMTFVBMVVRP\nTiBGaXJtd2FyZSBTVk4wNDAeFw0yMTA5MTUwMDAwMDBaFw0zOTEyMTUyMzU5NTla\nMIGdMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH\nUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMREwDwYDVQQL\nEwgxMC41LjAuMTE0MDIGA1UEAxMrUGx1dG9uSWQgMDQ1REJBRUM2RUY5NEFGNzU0\nRTg0NkY2ODYwMEIyMEY0MDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\nAIA9axAMUGITqcdi346+YiPuZ4ObOxtvtNe8Md9lpWA4Igk95IgIhmx/h3tf8TnZ\noOmgzkpiOPYhaay8DYrg3GIrgsVAzRvL6CUGRjxZsnqkaebL8bDWZ2tBjdOdin0Z\nkUY+Gn/gifMEdTdhzcM8Ksvy6opwgHR/2qcLx3TknA/rQqUjYPzkLMbY1XMWJ7O/\nVbm4HG+akGrh9POJHwf3xP9hb1sZZUFuxHhVPeXL/wRKjY7ZvT/simVEhK/xSclZ\n1EOJId74FtoDFhTbX/cqMy1bW0ooj+jdkFsktL0OXqcWDX65I2tR2VD3u6MMBauc\njI6UG2bpdM/ddN46VRQtA3UCAwEAAaOBrzCBrDBZBgNVHREBAf8ETzBNpEswSTEW\nMBQGBWeBBQIBDAtpZDo0RDUzNDY1NDEXMBUGBWeBBQICDAxQbHV0b24uVFBNLkEx\nFjAUBgVngQUCAwwLaWQ6MDAwYTAwMDUwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8E\nBAMCAwgwHwYDVR0jBBgwFoAUEOj0WJYRTYdNWWLP2pb/ogxoDgowEAYDVR0lBAkw\nBwYFZ4EFCAEwCgYIKoZIzj0EAwMDaAAwZQIxAIfzu1JHOtP6eRHZYtqVfiCglMbZ\n92GVDUJcGJ6DdHtpYWa7gN5RdNSYpaNi95FsYwIwCgdmnyvSAaA5MIfR8gynWOIw\nViidx0Y3uSMDUrL7q69V8NKw/BahGiMWBQRN+Y8JoQAxggFDMIIBPwIBAQQUlNrP\ne+luRlOW0ju3XqwZ5hRYOGYwCwYJYIZIAWUDBAIBoAAwCwYJKoZIhvcNAQEBBIIB\nBAALAQAhtEbxejd/2HpycHNVrWw9nkSZ9KWyVuLKHlUt/2mB5/cuC1U+nE+FNASU\n3Fje4we0iHfFP2O6vf6midQDVC1zEUxGb8KnaovocvcI2bVAAxO2S1fOZVj2YLxr\nuMCFs3beprpLWxWEwvHo+3pZjQ1/C9+9QFRHvFKEjPYspewypfJUc6IYkST72NF0\neurohQtihQTMJ9nfqh9uzINIWUdV389RQvoKh/leGJLQKkA8VYaeDF632RGMBsQk\nUc4x0gOKYKxuxDm7FnjeGw7KZpqc4apwb/7RVFrUsG1pJc3S3RyiywGONSfa3fmo\nahY9aX+CKknQH3Ma8j0zO8SqnZUGoQAwggOKMIIBLDALBgkqhkiG9w0BAQEDggEb\nAAABAAsAAwByAAAABgEAAEMAEAgAAAEAAQEAgBb3WHvnvZ/kc3pvfGw+0iOsObOB\nvSvvY3bHOSp4NVUmsKy1pR0VLXCI9p0DRyD6nhuUUSjDOZrwmMK9iv1bkPIxlnRc\nulLAJePGxM6vg724F+Pe+DpPSS3ruiqeL9SGNrhhBV487wotE0KyegOMXzGhczdZ\nvJTShBIHT8tMz2iAe7zFFtVmD/M8yb+O5igs4RHP0685SlpWCcrkMFL4O4mASv5z\n2yAik6HXDBR9hcqC6MgZO+a2vzUyI/BP2BXRS70t7ukdJ9bqtuMPhzx7khbwnH5V\nRnqr3DPNoAXjUOgJH0kk8i8lbMvdNs64iRPdZVb/iYdn+21GiDlkl7oEgTCCASow\nCwYJKoZIhvcNAQEBA4IBGQAAAQALAAUAcgAAABAAFAALCAAAAQABAQCADFdV68Ch\nSH/mPAgQ9tLJ8aOgMgEFLjAyAznNxcSYo9Ctlg0uaoedaD//u7CEKUkQhipr+dj2\ney+AAUHTEcW0kMvQ7AcRaUmCvdIyv843r9B4nuydGi0ri7NDmaHvA8jzQ8SQGwnO\no8fZ/Fg+aXrNxrzbwo/qWiYRVKM9IEe75wRsmqbxmkmM7bY/Y16pGI+rr643+iB5\n5DqVQSBgy9Bifk/hsv+SJf7HLKg81ZCyCLPBOHjVLuwgz/Mw94b86z+1VwSKM/AT\n4+4T0OxSZjUAjt2LSQUTXwjJZvNqPP7FzWnH65/7C1YxcTqm9v4T9+MTXDsDXXTc\nAVZ99ofBm6Y1MIIBKDALBgkqhkiG9w0BAQEDggEXAAABAAsABgByAAAAEAAQCAAA\nAQABAQCAVkNNJa8Y2/r0wYCPM0qHSoxf6DI2zhRPYPIVIk8oa9vILUBpE0JCCkJR\nMNBiGLn1yDN7hIjyTc9ZWdeVGpaFO5UswyFL3AHgaDLEdKaWBJJo0CLPHaBBCMiO\nY4FrU8z9p1peCbG40Khs7GrDKg9ZXl6k6mcplU+9kL5LC0D/6Itz35THMXUNi4ek\ncuqZ+HIVYdupK892FhemAqjV83B8xQbz9FSm1LkvXrhFAePCqtOD0t/j4lnDLAfR\nZ9XwyJ+M0ZEQY+rlTdD+UgwHoh75a6tnZgSrdKB0qBF4SraG56gn/EbUukErhA32\nu/cicm1MUpbH3hoCdo9F7ZR7EJcRMA0GCSqGSIb3DQEBBQUAA4IBAQAokC4R02/N\nPrqkzOHSuIb/RnoTmhrQhkobruVm7edskCyl7kaFqiSlqMGZyRJ2AxxLf0ZfFQEV\nakdIHEuAGJSTqG26Yb7OJM4+CPVL2CqFmSZDMKU9qoP48WiE5eOZiXG3MfWO0YVc\nZD5EndFP13ktfxsPhAiyZB3uWWgOEG99DNujD1zNTHsoM9tupvQqgPK0ijUEc9iE\nH/krwBXMzoGbjoa0a90r/6XrNuDJi3ePraOuLGc4NwO/K3rq7KPEpQRlWVg2b0Ft\ng7WoJNOGu3nDZv+rmUCpjcfC0TtZ6ybeagwTC0+8r5XDYn9TPypAS2sk+gw1Kkdj\nwA24pNzTrLak\n-----END CERTIFICATE REQUEST-----\n";
    private const string IncorrectCsr = "-----BEGIN CERTIFICATE REQUEST-----\nlkfdljvlnwlfnvlwnvflnkkwfKLLKNKNNLKLKKNLNlndfklgnNKNKNLKLNbGDHDHG=\n-----END CERTIFICATE REQUEST-----";
    
    private const string EkPubCorrect =
        "AAEACwADALIAIINxl2dEhLP4GpDMjUal1yT9UtduBlILZPKh2hszFGmqAAYAgABDABAIAAAAAAAB\nAK47ninXU/If3wBLp1n7mWIiEJimgcKNezNvV1TcbACprCXHK7ebHAdjZprnoPmm9H1i1hCyZBOa\nXSyyb5aA7ImvgXgOHSpCNNpW18vzHbdDEPL3QMN9HVsauWFIJ0lRSU4WPjqbNavsMYiIGbO01CGp\nQBpLYn0LL0pALugx+VnivOR13HurIZn7E6G6RRc6JPjp8rmDWD+FQtPgrVpqHovbSvibMyNsMoST\nXvRNshvgNCDIF46kMPIeR2AYguvk9pJugAz27+XI+4VMssLRgcvvFUWV8CxFBMj6mGtelER0Kwr5\nfIAFCp1LbHUkb8iWnP8eh0TQyCaYKoDLFCPmgGM=";

    private const string EkPubIncorrect = "Zmxka2ZtY2xudmt3amVubGtuY2x3a2VuZGxjbmx3ZW5jbG53ZWxqa2Nud2VkbGtqbHdlZGNuZGtqbG53ZWRkY2prbmprZWRjamtlY2RlY2Rqa2V3ZGprZWRjamtlZGNqa25uandlYw==";
    
    [Theory]
    [InlineData(ValidCsr, IncorrectCsr)]
    public void ShouldGenerateAttestationData_IfCsrIsCorrect(string validCsr, string incorrectCsr)
    {
        // Arrange
        var keyAttestationService = _keyAttestationServerFixture.KeyAttestationService;
        
        // Act
        var attestationDataCorrect = keyAttestationService.GetAttestationData(validCsr);
        var attestationDataIncorrect = keyAttestationService.GetAttestationData(incorrectCsr);
        
        // Arrange
        Assert.NotNull(attestationDataCorrect);
        Assert.Null(attestationDataIncorrect);
    }
    
    [Fact]
    public void ShouldGenerateCredential_IfAttestationDataIsNotNull()
    {
        // Arrange
        var keyAttestationService = _keyAttestationServerFixture.KeyAttestationService;
        
        // Act
        var attestationDataValid = keyAttestationService.GetAttestationData(ValidCsr);
        var credentialValid = keyAttestationService.MakeCredential(attestationDataValid);

        // Assert
        Assert.NotNull(credentialValid);
    }
    
    [Theory]
    [InlineData(ForgedCsr, ValidCsr)]
    public void ShouldVerifyAttestData_IfCsrIsCorrect(string forgedCsr, string validCsr)
    {
        // Arrange
        var keyAttestationService = _keyAttestationServerFixture.KeyAttestationService;
        
        // Act
        var attestationDataWithInValidCsr = keyAttestationService.GetAttestationData(forgedCsr);
        var attestationDataWithValidCsr = keyAttestationService.GetAttestationData(validCsr);
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