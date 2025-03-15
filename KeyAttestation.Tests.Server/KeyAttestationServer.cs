namespace KeyAttestation.Tests.Server;

public class KeyAttestationServer : IClassFixture<KeyAttestationServiceServerFixture>
{
    private readonly KeyAttestationServiceServerFixture _keyAttestationServiceServerFixture;

    public KeyAttestationServer(KeyAttestationServiceServerFixture keyAttestationServiceServerFixture)
    {
        _keyAttestationServiceServerFixture = keyAttestationServiceServerFixture;
    }

    private const string ForgedCsr =
        "-----BEGIN CERTIFICATE REQUEST-----\nMIIIeDCCB2ACAQAwgZ8xETAPBgNVBAMMCDE4NDk3MzIwMQ4wDAYDVQQLDAVVc2Vy\nczESMBAGA1UECwwJTGludXhVc2VyMSUwIwYJKoZIhvcNAQkBFhZlZWFuaXNpbW92\nQHNiZXJiYW5rLnJ1MRUwEwYKCZImiZPyLGQBGRYFc2lnbWExFDASBgoJkiaJk/Is\nZAEZFgRzYnJmMRIwEAYKCZImiZPyLGQBGRYCcnUwggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQCxswEONqUuM2n5T0JgTJgctviBLYm7QpMEPczDe5G3QMCt\niG1QgzGneH42g3vNZ2+fT4XBZXyoISmkdoTZtx/4YKvvzRf3sdo2JjOgk2caQmta\nJLFgrwJTjSyEBl948mfF/z0OX/4oR6ujWaupqICUKwTE1JmYw8VRLoziUZPWOBT+\nED2cpzXsYwRMKS6590PaWRRQjCh2LWPJaQVsHb8ycBQ9ZcmAP1YLffd5rCmxHGjz\ngHCRUC9vjg4YkqRG+EAl0D1pK+F1E3FQ6y6nIWRjKYhbE9E5TsdcJoq59d/NXxp5\n5wOGHIOypEWUVIFNsVrhdF0WpC2075EhiRT89DJ1AgMBAAGgggWRMBwGCisGAQQB\ngjcNAgMxDhYMMTAuMC4xOTA0NS4yMD4GCSqGSIb3DQEJDjExMC8wHQYDVR0OBBYE\nFHQubgtxiInP69UwIYJJ+H8xZbO9MA4GA1UdDwEB/wQEAwIFIDBcBgkrBgEEAYI3\nFRQxTzBNAgEJDA9DQUItV1NOLTAwMjcyODMMHFNJR01BXDE4NDk3MzIwQHNpZ21h\nLnNicmYucnUMGWF0dGVzdGF0aW9uX2dlbmVyYXRvci5leGUwZwYKKwYBBAGCNw0C\nAjFZMFcCAQEeUgBNAGkAYwByAG8AcwBvAGYAdAAgAEIAYQBzAGUAIABTAG0AYQBy\nAHQAIABDAGEAcgBkACAAQwByAHkAcAB0AG8AIABQAHIAbwB2AGkAZABlAHIwggRo\nBgkrBgEEAYI3FRgxggRZMIIEVQYJKoZIhvcNAQcCMIIERgIBATELBglghkgBZQME\nAgEwgZ4GCSqGSIb3DQEHAaCBkASBjf9UQ0eAFwAiAAuKuO/NmUj/0rPpJ6r78bZ+\nq6Dk+71dvdLBVq5sdkvSHQAAAAAACWopZ/YAAAL1AAAAAAEABwACAAEAAAAiAAvx\n4rPc7uay1957Vj9buKCCb6R3aJu2wR/x03juIVXg4QAiAAv9OV8LQH9Fjsvl4GkV\nRCN3jvFH9SyscOfjpNu2lakFn6CCAkwwggEhBgVngQUIDASCARYAAQALAAYAcgAA\nABAAEAgAAAEAAQEAsbMBDjalLjNp+U9CYEyYHLb4gS2Ju0KTBD3Mw3uRt0DArYht\nUIMxp3h+NoN7zWdvn0+FwWV8qCEppHaE2bcf+GCr780X97HaNiYzoJNnGkJrWiSx\nYK8CU40shAZfePJnxf89Dl/+KEero1mrqaiAlCsExNSZmMPFUS6M4lGT1jgU/hA9\nnKc17GMETCkuufdD2lkUUIwodi1jyWkFbB2/MnAUPWXJgD9WC333eawpsRxo84Bw\nkVAvb44OGJKkRvhAJdA9aSvhdRNxUOsupyFkYymIWxPROU7HXCaKufXfzV8aeecD\nhhyDsqRFlFSBTbFa4XRdFqQttO+RIYkU/PQydTCCASMGBWeBBQgDBIIBGAABAAsA\nBQByAAAAEAAUAAsIAAABAAEBALa/hbMk1crMXYkXDsqIktLrIBjwaBGToXobqAEo\nKvmyPm1ytlC3oV+gA0RwrULeI5cd9QQjNX/JuB191aYQU9YfnKiiUWyM1JDIu3tY\nq49xXiBRjCaJKqLpu8vXY/wZgEe7fCBkJJ0Xd5qH+JIVCa0dsP5oAbRnz+HyoCKY\n4YL1AlOmp7zvjh1J0FY9MrLn2Z2d1jAMDzGOtKA0bAoCSDMdr+S5Ct9cxIam3XoV\nX/6gGLy9Lq9zsG7r9OMSJrPLYuq1pEXmePp+UAV23eUFNN/UHB01622Xr+OBF9Xh\nKBD9oywDRu6iPx5ZhSjAslr5gNtkxpfNy8ravHHLfWDOAH2hADGCAT8wggE7AgEB\nBBQj18HNzx80nOBCRyon/S9XWyL/NzALBglghkgBZQMEAgGgADALBgkqhkiG9w0B\nAQEEggEAltcO6iNgF+wmfrWrxYf2W/c7wkkGUU8HNVfoFLR5dWBQEI4Wkk0Q8sxa\neeGzvZOKH9itGKOOcHpEf5UvGSvwwxTO5zzDsMVjuEcpi/3gaUDju8+ScCjYP9q+\nX6zoWhVwjz5yh9OSIG5gHLA3SrkOrgB2w2VHpY30vR92JQ9qVei3pVoUwlj7/xbx\n+m2QLa4ueaueGtMdFwwKVBID/iUQN6L8ZHrTG2GvhoYjKWDgd6FDwE9xGI8HPvC8\nGpybuHjpTFvS3YnnhwLIHd5heTVencXbRNcHS9TUnxH1S4XNrz8gQ4mS4bq2+hwM\ntklhcaTcxRHwrzM15ejNJ6WpynGzPqEAMA0GCSqGSIb3DQEBBQUAA4IBAQA9nJS8\n3Gw9CvQFE9wVAh2h5rnW87AGVKEPlfylpiwWLcYjYUPhHEKNQj1+qbPZ1kmsKYWD\nTBGSI0qONxIe0H7G/ovZMyvtOT+XBwCsIXrhkSjeVRq/QpyHk3xfPS5nnOTHRuRa\nDCs8qFLvDd6w5R4tL0OvRN0tAEoBUi/k6tJUntIF6JCmb/fhpd5I5MR6oDjoIChw\nbXFKmIo2hyIPhmYkDFueZyAMFKbT3B9oa1rTcnYQE5LnS89LBlgyF3opxtEOK29A\npoZiJ7O/s/nJIBo+BcQ+9KRpDLVMn4dqomQhOxUIGIX5cClt6JdB9/squaAfP6lm\nkG+SiHaSKQ4l6fJ7\n-----END CERTIFICATE REQUEST-----";

    private const string ValidCsr = "-----BEGIN CERTIFICATE REQUEST-----\nMIIIfDCCB2QCAQAwgZ8xETAPBgNVBAMMCDE4NDk3MzIwMQ4wDAYDVQQLDAVVc2Vy\nczESMBAGA1UECwwJTGludXhVc2VyMSUwIwYJKoZIhvcNAQkBFhZlZWFuaXNpbW92\nQHNiZXJiYW5rLnJ1MRUwEwYKCZImiZPyLGQBGRYFc2lnbWExFDASBgoJkiaJk/Is\nZAEZFgRzYnJmMRIwEAYKCZImiZPyLGQBGRYCcnUwggEiMA0GCSqGSIb3DQEBAQUA\nA4IBDwAwggEKAoIBAQDrD0fIVlOM2S+LlD4qY8FFvuKldRXPygyPobegK/KG/0gI\nq+12oi0NpCeZ8YU+akr2/wpNdB3XchmRGSgnPzIhO1q/ZtP2lQ8IOj72PAUqwZa0\n8LepjWfbCQ1mop83hoIA/zphhx3A8RM64YSJz90nHUgC/QiP7aME9IRKnwvT/2Lf\nnxPkzYpBAugQ7vvVUN3DFQ/T2PuwjFQ5lw3i777jOlIVk/DjwOJw+U8ognXN+uUX\n0U9zXoKOkQH+8CuJKBPNEq1YNpc4gcOiveXrMC2R6lg82dpXupBqXbaWY+W5euw7\nzFS36hPERhqyhsrGqvwMOvORBrhQTx8nvS4P1wp3AgMBAAGgggWVMBwGCisGAQQB\ngjcNAgMxDhYMMTAuMC4xOTA0NS4yMD4GCSqGSIb3DQEJDjExMC8wHQYDVR0OBBYE\nFPERvYHKKuYEJYwDUixjJfwaM/uLMA4GA1UdDwEB/wQEAwIFIDBcBgkrBgEEAYI3\nFRQxTzBNAgEJDA9DQUItV1NOLTAwMjcyODMMHFNJR01BXDE4NDk3MzIwQHNpZ21h\nLnNicmYucnUMGWF0dGVzdGF0aW9uX2dlbmVyYXRvci5leGUwZwYKKwYBBAGCNw0C\nAjFZMFcCAQEeUgBNAGkAYwByAG8AcwBvAGYAdAAgAEIAYQBzAGUAIABTAG0AYQBy\nAHQAIABDAGEAcgBkACAAQwByAHkAcAB0AG8AIABQAHIAbwB2AGkAZABlAHIwggRs\nBgkrBgEEAYI3FRgxggRdMIIEWQYJKoZIhvcNAQcCMIIESgIBATELBglghkgBZQME\nAgEwgZ4GCSqGSIb3DQEHAaCBkASBjf9UQ0eAFwAiAAu22EEjKHOTq7VtbeYBEssw\n9vuZ0kSsylgEE6Qs6ToBjwAAAAAACXjEofUAAAL3AAAAAAEABwACAAEAAAAiAAu8\n58xzI8l8byhON8egjb3lnCSufb/E8zcEJ820JzeqXwAiAAvz72UX69hGnjhkQ16E\nwKVvqsZMw/xL3j2olMCPNYQBs6CCAkwwggEhBgVngQUIDASCARYAAQALAAYAcgAA\nABAAEAgAAAEAAQEA6w9HyFZTjNkvi5Q+KmPBRb7ipXUVz8oMj6G3oCvyhv9ICKvt\ndqItDaQnmfGFPmpK9v8KTXQd13IZkRkoJz8yITtav2bT9pUPCDo+9jwFKsGWtPC3\nqY1n2wkNZqKfN4aCAP86YYcdwPETOuGEic/dJx1IAv0Ij+2jBPSESp8L0/9i358T\n5M2KQQLoEO771VDdwxUP09j7sIxUOZcN4u++4zpSFZPw48DicPlPKIJ1zfrlF9FP\nc16CjpEB/vAriSgTzRKtWDaXOIHDor3l6zAtkepYPNnaV7qQal22lmPluXrsO8xU\nt+oTxEYasobKxqr8DDrzkQa4UE8fJ70uD9cKdzCCASMGBWeBBQgDBIIBGAABAAsA\nBQByAAAAEAAUAAsIAAABAAEBAMC2dmoacgIc70yvxCqeoBsc4SP7MBxoUnpkh+kW\nlljcQ8v5V0YRUdX7QTZym/02WlsXVL898PKizDggCNEuK3NdVBYSzZmSCULzmeTh\nAvrfNW1sRu0+ceObo/qxLxaMUiEnNVoCBTSZADnV5wlIreNBXs6QAAapX+ZCYpDU\n+mR9ujClTAnKGKcaY5olHn0Mng2JDZNq0LCEIWARAFKfzzLPtg/5em7AlKobGdQl\n6fu/svYAYt0T9XzOZmvYXtblEB+2BdxbVWr/JFIO0bihRlJjSusQt9BaBZcOQU2M\nVziG657ZvjkTkIsCLOAYQ1HUaJ/oWF/O2+ZWHGTvz0jxqzmhADGCAUMwggE/AgEB\nBBRsbstCvoorWfG/DMAYNxjUmC530jALBglghkgBZQMEAgGgADALBgkqhkiG9w0B\nAQEEggEEAAsBAJexO1MvZMiUOhSVIqgKMyeMGmRm7HMXLiT/x44KQyVVYNLUDXHm\nO0n4bSi5guiWb/L/BzTs5prryI3tuGg/lShwq6Dnr5KXn5BZBy/FnP7/09GGF8Bs\nhsjjUVlHQWMzisPI5mYf8H2d7pkjx3lM8LV4ETPxGEJ9PT6ht8GhhVbTwYdAzH99\nwrPR6toM0fXM1oyinC40MXk1SfQSSzsbtOMBP2hquy1RXVGBl2Twb4NgK5RZAyVP\nFXiAihFCa2whp7DVFXueBPhHUzZzmSHh4TTi72qEB6mr5u48QbWCLoZWEh/Z9dOq\n/ldr1TpLdkSV/0HqV/CQqjSppUC4kOY3GO+hADANBgkqhkiG9w0BAQUFAAOCAQEA\nq/u8LTJfokNeXWxIVuIPr+TGk6MmWD7LnvmRHt0kysayMxRvHln6jw6EURqnkHXh\nrgyHGLgJG2YEupL20PRO4lTxuwn6Gb/zJRSQ8TEc1LSg0MKYe84Fp89VGWYydJn4\nxur4qZJsyf3pJSIkMq4cYWe/uLxz2zgsRcA+ZKCwcXGKNTUGA60Jj0e8PFk//pxg\nDP4HP0k4CgBo8nOUpdBW55bEmhqKhrgKq8QYrsiSL9PSbc7P1cN9Tmk2UCjG+qk0\nrYQtITUNzndDQO7ArNJpTodwvNiCdgtw7SlcuC+oKDKNLNh9Fd3tHJ8BVABpierW\n6tsK0zwGOyNBheZsEVIUVQ==\n-----END CERTIFICATE REQUEST-----";

    private const string IncorrectCsr = "-----BEGIN CERTIFICATE REQUEST-----\nlkfdljvlnwlfnvlwnvflnkkwfKLLKNKNNLKLKKNLNlndfklgnNKNKNLKLNbGDHDHG=\n-----END CERTIFICATE REQUEST-----";
    
    private const string EkPubCorrect =
        "AAEACwADALIAIINxl2dEhLP4GpDMjUal1yT9UtduBlILZPKh2hszFGmqAAYAgABDABAIAAAAAAAB\nAK47ninXU/If3wBLp1n7mWIiEJimgcKNezNvV1TcbACprCXHK7ebHAdjZprnoPmm9H1i1hCyZBOa\nXSyyb5aA7ImvgXgOHSpCNNpW18vzHbdDEPL3QMN9HVsauWFIJ0lRSU4WPjqbNavsMYiIGbO01CGp\nQBpLYn0LL0pALugx+VnivOR13HurIZn7E6G6RRc6JPjp8rmDWD+FQtPgrVpqHovbSvibMyNsMoST\nXvRNshvgNCDIF46kMPIeR2AYguvk9pJugAz27+XI+4VMssLRgcvvFUWV8CxFBMj6mGtelER0Kwr5\nfIAFCp1LbHUkb8iWnP8eh0TQyCaYKoDLFCPmgGM=";

    private const string EkPubIncorrect = "Zmxka2ZtY2xudmt3amVubGtuY2x3a2VuZGxjbmx3ZW5jbG53ZWxqa2Nud2VkbGtqbHdlZGNuZGtqbG53ZWRkY2prbmprZWRjamtlY2RlY2Rqa2V3ZGprZWRjamtlZGNqa25uandlYw==";
    
    [Fact]
    public void ShouldGenerateAttestationData_IfCsrIsCorrect()
    {
        // Arrange
        var keyAttestationService = _keyAttestationServiceServerFixture.KeyAttestationService;
        
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
        var keyAttestationService = _keyAttestationServiceServerFixture.KeyAttestationService;
        var ekPubCorrect = Convert.FromBase64String(EkPubCorrect);
        var ekPubIncorrect = Convert.FromBase64String(EkPubIncorrect);
        
        // Act
        var attestationData = keyAttestationService.GetAttestationData(ValidCsr);
        var credentialValid = keyAttestationService.MakeCredential(attestationData!, ekPubCorrect);
        var credentialInvalid = keyAttestationService.MakeCredential(attestationData!, ekPubIncorrect);

        // Assert
        Assert.NotNull(credentialValid);
        Assert.Null(credentialInvalid);
    }
    
    [Fact]
    public void ShouldVerifyAttestData_IfCsrIsCorrect()
    {
        // Arrange
        var keyAttestationService = _keyAttestationServiceServerFixture.KeyAttestationService;
        
        // Act
        var attestationDataWithInValidCsr = keyAttestationService.GetAttestationData(ForgedCsr);
        var attestationDataWithValidCsr = keyAttestationService.GetAttestationData(ValidCsr);
        var attestResultInvalid = keyAttestationService.Attest(attestationDataWithInValidCsr!);
        var attestResultValid = keyAttestationService.Attest(attestationDataWithValidCsr!);

        // Assert
        Assert.False(attestResultInvalid!.Result);
        Assert.True(attestResultValid!.Result);
    }
}