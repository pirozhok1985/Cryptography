using KeyAttestation;

namespace Cryptography.Tests;

public class Helpers
{
    [Theory]
    [InlineData(2164260861, @"^0x\w{8}$")]
    public void MustReturnValidHexString(uint value, string pattern)
    {
        // Act
        var result = KeyAttestation.Helpers.ToHexString(value);
        
        // Assert
        Assert.NotEmpty(result);
        Assert.Matches(pattern, result);
    }
}