using System.Numerics;

namespace KeyAttestation.Client.Extensions;

public static class NumericExtensions
{
    public static Org.BouncyCastle.Math.BigInteger ToBigIntegerBc(this BigInteger bigInteger)
        => new (bigInteger.ToString());
}