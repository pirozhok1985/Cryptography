using System.Numerics;

namespace KeyAttestation.Server.Extensions;

public static class NumericExtensions
{
    public static Org.BouncyCastle.Math.BigInteger ToBigIntegerBc(this BigInteger bigInteger)
        => new (bigInteger.ToByteArray().Reverse().ToArray());
}