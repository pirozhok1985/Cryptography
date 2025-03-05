using System.Numerics;
using System.Text;

namespace KeyAttestation;

public static class Helpers
{
    public static string ToHexString(uint value)
    {
        var hexStringStack = new Stack<string>(9);
        while (value % 16 != 0)
        {
            hexStringStack.Push($"{value % 16:x}");
            value /= 16;
        }
        hexStringStack.Push($"{value % 16:x}");
        hexStringStack.Push($"{value / 16:x}");
        hexStringStack.Push("0x");
        var resultString = String.Empty;
        while (hexStringStack.Count > 0)
        {
            resultString += hexStringStack.Pop();
        }

        return resultString;
    }
    
  public static BigInteger ModInverse(BigInteger a, BigInteger b)
    {
        var bigInteger1 = a % b;
        var bigInteger2 = b;
        var bigInteger3 = BigInteger.One;
        var bigInteger4 = BigInteger.Zero;
        BigInteger bigInteger5;
        for (; bigInteger2.Sign > 0; bigInteger2 = bigInteger5)
        {
            var bigInteger6 = bigInteger1 / bigInteger2;
            bigInteger5 = bigInteger1 % bigInteger2;
            if (bigInteger5.Sign > 0)
            {
                var bigInteger7 = bigInteger3 - bigInteger4 * bigInteger6;
                bigInteger3 = bigInteger4;
                bigInteger4 = bigInteger7;
                bigInteger1 = bigInteger2;
            }
            else
                break;
        }
        if (bigInteger2 != BigInteger.One)
            throw new Exception("ModInverse(): Not coprime");
        return bigInteger4.Sign >= 0 ? bigInteger4 : bigInteger4 + b;
    }

    public static Org.BouncyCastle.Math.BigInteger ToBigIntegerBc(this BigInteger bigInteger)
        => new (bigInteger.ToString());
}