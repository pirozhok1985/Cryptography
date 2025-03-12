using System.Numerics;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace KeyAttestation.Server.Utils;

public static class Helper
{
    public static Pkcs10CertificationRequest? FromPemCsr(string pemCsr, ILogger logger)
    {
        using var reader = new StringReader(pemCsr);
        using var pemReader = new PemReader(reader);
        try
        {
            return (Pkcs10CertificationRequest)pemReader.ReadObject();
        }
        catch (Exception e)
        {
            logger.LogError("Unable to parse PKCS#10 certificate request! Error: {Error}", e.Message);
            return null;
        }
    }
    
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
}