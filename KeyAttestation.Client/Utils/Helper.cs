using System.Numerics;
using KeyAttestation.Client.Abstractions;
using KeyAttestation.Client.Entities;
using Microsoft.Extensions.Logging;
using Tpm2Lib;

namespace KeyAttestation.Client.Utils;

public static class Helper
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
  
    public static ITpm2Facade CreateTpm2Facade(string deviceName, ILogger logger)
        => deviceName switch
        {
            "simulator" => new Tpm2Facade<TcpTpmDevice>(logger, new Tpm2DeviceCreationProperties()
            {
                ServerName = "localhost",
                ServerPort = 2322
            }),

            "linux" => new Tpm2Facade<LinuxTpmDevice>(logger, new Tpm2DeviceCreationProperties()
            {
                DeviceName = "/dev/tpmrm0"
            }),

            "windows" => new Tpm2Facade<TbsDevice>(logger, new Tpm2DeviceCreationProperties()),
            _ => throw new ArgumentOutOfRangeException(nameof(deviceName), deviceName, "Unrecognized device type")
        };
}