using System.Numerics;
using Tpm2Lib;

namespace KeyAttestation.Client.Entities;

public class RawRsaCustom
{
    public BigInteger E { get; set; }
    public BigInteger N { get; set; }

    public RawRsaCustom(TpmPublic tpmPublic)
    {
        Init(tpmPublic);
    }

    private void Init(TpmPublic tpmPublic)
    {
        var parameters = tpmPublic.parameters as RsaParms;
        E = new BigInteger(parameters?.exponent == 0U ? RsaParms.DefaultExponent : BitConverter.GetBytes(parameters!.exponent));
        N = RawRsa.FromBigEndian((tpmPublic.unique as Tpm2bPublicKeyRsa)!.buffer);
    }
}