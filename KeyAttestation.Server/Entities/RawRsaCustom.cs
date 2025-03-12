using System.Numerics;
using KeyAttestation.Server.Utils;
using Tpm2Lib;

namespace KeyAttestation.Server.Entities;

public class RawRsaCustom
{
    public BigInteger E { get; set; }
    public BigInteger N { get; set; }
    public BigInteger P { get; set; }
    public BigInteger Q { get; set; }
    public BigInteger D { get; set; }

    public void Init(TpmPublic tpmPublic, TpmPrivate tpmPrivate)
    {
        var clPriv = new Tpm2bPrivateKeyRsa(tpmPrivate.buffer);
        var parameters = tpmPublic.parameters as RsaParms;
        E = new BigInteger(parameters?.exponent == 0U ? RsaParms.DefaultExponent : BitConverter.GetBytes(parameters!.exponent));
        N = RawRsa.FromBigEndian((tpmPublic.unique as Tpm2bPublicKeyRsa)!.buffer);
        P = RawRsa.FromBigEndian(clPriv.buffer);
        Q = N / P;
        D = Helper.ModInverse(E, N - (P + Q - BigInteger.One));
    }
}