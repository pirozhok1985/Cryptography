using System.Diagnostics;
using System.Numerics;
using KeyAttestation.Client.Utils;
using Tpm2Lib;

namespace KeyAttestation.Client.Entities;

public class RawRsaCustom
{
    public BigInteger E { get; set; }
    public BigInteger N { get; set; }
    public BigInteger P { get; set; }
    public BigInteger Q { get; set; }
    public BigInteger D { get; set; }

    public void Init(TpmPublic tpmPublic, TpmPrivate tpmPrivate)
    {

        var rsaPrime = GetTpmPrivateRsaPrime(tpmPublic.nameAlg, tpmPrivate.buffer);
        var parameters = tpmPublic.parameters as RsaParms;
        E = new BigInteger(parameters?.exponent == 0U ? RsaParms.DefaultExponent : BitConverter.GetBytes(parameters!.exponent));
        N = RawRsa.FromBigEndian((tpmPublic.unique as Tpm2bPublicKeyRsa)!.buffer);
        P = RawRsa.FromBigEndian(rsaPrime.buffer);
        Q = N / P;
        D = Helper.ModInverse(E, N - (P + Q - BigInteger.One));
    }

    private Tpm2bPrivateKeyRsa GetTpmPrivateRsaPrime(TpmAlgId algId, byte[] buffer)
    {
        var integrityInnerOuterSize = CryptoLib.DigestSize(algId) * 8 * 2;
        return buffer.Length switch
        {
            222 => new Tpm2bPrivateKeyRsa(buffer),
            734 => new Tpm2bPrivateKeyRsa(buffer[integrityInnerOuterSize..]),
            _ => throw new ApplicationException($"Unsupported TpmPrivate buffer size! Size: {buffer.Length}")
        };
    }
}