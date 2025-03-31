using KeyAttestation.Server.Entities;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace KeyAttestation.Server.Extensions;

public static class TpmExtensions
{
    public static AsymmetricCipherKeyPair ToAsymmetricCipherKeyPair(this Tpm2Key key)
    {
        var rawRsa = new RawRsaCustom();
        rawRsa.Init(key.Public!, key.Private!);
        return new AsymmetricCipherKeyPair(
            new RsaKeyParameters(true, rawRsa.N.ToBigIntegerBc(), rawRsa.D.ToBigIntegerBc()),
            new RsaKeyParameters(false, rawRsa.N.ToBigIntegerBc(), rawRsa.E.ToBigIntegerBc()));
    }
}