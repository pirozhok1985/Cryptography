using KeyAttestation.Client.Entities;
using KeyAttestation.Client.Utils;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace KeyAttestation.Client.Extensions;

public static class TpmExtensions
{
    public static AsymmetricCipherKeyPair ToAsymmetricCipherKeyPair(this TpmKey key)
    {
        var rawRsa = new RawRsaCustom();
        rawRsa.Init(key.Public!, key.Private!);
        return new AsymmetricCipherKeyPair(
            new RsaKeyParameters(true, rawRsa.N.ToBigIntegerBc(), rawRsa.D.ToBigIntegerBc()),
            new RsaKeyParameters(false, rawRsa.N.ToBigIntegerBc(), rawRsa.E.ToBigIntegerBc()));
    }
}