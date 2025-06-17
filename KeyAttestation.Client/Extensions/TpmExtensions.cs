using KeyAttestation.Client.Entities;
using Org.BouncyCastle.Crypto.Parameters;

namespace KeyAttestation.Client.Extensions;

public static class TpmExtensions
{
    public static RsaKeyParameters ToRsaKeyParameter(this Tpm2Key key)
    {
        var rawRsa = new RawRsaCustom(key.Public!);
        return new RsaKeyParameters(false, rawRsa.N.ToBigIntegerBc(), rawRsa.E.ToBigIntegerBc());
    }
}