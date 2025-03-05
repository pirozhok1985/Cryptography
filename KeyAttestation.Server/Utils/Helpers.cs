using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace KeyAttestation.Server.Utils;

public static class Helpers
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
}