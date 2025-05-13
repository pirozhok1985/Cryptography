using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Pkcs;

namespace KeyAttestation.Server.Extensions;

public static class BouncyCastleExtensions
{
    public static SignedData? GetSignedData(this Pkcs10CertificationRequest request, ILogger logger)
    {
        var info = request.GetCertificationRequestInfo();
        var attributes = (DerSet)info.Attributes;
        try
        {
            var attestationStatementSequence = (DerSequence)attributes.First(attribute => attribute is DerSequence sequence
                && ((DerObjectIdentifier)sequence[0]).Id == "1.3.6.1.4.1.311.21.24");
            var signedDataSequence = ((DerSequence)((DerSet)attestationStatementSequence.First(
                        x => x is DerSet))
                    .First(x => x is DerSequence))
                .First(x => x is DerSequence);
            return SignedData.GetInstance(signedDataSequence);
        }
        catch (Exception e)
        {
            logger.LogError("Failed to retrieve signed information from Pkcs10CertificationRequest! Details: {Message}", e.Message);
            return null;
        }
    }
}