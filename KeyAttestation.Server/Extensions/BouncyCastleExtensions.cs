using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Pkcs;
using Tpm2Lib;

namespace KeyAttestation.Server.Extensions;

public static class BouncyCastleExtensions
{
    public static DerSet? GetAttestationStatement(this Pkcs10CertificationRequest request, ILogger logger)
    {
        var info = request.GetCertificationRequestInfo();
        var attributes = (DerSet)info.Attributes;
        DerSet? attestationStatement = null;
        try
        {
            attestationStatement = (DerSet)((DerSequence)attributes.First(attribute => attribute is DerSequence sequence
                && ((DerObjectIdentifier)sequence.First(attribute => attribute is DerObjectIdentifier)).Id == "1.3.6.1.4.1.311.21.24"))[1];
        }
        catch (Exception e)
        {
            logger.LogError("Attestation statement parse error! Error: {Error}", e.Message);
        }

        return attestationStatement;
    }
    public static SignedData? GetSignedData(this DerSet attestationStatement, ILogger logger)
    {
        Asn1Encodable? signedData = null;
        try
        {
            foreach (var attribute in attestationStatement)
            {
                if (attribute is DerSequence sequence && sequence[0] is DerObjectIdentifier oid && oid.Id == "1.2.840.113549.1.7.2")
                {
                    signedData = sequence[1];
                    break;
                }
            }

            return SignedData.GetInstance(signedData);
        }
        catch (Exception e)
        {
            logger.LogError("Failed to retrieve signed information from Pkcs10CertificationRequest! Details: {Message}", e.Message);
            return null;
        }
    }

    public static (TpmPublic ek, TpmPublic aik, TpmPublic client)? GetTpmPublicKeys(this DerSet attestationStatement, ILogger logger)
    {
        try
        {
            var keys = (DerSequence)attestationStatement.First(attribute => attribute is DerSequence sequence
                && sequence[0] is DerOctetString);
            var ek = Marshaller.FromTpmRepresentation<TpmPublic>(((DerOctetString)keys[0]).GetOctets());
            var aik = Marshaller.FromTpmRepresentation<TpmPublic>(((DerOctetString)keys[1]).GetOctets());
            var client = Marshaller.FromTpmRepresentation<TpmPublic>(((DerOctetString)keys[2]).GetOctets());
            return (ek, aik, client);
        }
        catch (Exception e)
        {
            logger.LogError("Failed to retrieve signed information from Pkcs10CertificationRequest! Details: {Message}", e.Message);
            return null;
        }
    }
}