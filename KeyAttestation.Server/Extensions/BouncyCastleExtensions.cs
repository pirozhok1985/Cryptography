using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Tpm2Lib;
using ContentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo;
using SignedData = Org.BouncyCastle.Asn1.Cms.SignedData;

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
                if (attribute is DerSequence sequence)
                {
                    var contentInfo = ContentInfo.GetInstance((DerSequence)sequence[0]);
                    signedData = contentInfo.Content;
                    break;
                }

                return null;
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
            var keySequence = (DerSequence)(attestationStatement[0] as DerSequence)![1];
            if (keySequence.Count < 3)
            {
                logger.LogError("Three keys are expected in the attestation statement, but found {Count} keys!", keySequence.Count);
                return null;
            }

            var ekSubPubInfo = SubjectPublicKeyInfo.GetInstance(keySequence[0]);
            var aikSubPubInfo = SubjectPublicKeyInfo.GetInstance(keySequence[1]);
            var clientSubPubInfo = SubjectPublicKeyInfo.GetInstance(keySequence[2]);
            
            var ek = Marshaller.FromTpmRepresentation<TpmPublic>(ekSubPubInfo.PublicKey.GetOctets());
            var aik = Marshaller.FromTpmRepresentation<TpmPublic>(aikSubPubInfo.PublicKey.GetOctets());
            var client = Marshaller.FromTpmRepresentation<TpmPublic>(clientSubPubInfo.PublicKey.GetOctets());
            return (ek, aik, client);
        }
        catch (Exception e)
        {
            logger.LogError("Failed to retrieve keys from Pkcs10CertificationRequest! Details: {Message}", e.Message);
            return null;
        }
    }
}