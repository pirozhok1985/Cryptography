using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Pkcs;
using Tpm2Lib;

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
    
    public static Attest? GetAttestData(this SignedData signedData, ILogger logger)
    {
        try
        {
            var content = signedData.EncapContentInfo.Content as DerOctetString;
            var attestBytes = content!.GetOctets();
            return Marshaller.FromTpmRepresentation<Attest>(attestBytes);
        }
        catch (Exception e)
        {
            logger.LogError("Failed to retrieve attest information from SignedData! Details: {Message}", e.Message);
            return null;
        }
    }

    public static byte[] GetAttestSignature(this SignedData signedData, ILogger logger)
    {
        try
        {
            var signerInfosDerSet = signedData.SignerInfos as DerSet;
            var signerInfos = SignerInfo.GetInstance(signerInfosDerSet![0]);
            return signerInfos!.EncryptedDigest.GetOctets();
        }
        catch (Exception e)
        {
            logger.LogError("Failed to retrieve signature from signed data! Details: {Message}", e.Message);
            return [];
        }
    }

    public static (TpmPublic Aik, TpmPublic Client)? GetSignedDataKeys(this SignedData signedData, ILogger logger)
    {
        TpmPublic? aikTpmPublicKey = null;
        TpmPublic? clientTpmPublicKey = null;
        var certsSet = signedData.Certificates as DerSet;
        if (certsSet is null || certsSet.Count == 0)
        {
            logger.LogError("No certificate signed data found!");
        }

        foreach (var sequence in certsSet!)
        {
            if (((DerSequence)sequence)[0] is DerObjectIdentifier id)
            {
                switch (id.Id)
                {
                    case "2.23.133.8.3":
                        aikTpmPublicKey = Marshaller.FromTpmRepresentation<TpmPublic>((((DerSequence)sequence)[1] as DerOctetString)!.GetOctets());
                        break;
                    case "2.23.133.8.12":
                        clientTpmPublicKey =
                            Marshaller.FromTpmRepresentation<TpmPublic>((((DerSequence)sequence)[1] as DerOctetString)!.GetOctets());
                        break;
                }
            }
        }
        
        return aikTpmPublicKey is null || clientTpmPublicKey is null ? null : (aikTpmPublicKey, clientTpmPublicKey);
    }
}