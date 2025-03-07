using KeyAttestation.Server.Entities;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Tpm2Lib;

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

    public static AttestationData GetAttestationRequest(Pkcs10CertificationRequest request, ILogger logger)
    {
        var attestationStatement = GetSignedData(request);
        var attest = GetAttestData(attestationStatement);
        var signature = GetAttestSignature(attestationStatement);
        var keys = GetSignedDataKeys(attestationStatement);
        return new AttestationData(attest, signature, keys.Aik, keys.Client);
    }

    private static SignedData GetSignedData(Pkcs10CertificationRequest request)
    {
        var info = request.GetCertificationRequestInfo();
        var attributes = (DerSet)info.Attributes;
        var attestationStatementSequence = (DerSequence)attributes.First(attribute => attribute is DerSequence sequence
            && ((DerObjectIdentifier)sequence[0]).Id == "1.3.6.1.4.1.311.21.24");
        var signedDataSequence = ((DerSequence)((DerSet)attestationStatementSequence.First(
                    x => x is DerSet))
                .First(x => x is DerSequence))
            .First(x => x is DerSequence);
        return SignedData.GetInstance(signedDataSequence);
    }

    private static Attest GetAttestData(SignedData signedData)
    {
        var content = signedData.EncapContentInfo.Content as DerOctetString;
        var attestBytes = content!.GetOctets();
        return Marshaller.FromTpmRepresentation<Attest>(attestBytes);
    }

    private static byte[] GetAttestSignature(SignedData signedData)
    {
        var signerInfosDerSet = signedData.SignerInfos as DerSet;
        var signerInfos = SignerInfo.GetInstance(signerInfosDerSet![0]);
        return signerInfos!.EncryptedDigest.GetOctets();
    }

    private static (byte[] Aik, TpmPublic Client) GetSignedDataKeys(SignedData signedData)
    {
        byte[]? aikRsaPublicKey = null;
        TpmPublic? clientTpmPublicKey = null;
        var certsSet = signedData.Certificates as DerSet;
        foreach (var sequence in certsSet!)
        {
            if (((DerSequence)sequence)[0] is DerObjectIdentifier id)
            {
                switch (id.Id)
                {
                    case "2.23.133.8.3":
                        aikRsaPublicKey = (((DerSequence)sequence)[1] as DerOctetString)!.GetOctets();
                        break;
                    case "2.23.133.8.12":
                        clientTpmPublicKey =
                            Marshaller.FromTpmRepresentation<TpmPublic>((((DerSequence)sequence)[1] as DerOctetString)!.GetOctets());
                        break;
                }
            }
        }
        
        return (aikRsaPublicKey, clientTpmPublicKey)!;
    }
}