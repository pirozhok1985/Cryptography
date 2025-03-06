using System.Formats.Asn1;
using KeyAttestation.Server.Entities;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;
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

    public static AttestationRequest GetAttestationRequest(Pkcs10CertificationRequest request, ILogger logger)
    {
        var info = request.GetCertificationRequestInfo();
        var attestationStatement = (SignedData)info.Attributes
            .First(x => x.GetType() == typeof(DerSequence) 
                        && ((DerSequence)x).Parser.ReadObject() is SignedData);
        
        var attest = GetAttestData(attestationStatement);
        var signature = GetAttestSignature(attestationStatement);
        var keys = GetSignedDataKeys(attestationStatement);
        return new AttestationRequest(attest, signature, keys.Aik, keys.Client);
    }

    private static Attest GetAttestData(SignedData signedData)
    {
        var content = signedData.EncapContentInfo.Content as BerSequence;
        var attestBerOctetString = content!.Parser.ReadObject() as BerOctetString;
        var attestBytes = attestBerOctetString!.GetOctets();
        var result = AsnDecoder.ReadOctetString(attestBytes.AsSpan(), AsnEncodingRules.BER, out _);
        return Marshaller.FromTpmRepresentation<Attest>(result);
    }

    private static byte[] GetAttestSignature(SignedData signedData)
    {
        var signerInfosBerSet = signedData.SignerInfos as BerSet;
        var signerInfos = signerInfosBerSet!.Parser.ReadObject() as SignerInfo;
        return signerInfos!.EncryptedDigest.GetOctets();
    }

    private static (byte[] Aik, TpmPublic Client) GetSignedDataKeys(SignedData signedData)
    {
        byte[]? aikRsaPublicKey = null;
        TpmPublic? clientTpmPublicKey = null;
        var certsBerSet = signedData.Certificates as BerSet;
        var certsSequence = certsBerSet!.Parser.ReadObject() as BerSequence;
        for (int i = 0; i < certsSequence!.Count; i++)
        {
            if (certsSequence[i] is DerObjectIdentifier objectIdentifier)
            {
                switch (objectIdentifier.Id)
                {
                    case "2.23.133.8.3":
                        aikRsaPublicKey = (certsSequence[i + 1] as BerOctetString)!.GetOctets();
                        break;
                    case "2.23.133.8.12":
                        clientTpmPublicKey = Marshaller.FromTpmRepresentation<TpmPublic>((certsSequence[i + 1] as BerOctetString)!.GetOctets());
                        break;
                }
            }
        }

        return (aikRsaPublicKey, clientTpmPublicKey)!;
    }
}