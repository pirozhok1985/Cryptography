using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Tpm2Lib;

namespace KeyAttestation.Server.Extensions;

public static class TpmExtensions
{
    public static RSA ToRsa(this TpmPublic keyPublic)
    {
        var rsaParams = new RSAParameters();
        rsaParams.Modulus = (keyPublic.unique as Tpm2bPublicKeyRsa)!.buffer;
        rsaParams.Exponent = BitConverter.GetBytes(65537);
        return RSA.Create(rsaParams);
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

    public static (TpmPublic Aik, TpmPublic Client, X509Certificate2 EkCertificate)? GetSignedDataKeys(this SignedData signedData, ILogger logger)
    {
        TpmPublic? aikTpmPublicKey = null;
        TpmPublic? clientTpmPublicKey = null;
        X509Certificate2? ekCert = null;
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
                    case "2.23.133.8.1":
                        var certInBytes = Marshaller.FromTpmRepresentation<byte[]>((((DerSequence)sequence)[1] as DerOctetString)!.GetOctets());
                        ekCert = new X509Certificate2(certInBytes);
                        break;
                }
            }
        }
        
        return aikTpmPublicKey is null 
            || clientTpmPublicKey is null 
            || ekCert is null 
            ? null 
            : (aikTpmPublicKey, clientTpmPublicKey, ekCert);
    }
}
