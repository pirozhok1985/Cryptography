using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
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

    public static AsymmetricKeyParameter ToAsymmetricKeyParameter(this TpmPublic keyPublic)
    {
        var parameters = keyPublic.parameters as RsaParms;
        var e = new BigInteger(parameters?.exponent == 0U ? RsaParms.DefaultExponent : BitConverter.GetBytes(parameters!.exponent)).ToBigIntegerBc();
        var n = RawRsa.FromBigEndian((keyPublic.unique as Tpm2bPublicKeyRsa)!.buffer).ToBigIntegerBc();
        return new RsaKeyParameters(false, n, e);
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

    public static X509Certificate2? GetEkCertificate(this SignedData signedData, ILogger logger)
    {
        X509Certificate2? ekCert = null;
        var certsSet = signedData.Certificates as DerSet;
        if (certsSet is null || certsSet.Count == 0)
        {
            logger.LogError("No certificate signed data found!");
        }

        foreach (var sequence in certsSet!)
        {
            if (((DerSequence)sequence)[0] is DerObjectIdentifier oid)
            {
                if (oid.Id == "2.23.133.8.1")
                {
                    try
                    {
                        var decodedCert = (((DerSequence)sequence)[1] as DerOctetString)!.GetOctets();
                        ekCert = new X509Certificate2(decodedCert);
                    }
                    catch (Exception e)
                    {
                        logger.LogError("Unable to create X509Certificate2 object using decoded certificate. Error: {Error}", e.Message);
                        return null;
                    }
                }
            }
        }

       if (ekCert is null)
       {
         logger.LogError("Unable to decode ek certificate!");
         return null;
       }
        
        return ekCert;
    }
}
