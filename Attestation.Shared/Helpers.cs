using System.IO.Abstractions;
using System.Numerics;
using Attestation.Shared.Entities;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Tls;
using Tpm2Lib;

namespace Attestation.Shared;

public static class Helpers
{
        public static string ToHexString(uint value)
    {
        var hexStringStack = new Stack<string>(9);
        while (value % 16 != 0)
        {
            hexStringStack.Push($"{value % 16:x}");
            value /= 16;
        }
        hexStringStack.Push($"{value % 16:x}");
        hexStringStack.Push($"{value / 16:x}");
        hexStringStack.Push("0x");
        var resultString = String.Empty;
        while (hexStringStack.Count > 0)
        {
            resultString += hexStringStack.Pop();
        }

        return resultString;
    }
    
  public static BigInteger ModInverse(BigInteger a, BigInteger b)
    {
        var bigInteger1 = a % b;
        var bigInteger2 = b;
        var bigInteger3 = BigInteger.One;
        var bigInteger4 = BigInteger.Zero;
        BigInteger bigInteger5;
        for (; bigInteger2.Sign > 0; bigInteger2 = bigInteger5)
        {
            var bigInteger6 = bigInteger1 / bigInteger2;
            bigInteger5 = bigInteger1 % bigInteger2;
            if (bigInteger5.Sign > 0)
            {
                var bigInteger7 = bigInteger3 - bigInteger4 * bigInteger6;
                bigInteger3 = bigInteger4;
                bigInteger4 = bigInteger7;
                bigInteger1 = bigInteger2;
            }
            else
                break;
        }
        if (bigInteger2 != BigInteger.One)
            throw new Exception("ModInverse(): Not coprime");
        return bigInteger4.Sign >= 0 ? bigInteger4 : bigInteger4 + b;
    }

    public static Org.BouncyCastle.Math.BigInteger ToBigIntegerBc(this BigInteger bigInteger)
        => new (bigInteger.ToString());

    public static async Task WriteCsrAsync(
        Pkcs10CertificationRequest request,
        string? fileName,
        IFile fileWriter,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        var requestPem =await ConvertPkcs10RequestToPem(request);
        await fileWriter.WriteAllTextAsync(fileName, requestPem, cancellationToken);
    }

    public static async Task<string> ConvertPkcs10RequestToPem(Pkcs10CertificationRequest request)
    {
        await using var textWriter = new StringWriter();
        using var pemWriter = new PemWriter(textWriter);
        pemWriter.WriteObject(request);
        return textWriter.ToString();
    }

    public static AsymmetricKeyParameter ToAsymmetricKeyParameter(TpmKey key, bool isPrivate)
    {
        var rawRsa = new RawRsaCustom();
        rawRsa.Init(key.Public!, key.Private!);
        return isPrivate
            ? new RsaKeyParameters(true, rawRsa.N.ToBigIntegerBc(), rawRsa.D.ToBigIntegerBc())
            : new RsaKeyParameters(false, rawRsa.N.ToBigIntegerBc(), rawRsa.E.ToBigIntegerBc());
    }
    
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

    private static (TpmPublic Aik, TpmPublic Client) GetSignedDataKeys(SignedData signedData)
    {
        TpmPublic aikTpmPublicKey = null;
        TpmPublic? clientTpmPublicKey = null;
        var certsSet = signedData.Certificates as DerSet;
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
        
        return (aikTpmPublicKey, clientTpmPublicKey)!;
    }

    public static bool VerifyCertify(AttestationData data, ILogger logger)
    {
        if (data.Attestation!.type != TpmSt.AttestCertify)
        {
            logger.LogError("VerifyCertify failed! Attestation is not TpmSt.AttestCertify!");
            return false;
        }

        if (!Globs.ArraysAreEqual(data.Attestation.extraData, Array.Empty<byte>()))
        {
            logger.LogError("VerifyCertify failed! ExtraData should be empty!");
            return false;
        }

        if (data.Attestation.magic != Generated.Value)
        {
            logger.LogError("VerifyCertify failed! Magic number is incorrect!");
            return false;
        }

        var certInfo = (CertifyInfo)data.Attestation.attested;
        if (!Globs.ArraysAreEqual(certInfo.name, data.ClientTpmPublic!.GetName()))
        {
            logger.LogError("VerifyCertify failed! ClientTpmPublic does not match with attested entity name!");
            return false;
        }

        var sigHash = TpmHash.FromData(TpmAlgId.Sha256, data.Attestation.GetTpmRepresentation());
        if (!data.AikTpmPublic!.VerifySignatureOverHash(sigHash, Marshaller.FromTpmRepresentation<SignatureRsassa>(data.Signature)))
        {
            logger.LogError("VerifyCertify failed! Signature is incorrect!");
            return false;
        }

        return true;
    }
}