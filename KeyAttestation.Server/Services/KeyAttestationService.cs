using System.Numerics;
using KeyAttestation.Server.Abstractions;
using KeyAttestation.Server.Entities;
using KeyAttestation.Server.Extensions;
using KeyAttestation.Server.Utils;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Tpm2Lib;

namespace KeyAttestation.Server.Services;

public class KeyAttestationService : IKeyAttestationService
{
    private readonly ILogger<KeyAttestationService> _logger;

    public KeyAttestationService(ILogger<KeyAttestationService> logger)
    {
        _logger = logger;
    }
    public AttestationData? GetAttestationData(string csr)
    {
        _logger.LogInformation("Constructing Pkcs10CertificationRequest from csr: {@Csr}", csr);
        var certificationRequest = Helper.FromPemCsr(csr, _logger);
        if (certificationRequest is null)
        {
            return null;
        }
        _logger.LogInformation("CertificationRequest has been successfully constructed! Result: {@Request}", certificationRequest);

        _logger.LogInformation("Retrieving attestation data!");
        var attestationData = GetAttestationRequest(certificationRequest, _logger);
        if (attestationData is null)
        {
            _logger.LogError("Attestation data retrieval failed!");
            return null;
        }

        return attestationData;
    }

    public Credential? MakeCredential(AttestationData attestationData)
    {   
        var aik = attestationData.AikTpmPublic;
        var ek = attestationData.EkTpmPublic;
        // Something that RA should take into account in order to compare with agent`s make_credential response
        var secret = Environment.MachineName.Select(Convert.ToByte).ToArray();
        
        try
        {
            var idObject = ek.CreateActivationCredentials(secret, aik.GetName(), out var encSecret);
            _logger.LogInformation("Encrypted credential has successfully been created! Cred: {@Cred}.", idObject);
            return new Credential(
                idObject.encIdentity,
                encSecret,
                secret,
                idObject.integrityHMAC);
        }
        catch (Exception e)
        {
            _logger.LogError("Failed to create credential! Details: {Message}", e.Message);
            return null;
        }
    }

    public AttestationResult Attest(AttestationData data)
    {
        if (data is null)
        {
            _logger.LogError("No attestation data provided!");
            return new AttestationResult
            {
                Result = false,
                Message = "Attestation failed! No attestation data provided!",
            };
        }
        
        if (!VerifyCertify(data, _logger))
        {
            _logger.LogError("Attestation failed!");
            return new AttestationResult
            {
                Result = false,
                Message = "Attestation failed!",
            };
        }

        return new AttestationResult
        {
            Result = true,
            Message = "Attestation has been successfully passed!"
        };
    }

    public bool CheckActivatedCredentials(byte[] clientCredentials, byte[] serverCredentials)
    {
        try
        {
            return Globs.ArraysAreEqual(clientCredentials, serverCredentials);
        }
        catch (Exception e)
        {
            _logger.LogError("Equality check error! Details: {Message}", e.Message);
            return false;
        }
    }
    
    private static bool VerifyCertify(AttestationData data, ILogger logger)
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
        if (!data.AikTpmPublic.VerifySignatureOverHash(sigHash, Marshaller.FromTpmRepresentation<SignatureRsassa>(data.Signature)))
        {
            logger.LogError("VerifyCertify failed! Signature is incorrect!");
            return false;
        }
        
        var clientKeyFromCsr = data.Csr.GetPublicKey();
        var clientKeyFromAttest = data.ClientTpmPublic.ToAsymmetricKeyParameter();
        if (!clientKeyFromCsr.Equals(clientKeyFromAttest))
        {
            logger.LogError("VerifyCertify failed! Client key from CSR does not match with attested key!");
            return false;
        }

        return true;
    }

    private static AttestationData? GetAttestationRequest(Pkcs10CertificationRequest request, ILogger logger)
    {
        var attestationStatement = request.GetAttestationStatement(logger);
        if (attestationStatement is null)
        {
            return null;
        }
        logger.LogInformation("Successfully retrieved attestation statement from Pkcs10CertificationRequest!");

        var signedData = attestationStatement.GetSignedData(logger);
        if (signedData is null)
        {
            return null;
        }
        logger.LogInformation("Successfully retrieved signed data from Pkcs10CertificationRequest! Signed Data: {@Data}", signedData);

        var attest = signedData.GetAttestData(logger);
        if (attest is null)
        {
            return null;
        }
        logger.LogInformation("Successfully retrieved Attestation data from Signed data: AttestData: {@Attest}", attest);

        var signature = signedData.GetAttestSignature(logger);
        if (signature.Length == 0)
        {
            return null;
        }
        logger.LogInformation("Successfully retrieved signature from Signed data: Signature: {Sig}", signature);

        var ekCert = signedData.GetEkCertificate(logger);
        if (ekCert is null)
        {
            return null;
        }
        logger.LogInformation("Successfully retrieved ek certificate from Signed data: EKCert:{@EKCertificate}", ekCert);

        var keys = attestationStatement.GetTpmPublicKeys(logger);
        if (keys is null)
        {
            return null;
        }
        logger.LogInformation("Successfully retrieved aik and client keys from Signed data: Ek:{@Ek} Aik:{@Aik}, ClientKey:{@Client}", keys.Value.ek, keys.Value.aik, keys.Value.client);

        return new AttestationData(attest, signature, keys.Value.ek, keys.Value.aik, keys.Value.client, ekCert, request);
    }
}