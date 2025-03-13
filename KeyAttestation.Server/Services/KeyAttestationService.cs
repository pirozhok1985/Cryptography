using KeyAttestation.Server.Entities;
using KeyAttestation.Server.Extensions;
using KeyAttestation.Server.Utils;
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

        _logger.LogInformation("Attestation data has been successfully retrieved! Result: {@AttestData}!", attestationData);

        return attestationData;
    }

    public Credential? MakeCredential(AttestationData data, byte[] ekPub)
    {
        TpmPublic? ekTpmPub;
        try
        {
            ekTpmPub = Marshaller.FromTpmRepresentation<TpmPublic>(ekPub);
        }
        catch (Exception e)
        {
            _logger.LogError("Failed to create TpmPublic! Details: {Message}", e.Message);
            return null;
        }
        
        // Something that RA should take into account in order to compare with agent`s make_credential response
        var secret = Environment.MachineName.Select(Convert.ToByte).ToArray();
        
        try
        {
            var idObject = ekTpmPub.CreateActivationCredentials(secret, data.AikTpmPublic!.GetName(), out var encSecret);
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

        return true;
    }

    private static AttestationData? GetAttestationRequest(Pkcs10CertificationRequest request, ILogger logger)
    {
        var attestationStatement = request.GetSignedData(logger);
        if (attestationStatement is null)
        {
            return null;
        }

        logger.LogInformation("Successfully retrieved Signed data from Pkcs10CertificationRequest: SignedData: {@Data}", attestationStatement);
        var attest = attestationStatement.GetAttestData(logger);
        if (attest is null)
        {
            return null;
        }

        logger.LogInformation("Successfully retrieved Attestation data from Signed data: AttestData: {@Attest}", attest);
        var signature = attestationStatement.GetAttestSignature(logger);
        if (signature.Length == 0)
        {
            return null;
        }

        logger.LogInformation("Successfully retrieved signature from Signed data: Signature: {Sig}", signature);
        var keys = attestationStatement.GetSignedDataKeys(logger);
        if (keys is null)
        {
            return null;
        }

        logger.LogInformation("Successfully retrieved aik and client keys from Signed data: Aik:{@Aik}, ClientKey:{@Client}", keys.Value.Aik, keys.Value.Client);
        return new AttestationData(attest, signature, keys.Value.Aik, keys.Value.Client);
    }
}