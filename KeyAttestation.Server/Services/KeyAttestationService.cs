using Attestation.Shared;
using Attestation.Shared.Entities;
using Tpm2Lib;

namespace KeyAttestation.Server.Services;

public class KeyAttestationService : IKeyAttestationService
{
    private readonly ILogger<KeyAttestationService> _logger;

    public KeyAttestationService(ILogger<KeyAttestationService> logger)
    {
        _logger = logger;
    }
    public AttestationData GetAttestationDataAsync(string csr)
    {
        _logger.LogInformation("Constructing Pkcs10CertificationRequest from csr: {@Csr}", csr);
        var certificationRequest = Helpers.FromPemCsr(csr, _logger);
        if (certificationRequest is null)
        {
            return AttestationData.Empty;
        }
        _logger.LogInformation("CertificationRequest has been successfully constructed! Result: {@Pkcs10}", certificationRequest);

        _logger.LogInformation("Retrieving attestation data!");
        var attestationData = Helpers.GetAttestationRequest(certificationRequest, _logger);
        _logger.LogInformation("Attestation data has been successfully retrieved! Result: {@AttestationData}!", attestationData);

        return attestationData;
    }

    public Credential MakeCredentialsAsync(AttestationData data, byte[] ekPub)
    {
        var ekTpmPub = Marshaller.FromTpmRepresentation<TpmPublic>(ekPub);
        
        // Something that RA should take into account in order to compare with agent`s make_credential response
        var secret = Environment.MachineName.Select(Convert.ToByte).ToArray();
        
        var idObject = ekTpmPub.CreateActivationCredentials(secret, data.AikTpmPublic!.GetName(), out var encSecret);
        _logger.LogInformation("Encrypted credential has successfully been created! Cred: {@Cred}.", idObject);
        return new Credential(
            idObject.encIdentity,
            encSecret,
            secret,
            idObject.integrityHMAC);
    }

    public AttestationResult AttestAsync(AttestationData data)
    {
        if (!Helpers.VerifyCertify(data, _logger))
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
       return Globs.ArraysAreEqual(clientCredentials, serverCredentials);
    }
}