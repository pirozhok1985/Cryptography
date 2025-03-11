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
        var certificationRequest = Helpers.FromPemCsr(csr, _logger);
        if (certificationRequest is null)
        {
            return AttestationData.Empty;
        }

        var attestationRequest = Helpers.GetAttestationRequest(certificationRequest, _logger);

        return attestationRequest;
    }

    public Credendtial MakeCredentialsAsync(AttestationData data, byte[] ekPub)
    {
        var ekTpmPub = Marshaller.FromTpmRepresentation<TpmPublic>(ekPub);
        
        // Something that RA should take account with in order to compare with agent make credential response
        var secret = Environment.MachineName.Select(Convert.ToByte).ToArray();
        
        var idObject = ekTpmPub.CreateActivationCredentials(secret, data.AikTpmPublic!.GetName(), out var encSecret);
        _logger.LogInformation("Encrypted credential has successfully been created! Cred: {Cred}.", typeof(IdObject));
        return new Credendtial(
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