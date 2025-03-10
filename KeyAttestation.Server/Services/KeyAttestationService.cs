using KeyAttestation.Server.Entities;
using KeyAttestation.Server.Utils;
using Tpm2Lib;

namespace KeyAttestation.Server.Services;

public class KeyAttestationService : IKeyAttestationService
{
    private readonly ILogger<KeyAttestationService> _logger;

    public KeyAttestationService(ILogger<KeyAttestationService> logger)
    {
        _logger = logger;
    }
    public Task<AttestationData> GetAttestationDataAsync(string csr, CancellationToken cancellationToken = default)
    {
        var certificationRequest = Helpers.FromPemCsr(csr, _logger);
        if (certificationRequest is null)
        {
            return Task.FromResult(AttestationData.Empty);
        }

        var attestationRequest = Helpers.GetAttestationRequest(certificationRequest, _logger);

        return Task.FromResult(attestationRequest);
    }

    public Task<byte[]> MakeCredentialsAsync(AttestationData data, byte[] ekPub, CancellationToken cancellationToken = default)
    {
        var ekTpmPub = Marshaller.FromTpmRepresentation<TpmPublic>(ekPub);
        var secret = Environment.MachineName.Select(Convert.ToByte).ToArray();
        var idObject = ekTpmPub.CreateActivationCredentials(secret, data.AikTpmPublic!.GetName(), out _);
        return Task.FromResult(Marshaller.GetTpmRepresentation(idObject));
    }
}