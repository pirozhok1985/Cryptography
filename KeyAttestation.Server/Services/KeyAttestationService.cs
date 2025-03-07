using KeyAttestation.Server.Entities;
using KeyAttestation.Server.Utils;

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

    public Task<TpmCredentials> MakeCredentials(AttestationData data, CancellationToken cancellationToken = default)
    {
        throw new NotImplementedException();
    }
}