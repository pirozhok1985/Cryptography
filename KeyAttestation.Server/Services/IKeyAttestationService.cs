using KeyAttestation.Server.Entities;

namespace KeyAttestation.Server.Services;

public interface IKeyAttestationService
{
    public Task<AttestationData> GetAttestationDataAsync(string csr, CancellationToken cancellationToken = default);

    public Task<TpmCredentials> MakeCredentials(AttestationData data, CancellationToken cancellationToken = default);
}