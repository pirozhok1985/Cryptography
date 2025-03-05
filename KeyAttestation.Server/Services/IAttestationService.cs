using KeyAttestation.Server.Entities;

namespace KeyAttestation.Server.Services;

public interface IAttestationService
{
    public Task<AttestationResult> AttestAsync(string csr, CancellationToken cancellationToken = default);
}