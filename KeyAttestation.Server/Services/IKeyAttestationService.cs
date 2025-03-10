using KeyAttestation.Server.Entities;

namespace KeyAttestation.Server.Services;

public interface IKeyAttestationService
{
    public Task<AttestationData> GetAttestationDataAsync(string csr, CancellationToken cancellationToken = default);

    public Task<byte[]> MakeCredentialsAsync(AttestationData data, byte[] ekPub, CancellationToken cancellationToken = default);
}