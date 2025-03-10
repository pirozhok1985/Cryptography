using Attestation.Shared.Entities;

namespace KeyAttestation.Server.Services;

public interface IKeyAttestationService
{
    public AttestationData GetAttestationDataAsync(string csr);

    public byte[] MakeCredentialsAsync(AttestationData data, byte[] ekPub);

    public AttestationResult AttestAsync(AttestationData data);

    public bool CheckActivatedCredentials(byte[] clientCredentials, byte[] serverCredentials);
}