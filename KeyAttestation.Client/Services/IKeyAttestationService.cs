using Attestation.Shared.Entities;

namespace KeyAttestation.Client.Services;

public interface IKeyAttestationService
{
    public Task<Pksc10GenerationResult> GeneratePkcs10CertificationRequestAsync(bool saveAsPemEncodedFile, string? fileName, CancellationToken cancellationToken);
    
    public Task<CredentialsActivationResult> ActivateCredentialsAsync(byte[] encryptedCredentials, TpmKey ek, TpmKey aik, CancellationToken cancellationToken);
}