using Attestation.Shared.Entities;

namespace KeyAttestation.Client.Services;

public interface IKeyAttestationService
{
    public Task<Pksc10GenerationResult> GeneratePkcs10CertificationRequestAsync(bool saveAsPemEncodedFile, string? fileName, CancellationToken cancellationToken);
    
    public Task<CredentialActivationResult> ActivateCredentialAsync(byte[] encryptedredential, byte[] encryptedSecret, TpmKey ek, TpmKey aik, CancellationToken cancellationToken);
}