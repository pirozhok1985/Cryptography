using KeyAttestation.Client.Entities;
using Org.BouncyCastle.Pkcs;

namespace KeyAttestation.Client.Services;

public interface IKeyAttestationService
{
    public Task<Pksc10GenerationResult> GeneratePkcs10CertificationRequestAsync(bool saveAsPemEncodedFile, string? fileName, CancellationToken cancellationToken);
    
    public Task<CredentialsActivationResult> ActivateCredentialsAsync(byte[] encryptedCredentials, TpmKey ek, TpmKey aik, CancellationToken cancellationToken);
}