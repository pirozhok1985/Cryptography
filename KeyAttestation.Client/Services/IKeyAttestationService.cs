using Attestation.Shared.Entities;
using Tpm2Lib;

namespace KeyAttestation.Client.Services;

public interface IKeyAttestationService
{
    /// <summary>
    /// Generates rsa keypair and certificate signing request
    /// </summary>
    /// <param name="saveAsPemEncodedFile">Indicates that request should be saved as pem encoded file</param>
    /// <param name="fileName">The name of the file to be saved</param>
    /// <param name="cancellationToken">Task canceling support</param>
    /// <returns>Pkcs10GenerationResult:string? Csr, TpmKey? Ek, TpmKey? Aik</returns>
    public Task<Pksc10GenerationResult> GeneratePkcs10CertificationRequestAsync(bool saveAsPemEncodedFile, string? fileName, CancellationToken cancellationToken);
    
    /// <summary>
    /// Credential activation interface
    /// </summary>
    /// <param name="encryptedCredential">Credential to decrypt</param>
    /// <param name="encryptedSecret">Encrypted seed used to calculate hmac and symmetric key</param>
    /// <param name="ek">Endorsement key(TpmPublic)</param>
    /// <param name="aik">Attestation identity key(TpmPublick)</param>
    /// <param name="cancellationToken">Task canceling support</param>
    /// <returns>CredentialActivationResult: byte[] ActivatedCredentials</returns>
    public Task<CredentialActivationResult> ActivateCredentialAsync(IdObject encryptedCredential, byte[] encryptedSecret, TpmKey ek, TpmKey aik, CancellationToken cancellationToken);
}