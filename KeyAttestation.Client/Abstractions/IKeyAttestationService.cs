using KeyAttestation.Client.Entities;
using KeyAttestation.Client.Utils;
using Tpm2Lib;

namespace KeyAttestation.Client.Abstractions;

public interface IKeyAttestationService
{
    /// <summary>
    /// Generates rsa keypair and certificate signing request
    /// </summary>
    /// <param name="tpm2Facade">Tpm2 device interface facade</param>>
    /// <param name="fileName">The name of the file to be saved</param>
    /// <returns>Pkcs10GenerationResult:string? Csr, TpmKey? Ek, TpmKey? Aik</returns>
    public Task<Pksc10GenerationResult> GeneratePkcs10CertificationRequest(ITpm2Facade tpm2Facade, string? fileName);
    
    /// <summary>
    /// Credential activation interface
    /// </summary>
    /// <param name="tpm2Facade">Tpm2 device interface facade</param>>
    /// <param name="encryptedCredential">Credential to decrypt</param>
    /// <param name="encryptedSecret">Encrypted seed used to calculate hmac and symmetric key</param>
    /// <param name="ek">Endorsement key(TpmPublic)</param>
    /// <param name="aik">Attestation identity key(TpmPublick)</param>
    /// <returns>CredentialActivationResult: byte[] ActivatedCredentials</returns>
    public CredentialActivationResult? ActivateCredential(ITpm2Facade tpm2Facade, IdObject encryptedCredential, byte[] encryptedSecret, Tpm2Key ek, Tpm2Key aik);
}