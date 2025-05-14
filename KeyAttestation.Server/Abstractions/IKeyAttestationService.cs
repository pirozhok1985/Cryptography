using KeyAttestation.Server.Entities;
using Tpm2Lib;

namespace KeyAttestation.Server.Abstractions;

public interface IKeyAttestationService
{
    /// <summary>
    /// Retrieve AttestationData from Certificate Signing Request
    /// </summary>
    /// <param name="csr">Pem encoded certificate signing request</param>
    /// <returns>AttestationData: Attest? Attestation, byte[]? Signature, TpmPublic? AikTpmPublic, TpmPublic? ClientTpmPublic, string? Csr</returns>
    public AttestationData? GetAttestationData(string csr);

    /// <summary>
    /// Make credential as a part of credential activation process(without tpm)
    /// </summary>
    /// <param name="aikName">Attestation identity key name</param>
    /// <param name="ekPub">Public portion of Endorsement key</param>
    /// <returns>Credential: byte[] EncryptedIdentity, byte[] IntegrityHmac, byte[] EncryptedSecret, byte[] clearSecret, byte[] integrityHmac</returns>
    public Credential? MakeCredential(AttestationData attestationData);

    /// <summary>
    /// Attestation statement validation
    /// </summary>
    /// <param name="data">Attestation data to process</param>
    /// <returns>AttestationResult: bool Result, string? Message</returns>
    public AttestationResult? Attest(AttestationData data);

    /// <summary>
    /// Check whether received credential is equal to created one
    /// </summary>
    /// <param name="clientCredentials">Received credential</param>
    /// <param name="serverCredentials">Source credential</param>
    /// <returns>true if credentials are equal</returns>
    public bool CheckActivatedCredentials(byte[] clientCredentials, byte[] serverCredentials);
}