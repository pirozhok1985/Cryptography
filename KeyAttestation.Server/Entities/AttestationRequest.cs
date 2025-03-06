using Org.BouncyCastle.Crypto;
using Tpm2Lib;

namespace KeyAttestation.Server.Entities;

public class AttestationRequest
{
    public Attest? Attestation { get; init; }
    public byte[]? Signature { get; init; }
    public byte[]? AikTpmPublic { get; init; }
    public TpmPublic? ClientTpmPublic { get; init; }

    public AttestationRequest(Attest? attestation, byte[] signature, byte[] aikTpmPublic, TpmPublic? clientTpmPublic)
    {
        Attestation = attestation;
        Signature = signature;
        AikTpmPublic = aikTpmPublic;
        ClientTpmPublic = clientTpmPublic;
    }
}