using Org.BouncyCastle.Crypto;
using Tpm2Lib;

namespace KeyAttestation.Server.Entities;

public class AttestationData
{
    public Attest? Attestation { get; init; }
    public byte[]? Signature { get; init; }
    public byte[]? AikRsaPublic { get; init; }
    public TpmPublic? ClientTpmPublic { get; init; }

    public AttestationData(Attest? attestation, byte[] signature, byte[] aikRsaPublic, TpmPublic? clientTpmPublic)
    {
        Attestation = attestation;
        Signature = signature;
        AikRsaPublic = aikRsaPublic;
        ClientTpmPublic = clientTpmPublic;
    }

    private AttestationData()
    {
        
    }

    public static AttestationData Empty => new AttestationData();
}