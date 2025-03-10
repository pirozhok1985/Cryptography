using Tpm2Lib;

namespace Attestation.Shared.Entities;

public class AttestationData
{
    public Attest? Attestation { get; init; }
    
    public byte[]? Signature { get; init; }
    
    public TpmPublic? AikTpmPublic { get; init; }
    
    public TpmPublic? ClientTpmPublic { get; init; }
    
    public string Csr { get; set; }

    public AttestationData(Attest? attestation, byte[] signature, TpmPublic? aikTpmPublic, TpmPublic? clientTpmPublic)
    {
        Attestation = attestation;
        Signature = signature;
        AikTpmPublic = aikTpmPublic;
        ClientTpmPublic = clientTpmPublic;
    }

    private AttestationData()
    {
        
    }

    public static AttestationData Empty => new AttestationData();
}