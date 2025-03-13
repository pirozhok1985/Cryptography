using Tpm2Lib;

namespace KeyAttestation.Server.Entities;

public class AttestationData
{
    public Attest Attestation { get; init; }
    
    public byte[] Signature { get; init; }
    
    public TpmPublic AikTpmPublic { get; init; }
    
    public TpmPublic ClientTpmPublic { get; init; }
    
    public string? Csr { get; set; }

    public AttestationData(Attest? attestation, byte[] signature, TpmPublic? aikTpmPublic, TpmPublic? clientTpmPublic)
    {
        Attestation = attestation ?? throw new ArgumentNullException(nameof(attestation));
        Signature = signature;
        AikTpmPublic = aikTpmPublic ?? throw new ArgumentNullException(nameof(aikTpmPublic));
        ClientTpmPublic = clientTpmPublic ?? throw new ArgumentNullException(nameof(clientTpmPublic));
    }

    public override string ToString()
    {
        return $"AttestationData:\n\tAttestation = {Attestation}\n\tSignature = {Convert.ToBase64String(Signature)}\n\tAikTpmPublic = {AikTpmPublic}\n\tClientTpmPublic = {ClientTpmPublic}";
    }
}