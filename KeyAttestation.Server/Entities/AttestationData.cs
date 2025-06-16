using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Pkcs;
using Tpm2Lib;

namespace KeyAttestation.Server.Entities;

public class AttestationData
{
    public Attest Attestation { get; init; }
    
    public byte[] Signature { get; init; }

    public TpmPublic EkTpmPublic { get; init; }
    
    public TpmPublic AikTpmPublic { get; init; }
    
    public TpmPublic ClientTpmPublic { get; init; }

    public X509Certificate2 EKCertificate { get; init; }
    
    public Pkcs10CertificationRequest Csr { get; set; }

    public AttestationData(Attest? attestation, byte[] signature, TpmPublic? ekTpmPublic, TpmPublic? aikTpmPublic, TpmPublic? clientTpmPublic, X509Certificate2 ekCert, Pkcs10CertificationRequest request)
    {
        Attestation = attestation ?? throw new ArgumentNullException(nameof(attestation));
        Signature = signature;
        EkTpmPublic = ekTpmPublic ?? throw new ArgumentNullException(nameof(ekTpmPublic));
        AikTpmPublic = aikTpmPublic ?? throw new ArgumentNullException(nameof(aikTpmPublic));
        ClientTpmPublic = clientTpmPublic ?? throw new ArgumentNullException(nameof(clientTpmPublic));
        EKCertificate = ekCert ?? throw new ArgumentNullException(nameof(ekCert));
        Csr = request ?? throw new ArgumentNullException(nameof(request));
    }

    public override string ToString()
    {
        return $"AttestationData:\n\tAttestation = {Attestation}\n\tSignature = {Convert.ToBase64String(Signature)}\n\tAikTpmPublic = {AikTpmPublic}\n\tClientTpmPublic = {ClientTpmPublic}";
    }
}