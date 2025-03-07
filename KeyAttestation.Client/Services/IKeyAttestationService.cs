using KeyAttestation.Client.Entities;
using Org.BouncyCastle.Pkcs;

namespace KeyAttestation.Client.Services;

public interface IKeyAttestationService
{
    public Task<(string Csr, byte[] EkPub)> GeneratePkcs10CertificationRequestAsync(bool saveAsPemEncodedFile, string? fileName, CancellationToken cancellationToken);
    
    public Task<AttestationResult> SendPkcs10CertificationRequestAsync(string certificationRequest, byte[] ekPub, CancellationToken cancellationToken);
}