using Org.BouncyCastle.Pkcs;

namespace KeyAttestation.Client.Services;

public interface IKeyAttestationService
{
    public Task<string> GeneratePkcs10CertificationRequestAsync(bool saveAsPemEncodedFile, string? fileName, CancellationToken cancellationToken);
    
    public Task<string> SendPkcs10CertificationRequestAsync(string certificationRequest, CancellationToken cancellationToken);
}