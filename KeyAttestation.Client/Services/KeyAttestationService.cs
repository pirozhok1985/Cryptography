using System.IO.Abstractions;
using Attestation.Shared;
using Attestation.Shared.Entities;
using KeyAttestation.Client.Utils;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Tpm2Lib;

namespace KeyAttestation.Client.Services;

public sealed class KeyAttestationService : IKeyAttestationService, IDisposable
{
    private readonly KeyAttestationV1.KeyAttestationService.KeyAttestationServiceClient _client;
    private readonly IFileSystem _fileSystem;
    private readonly ILogger<KeyAttestationService> _logger;
    private readonly TpmFacade? _tpmFacade;
    private bool _disposed;

    public KeyAttestationService(IFileSystem fileSystem, ILogger<KeyAttestationService> logger, KeyAttestationV1.KeyAttestationService.KeyAttestationServiceClient client)
    {
        _fileSystem = fileSystem;
        _logger = logger;
        _client = client;
        _tpmFacade = new TpmFacade();
        _tpmFacade.InitialiseTpm("/dev/tpmrm0");
    }
    
    public async Task<Pksc10GenerationResult> GeneratePkcs10CertificationRequestAsync(bool saveAsPemEncodedFile, string? fileName = null, CancellationToken cancellationToken = default)
    {
        var ek = _tpmFacade!.CreateEk();
        var aik = _tpmFacade.CreateAk(ek.Handle!);
        var srkHandlePersistent = TpmHandle.Persistent(5);
        var clientTpmKey = _tpmFacade.CreateKey(srkHandlePersistent);
        var attestation = _tpmFacade.Tpm!.Certify(clientTpmKey.Handle, aik.Handle, null, new SchemeRsassa(TpmAlgId.Sha256),
            out var signature);

        var clientRsaKeyPair = new AsymmetricCipherKeyPair(
            Helpers.ToAsymmetricKeyParameter(clientTpmKey, false),
            Helpers.ToAsymmetricKeyParameter(clientTpmKey, true));

        var cms = Pkcs10RequestGenerator.GenerateCms(((SignatureRsassa)signature).sig, attestation.GetTpmRepresentation(), clientTpmKey.Public!.GetTpmRepresentation(), aik);
        var csr = Pkcs10RequestGenerator.Generate(clientRsaKeyPair.Public, clientRsaKeyPair.Private, cms);

        if (saveAsPemEncodedFile)
        {
            await Helpers.WriteCsrAsync(csr, fileName, _fileSystem.File, cancellationToken);
        }

        return new Pksc10GenerationResult
        {
            Csr = await Helpers.ConvertPkcs10RequestToPem(csr),
            Ek = ek,
            Aik = aik
        };
    }

    public Task<CredentialActivationResult> ActivateCredentialAsync(
        IdObject encryptedCredential,
        byte[] encryptedSecret,
        TpmKey ek,
        TpmKey aik,
        CancellationToken cancellationToken)
    {
        var activatedCredential = _tpmFacade!.Tpm!.ActivateCredential(
            aik.Handle,
            ek.Handle,
            encryptedCredential,
            encryptedSecret);
        return Task.FromResult(new CredentialActivationResult
        {
            ActivatedCredentials = activatedCredential
        });
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _tpmFacade?.Dispose();
        _disposed = true;
    }
}