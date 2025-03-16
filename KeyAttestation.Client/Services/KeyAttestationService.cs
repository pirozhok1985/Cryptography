using System.IO.Abstractions;
using KeyAttestation.Client.Entities;
using KeyAttestation.Client.Extensions;
using KeyAttestation.Client.Utils;
using Microsoft.Extensions.Logging;
using Tpm2Lib;
using Exception = System.Exception;

namespace KeyAttestation.Client.Services;

public sealed class KeyAttestationService : IKeyAttestationService, IDisposable
{
    private readonly KeyAttestationV1.KeyAttestationService.KeyAttestationServiceClient _client;
    private readonly IFileSystem _fileSystem;
    private readonly ILogger<KeyAttestationService> _logger;
    private readonly TpmFacade? _tpmFacade;
    private bool _disposed;

    public KeyAttestationService(
        IFileSystem fileSystem,
        ILogger<KeyAttestationService> logger,
        KeyAttestationV1.KeyAttestationService.KeyAttestationServiceClient client,
        string deviceName)
    {
        _fileSystem = fileSystem;
        _logger = logger;
        _client = client;
        _tpmFacade = new TpmFacade(logger);
        _tpmFacade.InitialiseTpm(deviceName);
    }
    
    public async Task<Pksc10GenerationResult> GeneratePkcs10CertificationRequest(string? fileName = null)
    {
        var ek = _tpmFacade!.CreateEk();
        if (ek == null)
        {
            return Pksc10GenerationResult.Empty;
        }

        var aik = _tpmFacade.CreateAk(ek.Handle!);
        if (aik == null)
        {
            return Pksc10GenerationResult.Empty;
        }

        // Parent key persistent handle
        var srkHandlePersistent = TpmHandle.Persistent(5);
        
        var clientTpmKey = _tpmFacade.CreateKey(srkHandlePersistent);
        if (clientTpmKey == null)
        {
            return Pksc10GenerationResult.Empty;
        }

        Attest? attestation;
        ISignatureUnion? signature;
        try
        {
            attestation = _tpmFacade.Tpm!.Certify(
                clientTpmKey.Handle,
                aik.Handle,
                [],
                new SchemeRsassa(aik.Public!.nameAlg),
                out signature);
        }
        catch (Exception e)
        {
            _logger.LogError("Attestation statement generation failed! Details: {Message}", e.Message);
            return Pksc10GenerationResult.Empty;
        }

        var clientRsaKeyPair = clientTpmKey.ToAsymmetricCipherKeyPair();

        var cms = SignedDataGenerator.GenerateCms(Marshaller.GetTpmRepresentation(signature), attestation.GetTpmRepresentation(), clientTpmKey!.Public!.GetTpmRepresentation(), aik);
        var csr = Pkcs10RequestGenerator.Generate(clientRsaKeyPair.Public, clientRsaKeyPair.Private, cms);

        if (!string.IsNullOrEmpty(fileName))
        {
            await csr.WriteCsrAsync(fileName, _fileSystem.File);
        }

        return new Pksc10GenerationResult
        {
            Csr = await csr.ConvertPkcs10RequestToPem(),
            Ek = ek,
            Aik = aik
        };
    }

    public CredentialActivationResult? ActivateCredential(
        IdObject encryptedCredential,
        byte[] encryptedSecret,
        TpmKey ek,
        TpmKey aik)
    {
        try
        {
            var activatedCredential = _tpmFacade!.Tpm!.ActivateCredential(
                aik.Handle,
                ek.Handle,
                encryptedCredential,
                encryptedSecret);
            return new CredentialActivationResult(activatedCredential);
        }
        catch (Exception e)
        {
            _logger.LogError("Attestation statement activation failed! Details: {Message}", e.Message);
            return null;
        }
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