using System.IO.Abstractions;
using System.Runtime.InteropServices;
using KeyAttestation.Client.Abstractions;
using KeyAttestation.Client.Entities;
using KeyAttestation.Client.Extensions;
using KeyAttestation.Client.Utils;
using Microsoft.Extensions.Logging;
using Tpm2Lib;
using Exception = System.Exception;

namespace KeyAttestation.Client.Services;

public sealed class KeyAttestationService : IKeyAttestationService
{
    private readonly IFileSystem _fileSystem;
    private readonly ILogger<KeyAttestationService> _logger;

    public KeyAttestationService(
        IFileSystem fileSystem,
        ILogger<KeyAttestationService> logger)
    {
        _fileSystem = fileSystem;
        _logger = logger;
    }
    
    public async Task<Pksc10GenerationResult> GeneratePkcs10CertificationRequest(ITpm2Facade tpm2Facade, string? fileName = null)
    {
        var ekCert = tpm2Facade.GetEkCert();
        if (ekCert is null)
        {
            return Pksc10GenerationResult.Empty;
        }

        var ek = tpm2Facade.CreateEk();
        if (ek == null)
        {
            return Pksc10GenerationResult.Empty;
        }

        var aik = tpm2Facade.CreateAk(ek.Handle!);
        if (aik == null)
        {
            return Pksc10GenerationResult.Empty;
        }

        // Parent key persistent handle
        TpmHandle srkHandle;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            srkHandle = TpmHandle.Persistent(5); // Preconfigured parent key under 0x81000005. You have to create it first or use endorsemnt key as a parent.
        }
        else
        {
            srkHandle = ek.Handle!;
        }

        var clientTpmKey = tpm2Facade.CreateKey(srkHandle);
        if (clientTpmKey == null)
        {
            return Pksc10GenerationResult.Empty;
        }

        Attest? attestation;
        ISignatureUnion? signature;
        try
        {
            attestation = tpm2Facade.Tpm!.Certify(
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

        var cms = SignedDataGenerator.GenerateCms(Marshaller.GetTpmRepresentation(signature), attestation.GetTpmRepresentation(), clientTpmKey.Public!.GetTpmRepresentation(), aik, ekCert);
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
        ITpm2Facade tpm2Facade,
        IdObject encryptedCredential,
        byte[] encryptedSecret,
        Tpm2Key ek,
        Tpm2Key aik)
    {
        try
        {
            var activatedCredential = tpm2Facade.Tpm!.ActivateCredential(
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
}