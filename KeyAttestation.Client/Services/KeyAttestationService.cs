using System.IO.Abstractions;
using Google.Protobuf;
using KeyAttestation.Client.Entities;
using KeyAttestation.Client.Utils;
using KeyAttestationV1;
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
    
    public async Task<(string Csr, byte[] EkPub)> GeneratePkcs10CertificationRequestAsync(bool saveAsPemEncodedFile, string? fileName = null, CancellationToken cancellationToken = default)
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

        var aikRsaPublic = Helpers.ToAsymmetricKeyParameter(aik, false);

        var cms = Pkcs10RequestGenerator.GenerateCms(((SignatureRsassa)signature).sig, attestation.GetTpmRepresentation(), clientTpmKey.Public!.GetTpmRepresentation(), aikRsaPublic);
        var csr = Pkcs10RequestGenerator.Generate(clientRsaKeyPair.Public, clientRsaKeyPair.Private, cms);

        if (saveAsPemEncodedFile)
        {
            await Helpers.WriteCsrAsync(csr, fileName, _fileSystem.File, cancellationToken);
        }

        return (await Helpers.ConvertPkcs10RequestToPem(csr), Marshaller.GetTpmRepresentation(ek.Public));
    }

    public async Task<AttestationResult> SendPkcs10CertificationRequestAsync(
        string certificationRequest,
        byte[] ekPub,
        CancellationToken cancellationToken)
    {
        var activationRequest = new ActivationRequest
        {
            Csr = certificationRequest,
            EkPub = ByteString.CopyFrom(ekPub)
        };
        var activationResponse = await _client.ActivateCredentialsAsync(activationRequest);
        
        //TODO
        //Some service which makes credential activation
        
        var attestationRequest = new AttestationRequest
        {
            DecryptedCredentials = null,
            CorrelationId = 0
        };
         var attestationResponse = await _client.AttestAsync(attestationRequest);
         return new AttestationResult
         {
             Result = attestationResponse.IsAttested,
             Message = attestationResponse.Message,
             Certificate = attestationResponse.Certificate
         };
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