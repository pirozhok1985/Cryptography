using System.IO.Abstractions;
using KeyAttestation.Client.Entities;
using KeyAttestation.Client.Utils;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Tpm2Lib;

namespace KeyAttestation.Client.Services;

public sealed class KeyAttestationService : IKeyAttestationService, IDisposable
{
    private readonly HttpClient _client;
    private readonly IFileSystem _fileSystem;
    private readonly ILogger<KeyAttestationService> _logger;
    private readonly TpmFacade? _tpmFacade;
    private bool _disposed;

    public KeyAttestationService(IFileSystem fileSystem, ILogger<KeyAttestationService> logger, HttpClient client)
    {
        _fileSystem = fileSystem;
        _logger = logger;
        _client = client;
        _tpmFacade = new TpmFacade();
        _tpmFacade.InitialiseTpm("/dev/tpmrm0");
    }
    
    public async Task<string> GeneratePkcs10CertificationRequestAsync(bool saveAsPemEncodedFile, string? fileName = null, CancellationToken cancellationToken = default)
    {
        var ek = _tpmFacade!.CreateEk();
        var ak = _tpmFacade.CreateAk(ek.Handle!);
        var srkHandlePersistent = TpmHandle.Persistent(5);
        var key = _tpmFacade.CreateKey(srkHandlePersistent);
        var attestation = _tpmFacade.Tpm!.Certify(key.Handle, ak.Handle, null, new SchemeRsassa(TpmAlgId.Sha256),
            out var signature);

        var rawRsa = new RawRsaCustom();
        rawRsa.Init(key.Public!, key.Private!);

        var keyPair = new AsymmetricCipherKeyPair(
            new RsaKeyParameters(false, rawRsa.N.ToBigIntegerBc(), rawRsa.E.ToBigIntegerBc()),
            new RsaKeyParameters(true, rawRsa.N.ToBigIntegerBc(), rawRsa.D.ToBigIntegerBc()));

        var cms = Pkcs10RequestGenerator.GenerateCms(((SignatureRsassa)signature).sig, attestation.GetTpmRepresentation(), keyPair.Public, ak.Public);
        var csr = Pkcs10RequestGenerator.Generate(keyPair.Public, keyPair.Private, cms);

        if (saveAsPemEncodedFile)
        {
            await Helpers.WriteCsrAsync(csr, fileName, _fileSystem.File, cancellationToken);
        }

        return await Helpers.ConvertPkcs10RequestToPem(csr);
    }

    public async Task<string> SendPkcs10CertificationRequestAsync(string certificationRequest,
        CancellationToken cancellationToken)
    {
        var content = new StringContent(certificationRequest);
        var response = await _client.PostAsync("csr", content, cancellationToken);
        try
        {
            response.EnsureSuccessStatusCode();
        }
        catch (Exception e)
        {
            _logger.LogError("Error sending csr! Error: {Error}", e.Message);
            return string.Empty;
        }
        return await response.Content.ReadAsStringAsync(cancellationToken);
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