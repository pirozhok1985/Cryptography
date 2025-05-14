using System.Security.Cryptography.X509Certificates;
using KeyAttestation.Client.Abstractions;
using KeyAttestation.Client.Entities;
using KeyAttestation.Client.Factories;
using Microsoft.Extensions.Logging;
using Tpm2Lib;

namespace KeyAttestation.Client;

public sealed class Tpm2Facade<TTpm2Device>: ITpm2Facade
{
    private readonly ILogger _logger;
    private readonly Tpm2DeviceCreationProperties _properties;

    enum KeyType
    {
        Attestation,
        Ordinal
    }
    
    public Tpm2? Tpm { get; init; }
    private Tpm2Device? _tpmDevice;
    private bool _disposed;

    public Tpm2Facade(
        ILogger logger,
        Tpm2DeviceCreationProperties properties)
    {
        _logger = logger;
        _properties = properties;
        Tpm = InitialiseTpm();
    }

    private Tpm2? InitialiseTpm()
    {
        var factory = new Tpm2DeviceFactory<TTpm2Device>();
        _tpmDevice = factory.CreateTpm2Device(_properties);
        try
        {
            _tpmDevice?.Connect();
            return new Tpm2(_tpmDevice);
        }
        catch (Exception e)
        {
            _logger.LogError("Failed to connect to TpmDevice! Details: {Message}", e.Message);
            return null;
        }
    }

    
    public byte[] GetEkCert()
    {
        var ekCertIndex = TpmHandle.NV(0xc00002);
        var ekCertPub = Tpm!.NvReadPublic(ekCertIndex, out var _);
        return Tpm.NvRead(TpmRh.Owner, ekCertPub.nvIndex, ekCertPub.dataSize, 0);
    } 
    
    public Tpm2Key? CreateEk()
    {
        var ekAttributes = ObjectAttr.Restricted | ObjectAttr.Decrypt | ObjectAttr.FixedTPM | ObjectAttr.FixedParent |
                           ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin;
        var ekRsaParams = new RsaParms(new SymDefObject(TpmAlgId.Aes, 256, TpmAlgId.Cfb), null, 2048, 65537);
        var endorsementKeyTemplate = new TpmPublic(TpmAlgId.Sha256, ekAttributes, null, ekRsaParams, new Tpm2bPublicKeyRsa());
        try
        {
            var ekHandle = Tpm!.CreatePrimary(
                TpmHandle.RhEndorsement, 
                new SensitiveCreate(),
                endorsementKeyTemplate,
                null,
                [],
                out var ekPublic,
                out _,
                out _,
                out _);
            return new Tpm2Key(ekPublic, ekHandle);
        }
        catch (Exception e)
        {
            _logger.LogError("Failed to create Endorsement key! Details: {Message}", e.Message);
            return null;
        }
    }

    public Tpm2Key? ImportHmacKey(TpmHandle parent, byte[] seed, string pin)
    {
        var parentPub = Tpm!.ReadPublic(parent, out _, out _);
        var objAttributes = ObjectAttr.UserWithAuth | ObjectAttr.Sign;
        var hmacParams = new KeyedhashParms(new SchemeHmac(TpmAlgId.Sha256));
        var objPublic = new TpmPublic(TpmAlgId.Sha256, objAttributes, null, hmacParams, new Tpm2bDigestKeyedhash());
        var authValue = AuthValue.FromString(TpmAlgId.Sha256, pin);
        var keyToImport = TssObject.Create(objPublic, authValue, seed);
        var dupBlob = keyToImport.GetDuplicationBlob(parentPub, null, out var secret);
        try
        {
            var result = Tpm!.Import(parent, null, keyToImport.Public, dupBlob, secret, new SymDefObject());
            var handle = Tpm.Load(parent, result, keyToImport.Public);
            return new Tpm2Key(keyToImport.Public, handle, result);
        }
        catch (Exception e)
        {
            _logger.LogError("Failed to import hmac key! Details: {Message}", e.Message);
            return null;
        }
    }

    public Tpm2Key? CreateAk(TpmHandle parent)
        => CreateRsaKey(KeyType.Attestation, parent);
    
    public Tpm2Key? CreateKey(TpmHandle parent)
        => CreateRsaKey(KeyType.Ordinal, parent);

    private Tpm2Key? CreateRsaKey(KeyType keyType, TpmHandle parent)
    {
        ObjectAttr typedAttributes = default;
        RsaParms? keyParams = null;
        switch (keyType)
        {
            case KeyType.Attestation:
                typedAttributes = ObjectAttr.Restricted | ObjectAttr.Sign | ObjectAttr.SensitiveDataOrigin;
                keyParams = new RsaParms(new SymDefObject(), new SchemeRsassa(TpmAlgId.Sha256), 2048, 65537);
                break;
            case KeyType.Ordinal:
                typedAttributes = ObjectAttr.Decrypt | ObjectAttr.Sign;
                keyParams = new RsaParms(new SymDefObject(), null, 2048, 65537);
                break;
        }
        
        var keyAttributes = ObjectAttr.FixedTPM | ObjectAttr.FixedParent |
                            ObjectAttr.UserWithAuth | typedAttributes;
        var keyTemplate = new TpmPublic(TpmAlgId.Sha256, keyAttributes, null, keyParams, new Tpm2bPublicKeyRsa());

        try
        {
            var keyPriv = Tpm!.Create(
                parent,
                new SensitiveCreate(),
                keyTemplate,
                null,
                [],
                out var keyPub,
                out _,
                out _,
                out _);
            var handle = Tpm.Load(parent, keyPriv, keyPub);
            return new Tpm2Key(keyPub, handle, keyPriv);
        }
        catch (Exception e)
        {
            _logger.LogError("Failed to create asymmetric key! Details: {Message}", e.Message);
            return null;
        }
    }
    
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        Tpm?.Dispose();
        _tpmDevice?.Dispose();
        _disposed = true;
    }
}