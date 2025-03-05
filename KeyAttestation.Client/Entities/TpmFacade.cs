using Tpm2Lib;

namespace KeyAttestation.Client.Entities;

public sealed class TpmFacade: IDisposable
{
    enum KeyType
    {
        Attestation,
        Ordinal
    }
    
    public Tpm2? Tpm { get; private set; }
    private LinuxTpmDevice? _tpmDevice;
    private bool _disposed;

    public void InitialiseTpm(string deviceName)
    {
        _tpmDevice = new LinuxTpmDevice(deviceName);
        try
        {
            _tpmDevice.Connect();
            Tpm = new Tpm2(_tpmDevice);
        }
        catch (Exception)
        {
            Dispose();
        }
    }
    
    public TpmKey CreateEk()
    {
        var ekAttributes = ObjectAttr.Restricted | ObjectAttr.Decrypt | ObjectAttr.FixedTPM | ObjectAttr.FixedParent |
                           ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin;
        var ekRsaParams = new RsaParms(new SymDefObject(TpmAlgId.Aes, 256, TpmAlgId.Cfb), null, 2048, 65537);
        var endorsementKeyTemplate = new TpmPublic(TpmAlgId.Sha256, ekAttributes, null, ekRsaParams, new Tpm2bPublicKeyRsa());
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
        return new TpmKey(ekPublic, ekHandle);
    }
    
    public TpmKey CreateAk(TpmHandle parent)
        => CreateKey(KeyType.Attestation, parent);
    
    public TpmKey CreateKey(TpmHandle parent)
        => CreateKey(KeyType.Ordinal, parent);

    private TpmKey CreateKey(KeyType keyType, TpmHandle parent)
    {
        ObjectAttr typedAttributes = default;
        RsaParms? keyParams = null;
        switch (keyType)
        {
            case KeyType.Attestation:
                typedAttributes = ObjectAttr.Restricted | ObjectAttr.Sign;
                keyParams = new RsaParms(new SymDefObject(), new SchemeRsassa(TpmAlgId.Sha256), 2048, 65537);
                break;
            case KeyType.Ordinal:
                typedAttributes = ObjectAttr.Decrypt | ObjectAttr.Sign;
                keyParams = new RsaParms(new SymDefObject(), null, 2048, 65537);
                break;
        }
        
        var keyAttributes = ObjectAttr.FixedTPM | ObjectAttr.FixedParent |
                            ObjectAttr.UserWithAuth | ObjectAttr.SensitiveDataOrigin | typedAttributes;
        var keyTemplate = new TpmPublic(TpmAlgId.Sha256, keyAttributes, null, keyParams, new Tpm2bPublicKeyRsa());

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
        return new TpmKey(keyPub, handle, keyPriv);
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