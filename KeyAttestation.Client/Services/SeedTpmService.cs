using System.Text;
using KeyAttestation.Client.Abstractions;
using KeyAttestation.Client.Entities;
using Microsoft.Extensions.Logging;
using Tpm2Lib;

namespace KeyAttestation.Client.Services;

public class SeedTpmService : ISeedTpmService
{
    private readonly ILogger<SeedTpmService> _logger;

    public SeedTpmService(ILogger<SeedTpmService> logger)
    {
        _logger = logger;
    }
    
    public Tpm2Key? ImportSeedToTpm(ITpm2Facade tpm2Facade, byte[] seed, string pin)
    {
        var parent = TpmHandle.Persistent(5);
        var parentPub = tpm2Facade.Tpm!.ReadPublic(parent, out _, out _);
        var objAttributes = ObjectAttr.UserWithAuth | ObjectAttr.Sign;
        var hmacParams = new KeyedhashParms(new SchemeHmac(TpmAlgId.Sha256));
        var objPublic = new TpmPublic(TpmAlgId.Sha256, objAttributes, null, hmacParams, new Tpm2bDigestKeyedhash());
        var authValue = AuthValue.FromString(TpmAlgId.Sha256, pin);
        var keyToImport = TssObject.Create(objPublic, authValue, seed);
        var dupBlob = keyToImport.GetDuplicationBlob(parentPub, null, out var secret);
        var result = tpm2Facade.Tpm!.Import(parent, null, keyToImport.Public, dupBlob, secret, new SymDefObject());
        var handle = tpm2Facade.Tpm.Load(parent, result, keyToImport.Public);
        return new Tpm2Key(keyToImport.Public, handle, result);
    }
}