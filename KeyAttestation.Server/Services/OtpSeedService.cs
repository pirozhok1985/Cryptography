using System.Security.Cryptography;
using KeyAttestation.Server.Abstractions;
using KeyAttestation.Server.Entities;
using Tpm2Lib;

namespace KeyAttestation.Server.Services;

public class OtpSeedService : IOtpSeedService
{
    private readonly ILogger<OtpSeedService> _logger;

    public OtpSeedService(ILogger<OtpSeedService> logger)
    {
        _logger = logger;
    }

    public Credential? MakeSeedBasedCredential(byte[] aikName, byte[] ekPub)
    {
        var seed = GenerateOtpSeedAsync();
        try
        {
            var ekPubObj = Marshaller.FromTpmRepresentation<TpmPublic>(ekPub);
            var idObject = ekPubObj.CreateActivationCredentials(seed, aikName, out var encSeed);
            return new Credential(idObject.encIdentity, encSeed, null, idObject.integrityHMAC);
        }
        catch (Exception e)
        {
            _logger.LogError("MakeSeedBasedCredential failed! Error: {Message}",e.Message);
            return null;
        }
    }
    
    private byte[] GenerateOtpSeedAsync()
    {
        return RandomNumberGenerator.GetBytes(32);
    }
}