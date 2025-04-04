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
        _logger.LogInformation("Starting seed generation!");
        var seed = GenerateOtpSeedAsync();
        _logger.LogInformation("Seed generation finished! Seed: {Seed}", seed);
        try
        {
            var ekPubObj = Marshaller.FromTpmRepresentation<TpmPublic>(ekPub);
            _logger.LogInformation("Starting make credential process!");
            var idObject = ekPubObj.CreateActivationCredentials(seed, aikName, out var encSeed);
            _logger.LogInformation("Encrypted credential has successfully been created! Cred: {@Cred}.", idObject);
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