using System.Security.Cryptography;
using System.Text;
using KeyAttestation.Server.Abstractions;
using Tpm2Lib;

namespace KeyAttestation.Server.Services;

public class OtpSeedService : IOtpSeedService
{
    private readonly ILogger<OtpSeedService> _logger;

    public OtpSeedService(ILogger<OtpSeedService> logger)
    {
        _logger = logger;
    }

    public byte[] MakeSeedBasedCredential(byte[] aikName, byte[] ekPub)
    {
        var seed = GenerateOtpSeedAsync();
        try
        {
            var ekPubObj = Marshaller.FromTpmRepresentation<TpmPublic>(ekPub);
            var idObject = ekPubObj.CreateActivationCredentials(seed, aikName, out var encSeed);
            return idObject.GetTpmRepresentation();
        }
        catch (Exception e)
        {
            _logger.LogError("MakeSeedBasedCredential failed! Error: {Message}",e.Message);
            return [];
        }
    }
    
    private byte[] GenerateOtpSeedAsync()
    {
        return RandomNumberGenerator.GetBytes(32);
    }
}