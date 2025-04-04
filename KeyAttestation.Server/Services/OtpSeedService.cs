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

    public async Task<byte[]> MakeSeedBasedCredential(byte[] aikName, byte[] ekPub)
    {
        var seed = await GenerateOtpSeedAsync(aikName);
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
    
    private async Task<byte[]> GenerateOtpSeedAsync(byte[] aikName)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(Convert.ToHexString(aikName)));
        return await HMACSHA256.HashDataAsync(Encoding.UTF8.GetBytes("super secret"), stream);
    }
}