using System.Security.Cryptography;
using System.Text;
using KeyAttestation.Server.Entities;
using Tpm2Lib;

namespace KeyAttestation.Server.Services;

public class OtpSeedService : IOtpSeedService
{
    private readonly IKeyAttestationService _keyAttestationService;

    public OtpSeedService(IKeyAttestationService keyAttestationService)
    {
        _keyAttestationService = keyAttestationService;
    }

    public async Task<byte[]> MakeSeedBasedCredential(byte[] aikName, TpmPublic ekPub)
    {
        var seed = await GenerateOtpSeedAsync();
        var idObject = ekPub.CreateActivationCredentials(seed, aikName, out var encSeed);
        return idObject.GetTpmRepresentation();
    }
    
    private async Task<byte[]> GenerateOtpSeedAsync()
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes("Random Random Random Random"));
        return await HMACSHA256.HashDataAsync(Encoding.UTF8.GetBytes("super secret"), stream);
    }
}