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
    
    public Tpm2Key? ImportSeedToTpm(ITpm2Facade tpm2Facade, TpmHandle parent, byte[] seed, string pin)
    {
        return tpm2Facade.ImportHmacKey(parent, seed, pin);
    }
}