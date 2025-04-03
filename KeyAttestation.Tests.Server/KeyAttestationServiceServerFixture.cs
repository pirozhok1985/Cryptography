using KeyAttestation.Server.Abstractions;
using KeyAttestation.Server.Services;
using Microsoft.Extensions.Logging;

namespace KeyAttestation.Tests.Server;

public class KeyAttestationServiceServerFixture
{
    public IKeyAttestationService KeyAttestationService { get; init; }
    public IOtpSeedService OtpSeedService { get; init; }
    
    public KeyAttestationServiceServerFixture()
    {
        ILogger<KeyAttestationService> logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<KeyAttestationService>();
        KeyAttestationService = new KeyAttestationService(logger);
        OtpSeedService = new OtpSeedService(KeyAttestationService);
    }
}