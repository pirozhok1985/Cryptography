using KeyAttestation.Server.Abstractions;
using KeyAttestation.Server.Services;
using Microsoft.Extensions.Logging;

namespace KeyAttestation.Tests.Server;

public class KeyAttestationServerFixture
{
    public IKeyAttestationService KeyAttestationService { get; init; }
    public IOtpSeedService OtpSeedService { get; init; }

    public KeyAttestationServerFixture()
    {
        var loggerAttest = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<KeyAttestationService>();
        var loggerSeed = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<OtpSeedService>();
        KeyAttestationService = new KeyAttestationService(loggerAttest);
        OtpSeedService = new OtpSeedService(loggerSeed);
    }
}