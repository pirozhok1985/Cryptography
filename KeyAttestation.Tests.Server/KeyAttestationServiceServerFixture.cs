using KeyAttestation.Server.Abstractions;
using KeyAttestation.Server.Services;
using Microsoft.Extensions.Logging;

namespace KeyAttestation.Tests.Server;

public abstract class KeyAttestationServiceServerFixture
{
    public IKeyAttestationService KeyAttestationService { get; init; }
    public IOtpSeedService OtpSeedService { get; init; }

    protected KeyAttestationServiceServerFixture()
    {
        var loggerAttest = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<KeyAttestationService>();
        var loggerSeed = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<OtpSeedService>();
        KeyAttestationService = new KeyAttestationService(loggerAttest);
        OtpSeedService = new OtpSeedService(loggerSeed);
    }
}