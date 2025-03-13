using KeyAttestation.Server.Services;
using Microsoft.Extensions.Logging;

namespace KeyAttestation.Tests;

public class HelperServerFixture
{
    public IKeyAttestationService KeyAttestationService { get; init; }
    
    public HelperServerFixture()
    {
        ILogger<KeyAttestationService> logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<KeyAttestationService>();
        KeyAttestationService = new KeyAttestationService(logger);
    }
}