using KeyAttestation.Server.Services;
using Microsoft.Extensions.Logging;

namespace KeyAttestation.Tests;

public class HelperServerFixture
{
    private readonly ILogger<KeyAttestationService> _logger;
    public IKeyAttestationService KeyAttestationService { get; init; }
    
    public HelperServerFixture()
    {
        _logger = LoggerFactory.Create(builder => builder.AddConsole()).CreateLogger<KeyAttestationService>();
        KeyAttestationService = new KeyAttestationService(_logger);
    }
}