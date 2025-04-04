using System.IO.Abstractions;
using KeyAttestation.Client.Factories;
using KeyAttestation.Client.Services;
using KeyAttestation.Client.Utils;
using Microsoft.Extensions.Logging;
using OtpSeedV1;

namespace KeyAttestation.Client;

public static class WorkerOtp
{
    public static async Task DoWork(string tpmDevice, string endPoint, string pin, string? seedPublic, string? seedPrivate)
    {
        var fileSystem = new FileSystem();
        var logger = LoggerFactory.Create(b => b.AddConsole()).CreateLogger<KeyAttestationService>();
        using var factory = new GrpcClientFactoryCustom<OtpSeedService.OtpSeedServiceClient>(endPoint);
        var client = factory.CreateClient(channel => new OtpSeedService.OtpSeedServiceClient(channel));
        using var tpmFacade = Helper.CreateTpm2Facade(tpmDevice, logger);
        var keyAttestationService = new KeyAttestationService(fileSystem, logger);
    }
}