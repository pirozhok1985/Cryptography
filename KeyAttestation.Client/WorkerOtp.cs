using System.IO.Abstractions;
using System.Runtime.InteropServices;
using Google.Protobuf;
using KeyAttestation.Client.Factories;
using KeyAttestation.Client.Services;
using Microsoft.Extensions.Logging;
using OtpSeedV1;
using Tpm2Lib;

namespace KeyAttestation.Client;

public static class WorkerOtp
{
    public static async Task DoWork(string tpmDevice, string endPoint, string pin, string? seedPublic, string? seedPrivate)
    {
        var fileSystem = new FileSystem();
        var loggerAttest = LoggerFactory.Create(b => b.AddConsole()).CreateLogger<KeyAttestationService>();
        var loggerSeed = LoggerFactory.Create(b => b.AddConsole()).CreateLogger<SeedTpmService>();
        using var factory = new GrpcClientFactoryCustom<OtpSeedService.OtpSeedServiceClient>(endPoint);
        var client = factory.CreateClient(channel => new OtpSeedService.OtpSeedServiceClient(channel));
        using var tpmFacade = Tpm2FacadeFactory.CreateTpm2Facade(tpmDevice, loggerAttest);
        var keyAttestationService = new KeyAttestationService(fileSystem, loggerAttest);
        var seedTpmService = new SeedTpmService(loggerSeed);

        var ek = tpmFacade.CreateEk();
        var aik = tpmFacade.CreateAk(ek.Handle);

        var makeCredResponse = await client.GetOtpSeedAsync(new SeedRequest
        {
            AikName = ByteString.CopyFrom(aik.Public.GetName()),
            EkPub = ByteString.CopyFrom(Marshaller.GetTpmRepresentation(ek.Public))
        });

        var idObject = new IdObject(makeCredResponse.IntegrityHmac.ToByteArray(),
            makeCredResponse.EncryptedIdentity.ToByteArray());
        loggerSeed.LogInformation("Start credential activation!");
        var seed = keyAttestationService.ActivateCredential(
            tpmFacade,
            idObject,
            makeCredResponse.EncryptedSecret.ToByteArray(),
            ek,
            aik);
        loggerSeed.LogInformation("Activation credential successfully finished! Result: {@Content}", seed);
        
        loggerSeed.LogInformation("Importing seed into tpm!!");
        TpmHandle srkHandle;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            srkHandle = TpmHandle.Persistent(5); // Preconfigured parent key under 0x81000005. You have to create it first or use endorsemnt key as a parent.
        }
        else
        {
            srkHandle = ek.Handle!;
        }
        var importedKey = seedTpmService.ImportSeedToTpm(tpmFacade, srkHandle, seed.ActivatedCredentials, "123456");
        loggerSeed.LogInformation("Seed importing successfully finished! Details: {Key}", importedKey);
    }
}