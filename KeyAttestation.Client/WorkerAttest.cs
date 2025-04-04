using System.IO.Abstractions;
using Google.Protobuf;
using KeyAttestation.Client.Abstractions;
using KeyAttestation.Client.Entities;
using KeyAttestation.Client.Factories;
using KeyAttestationV1;
using Microsoft.Extensions.Logging;
using Tpm2Lib;
using KeyAttestationService = KeyAttestation.Client.Services.KeyAttestationService;

namespace KeyAttestation.Client;

public static class WorkerAttest
{
    public static async Task DoWork(string tpmDevice, string? csrFilePath, string endPoint)
    {
        var fileSystem = new FileSystem();
        var logger = LoggerFactory.Create(b => b.AddConsole()).CreateLogger<KeyAttestationService>();
        using var factory = new KeyAttestationGrpcClientFactory(endPoint);
        var client = factory.CreateClient();
        var tpmFacade = CreateTpm2Facade(tpmDevice, logger);

        using var keyAttestationService = new KeyAttestationService(fileSystem, logger, tpmFacade);

        logger.LogInformation("Start generating PKCS10 certificate signing request");
        var result = await keyAttestationService.GeneratePkcs10CertificationRequest(csrFilePath);
        if (result.Ek == null || result.Aik == null || result.Csr == null)
        {
            logger.LogError("Pkcs10 certificate signing request generation failed!");
            return;
        }

        logger.LogInformation("Successfully generated PKCS10 certificate request and saved it on file system!");

        logger.LogInformation("Sending Activation Request!");
        var makeCredResponse = await client.MakeCredentialAsync(new ActivationRequest
        {
            Csr = result.Csr,
            EkPub = ByteString.CopyFrom(result.Ek!.Public)
        });
        logger.LogInformation(
            "Received Activation Response! Result: {@Content}", makeCredResponse);

        var cred = new IdObject(makeCredResponse.IntegrityHmac.ToByteArray(),
            makeCredResponse.EncryptedIdentity.ToByteArray());

        logger.LogInformation("Start credential activation!");
        var activatedCred = keyAttestationService.ActivateCredential(
            cred,
            makeCredResponse.EncryptedSecret.ToByteArray(),
            result.Ek,
            result.Aik!);

        if (activatedCred is null)
        {
            logger.LogError("Credential activation failed!");
            return;
        }

        logger.LogInformation("Activation credential successfully finished! Result: {@Content}", activatedCred);

        logger.LogInformation("Sending attestation request!");
        var attestResponse = await client.AttestAsync(new AttestationRequest
        {
            DecryptedCredentials = ByteString.CopyFrom(activatedCred.ActivatedCredentials),
            CorrelationId = makeCredResponse.CorrelationId
        });
        logger.LogInformation("Received Attestation Response! Result: {@Content}", attestResponse);
    }

    private static ITpm2Facade CreateTpm2Facade(string deviceName, ILogger logger)
        => deviceName switch
        {
            "simulator" => new Tpm2Facade<TcpTpmDevice>(logger, new Tpm2DeviceCreationProperties()
            {
                ServerName = "localhost",
                ServerPort = 2322
            }),

            "linux" => new Tpm2Facade<LinuxTpmDevice>(logger, new Tpm2DeviceCreationProperties()
            {
                DeviceName = "/dev/tpmrm0"
            }),

            "windows" => new Tpm2Facade<TbsDevice>(logger, new Tpm2DeviceCreationProperties()),
            _ => throw new ArgumentOutOfRangeException(nameof(deviceName), deviceName, "Unrecognized device type")
        };
}