using System.IO.Abstractions;
using Google.Protobuf;
using KeyAttestation.Client.Factories;
using KeyAttestation.Client.Utils;
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
        using var factory = new GrpcClientFactoryCustom<KeyAttestationV1.KeyAttestationService.KeyAttestationServiceClient>(endPoint);
        var client = factory.CreateClient(channel => new KeyAttestationV1.KeyAttestationService.KeyAttestationServiceClient(channel));
        using var tpmFacade = Helper.CreateTpm2Facade(tpmDevice, logger);

        var keyAttestationService = new KeyAttestationService(fileSystem, logger);

        logger.LogInformation("Start generating PKCS10 certificate signing request");
        var result = await keyAttestationService.GeneratePkcs10CertificationRequest(tpmFacade, csrFilePath);
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
            tpmFacade,
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
}