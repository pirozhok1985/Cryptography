using System.IO.Abstractions;
using Google.Protobuf;
using KeyAttestation.Client.Abstractions;
using KeyAttestation.Client.Entities;
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
        var logger = LoggerFactory.Create(b => b.AddConsole()).CreateLogger<KeyAttestationService>();
        var client = CreateAttestationClient(endPoint);
        using var tpmFacade = Tpm2FacadeFactory.CreateTpm2Facade(tpmDevice, logger);
        var keyAttestationService = new KeyAttestationService(new FileSystem(), logger);

        var pkcs10GenResult = await CreatePkcs10RequestWithAttestation(keyAttestationService, tpmFacade, csrFilePath, logger);

        var activatedCred = await ActivateCredential(keyAttestationService, tpmFacade, client, pkcs10GenResult, logger);

        var attestationResult = await Attestate(activatedCred, client, logger);
    }

    private static KeyAttestationV1.KeyAttestationService.KeyAttestationServiceClient CreateAttestationClient(string endpoint)
    {
        using var factory = new GrpcClientFactoryCustom<KeyAttestationV1.KeyAttestationService.KeyAttestationServiceClient>(endpoint);
        return factory.CreateClient(channel => new KeyAttestationV1.KeyAttestationService.KeyAttestationServiceClient(channel));
    }

    private static async Task<Pkcs10GenerationResult> CreatePkcs10RequestWithAttestation(
        IKeyAttestationService keyAttestationService,
        ITpm2Facade tpmFacade,
        string? csrFilePath,
        ILogger logger)
    {
        logger.LogInformation("Start generating PKCS10 certificate signing request");
        var result = await keyAttestationService.GeneratePkcs10CertificationRequest(tpmFacade, csrFilePath);
        if (result.Ek == null || result.Aik == null || result.Csr == null)
        {
            logger.LogError("Pkcs10 certificate signing request generation failed!");
            return Pkcs10GenerationResult.Empty;
        }

        logger.LogInformation("Successfully generated PKCS10 certificate request and saved it on file system!");
        return result;
    }

    private static async Task<CredentialActivationResult> ActivateCredential(
        IKeyAttestationService keyAttestationService,
        ITpm2Facade tpmFacade,
        KeyAttestationV1.KeyAttestationService.KeyAttestationServiceClient client,
        Pkcs10GenerationResult result,
        ILogger logger)
    {
        logger.LogInformation("Sending Activation Request!");
        var makeCredResponse = await client.MakeCredentialAsync(new ActivationRequest
        {
            Csr = result.Csr,
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
            return CredentialActivationResult.Empty;
        }

        activatedCred.CorrelationId = makeCredResponse.CorrelationId;

        logger.LogInformation("Activation credential successfully finished! Result: {@Content}", activatedCred);
        return activatedCred;
    }

    private static async Task<AttestationResult> Attestate(
        CredentialActivationResult activatedCred,
        KeyAttestationV1.KeyAttestationService.KeyAttestationServiceClient client,
        ILogger logger)
    {
        logger.LogInformation("Sending attestation request!");
        var attestResponse = await client.AttestAsync(new AttestationRequest
        {
            DecryptedCredentials = ByteString.CopyFrom(activatedCred.ActivatedCredentials),
            CorrelationId = activatedCred.CorrelationId
        });
        logger.LogInformation("Received Attestation Response! Result: {@Content}", attestResponse);
        return new AttestationResult(attestResponse.IsAttested, attestResponse.Message, attestResponse.Certificate);
    }
}