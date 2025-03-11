// See https://aka.ms/new-console-template for more information
using System.IO.Abstractions;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Google.Protobuf;
using Grpc.Net.Client;
using KeyAttestationV1;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Tls;
using Tpm2Lib;
using KeyAttestationService = KeyAttestation.Client.Services.KeyAttestationService;

var fileSystem = new FileSystem();
var logger = LoggerFactory.Create(b => b.AddConsole()).CreateLogger<KeyAttestationService>();
using var channel = GrpcChannel.ForAddress("https://localhost:8085", new GrpcChannelOptions()
{
    HttpHandler = new SocketsHttpHandler()
    {
        SslOptions = new SslClientAuthenticationOptions
        {
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            EnabledSslProtocols = SslProtocols.Tls12,
            EncryptionPolicy = EncryptionPolicy.RequireEncryption,
            RemoteCertificateValidationCallback = (_, _, _, _) => true,
        }
    }
});
var client = new KeyAttestationV1.KeyAttestationService.KeyAttestationServiceClient(channel);

using var keyAttestationService = new KeyAttestationService(fileSystem, logger, client);

logger.LogInformation("Start generating PKCS10 certificate request");
var result = await keyAttestationService.GeneratePkcs10CertificationRequestAsync(true,
    "/home/sigma.sbrf.ru@18497320/temp/openssl_test/client.csr");
logger.LogInformation("Successfully generated PKCS10 certificate request and saved it on file system!");

logger.LogInformation("Sending Activation Request!");
var makeCredResponse = await client.MakeCredentialAsync(new ActivationRequest
{
    Csr = result.Csr,
    EkPub = ByteString.CopyFrom(result.Ek!.Public)
});
logger.LogInformation(
    "Received Activation Response!Content: {@Content}", makeCredResponse);

var cred = new IdObject(makeCredResponse.IntegrityHmac.ToByteArray(), makeCredResponse.EncryptedIdentity.ToByteArray());

logger.LogInformation("Start credential activation!");
var activatedCred = await keyAttestationService.ActivateCredentialAsync(
    cred,
    makeCredResponse.EncryptedSecret.ToByteArray(),
    result.Ek,
    result.Aik!,
    CancellationToken.None);
logger.LogInformation("Activation credential successfully finished! Result: {@Result}", activatedCred);

logger.LogInformation("Sending attestation request!");
var attestResponse = await client.AttestAsync(new AttestationRequest
{
    DecryptedCredentials = ByteString.CopyFrom(activatedCred.ActivatedCredentials),
    CorrelationId = makeCredResponse.CorrelationId
});
logger.LogInformation("Received Attestation Response!Content: {@Content}", attestResponse);
