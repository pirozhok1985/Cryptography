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
var result = await keyAttestationService.GeneratePkcs10CertificationRequestAsync(true,
    "/home/sigma.sbrf.ru@18497320/temp/openssl_test/client.csr");
var makeCredResponse = await client.MakeCredentialAsync(new ActivationRequest
{
    Csr = result.Csr,
    EkPub = ByteString.CopyFrom(result.Ek!.Public)
});

var cred = new IdObject(makeCredResponse.IntegrityHmac.ToByteArray(), makeCredResponse.EncryptedIdentity.ToByteArray());
var activatedCred = await keyAttestationService.ActivateCredentialAsync(
    cred,
    makeCredResponse.EncryptedSecret.ToByteArray(),
    result.Ek,
    result.Aik!,
    CancellationToken.None);

var attestResponse = await client.AttestAsync(new AttestationRequest
{
    DecryptedCredentials = ByteString.CopyFrom(activatedCred.ActivatedCredentials),
    CorrelationId = makeCredResponse.CorrelationId
});
