// See https://aka.ms/new-console-template for more information
using System.IO.Abstractions;
using Google.Protobuf;
using Grpc.Net.Client;
using KeyAttestationV1;
using Microsoft.Extensions.Logging;
using KeyAttestationService = KeyAttestation.Client.Services.KeyAttestationService;

var fileSystem = new FileSystem();
var logger = LoggerFactory.Create(b => b.AddConsole()).CreateLogger<KeyAttestationService>();
using var channel = GrpcChannel.ForAddress("http://localhost:8080");
var client = new KeyAttestationV1.KeyAttestationService.KeyAttestationServiceClient(channel);

using var keyAttestationService = new KeyAttestationService(fileSystem, logger, client);
var result = await keyAttestationService.GeneratePkcs10CertificationRequestAsync(true,
    "/home/sigma.sbrf.ru@18497320/temp/openssl_test/client.csr");
var response = await client.ActivateCredentialsAsync(new ActivationRequest
{
    Csr = result.Csr,
    EkPub = ByteString.CopyFrom(result.Ek!.Public)
});
