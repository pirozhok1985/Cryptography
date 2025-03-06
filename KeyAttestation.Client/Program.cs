// See https://aka.ms/new-console-template for more information
using System.IO.Abstractions;
using KeyAttestation.Client.Services;
using Microsoft.Extensions.Logging;

var fileSystem = new FileSystem();
var logger = LoggerFactory.Create(b => b.AddConsole()).CreateLogger<KeyAttestationService>();
using var httpClient = new HttpClient();
httpClient.BaseAddress = new Uri("http://localhost:8080");

using var keyAttestationService = new KeyAttestationService(fileSystem, logger, httpClient);
await keyAttestationService.GeneratePkcs10CertificationRequestAsync(true,
    "/home/sigma.sbrf.ru@18497320/temp/openssl_test/client.csr");
