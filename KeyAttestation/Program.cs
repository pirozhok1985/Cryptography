// See https://aka.ms/new-console-template for more information

using System.IO.Abstractions;
using KeyAttestation.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var hostBuilder = Host.CreateApplicationBuilder();

hostBuilder.Services.AddSingleton<IFileSystem, FileSystem>();
hostBuilder.Services.AddScoped<IKeyAttestationService, KeyAttestationService>();
hostBuilder.Services.AddHttpClient<KeyAttestationService>(client =>
{
    client.BaseAddress = new Uri("http://localhost:8080");
});

