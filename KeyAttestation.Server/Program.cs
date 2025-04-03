using KeyAttestation.Server.Abstractions;
using KeyAttestation.Server.Endpoints;
using KeyAttestation.Server.Services;
using KeyAttestation.Server.Services.Grpc;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddGrpc();
builder.Services.AddScoped<IKeyAttestationService, KeyAttestationService>();
builder.Services.AddScoped<IOtpSeedService, OtpSeedService>();
var app = builder.Build();

app.MapGrpcService<KeyAttestationServiceGrpc>();
app.MapPost("seed", async (context) => await SeedEndpoint.Endpoint(context));

app.Run();