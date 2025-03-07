using KeyAttestation.Server.Services;
using KeyAttestation.Server.Services.Grpc;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddGrpc();
builder.Services.AddScoped<IKeyAttestationService, KeyAttestationService>();
var app = builder.Build();

app.MapGrpcService<KeyAttestationServiceGrpc>();

app.Run();