using System.Buffers;
using KeyAttestation.Server.Services;
using Tpm2Lib;

namespace KeyAttestation.Server.Endpoints;

public class SeedEndpoint
{
    private readonly IOtpSeedService _otpSeedService;

    public SeedEndpoint(IOtpSeedService otpSeedService)
    {
        _otpSeedService = otpSeedService;
    }
    public async Task Endpoint(HttpContext context)
    {
        var readResult = await context.Request.BodyReader.ReadAsync();
        var aik = readResult.Buffer.ToArray();
        TpmPublic? ekPub = null; // Stub used to build project!! Does not work in prom environment!
        var seed = await _otpSeedService.MakeSeedBasedCredential(aik, ekPub);
        
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(seed);
        context.Response.StatusCode = 200;
    }
}