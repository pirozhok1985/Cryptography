using System.Buffers;
using KeyAttestation.Server.Abstractions;
using KeyAttestation.Server.Services;
using Tpm2Lib;

namespace KeyAttestation.Server.Endpoints;

public static class SeedEndpoint
{
    public static async Task Endpoint(HttpContext context)
    {
        var otpSeedService = context.RequestServices.GetRequiredService<IOtpSeedService>();
        var readResult = await context.Request.BodyReader.ReadAsync();
        var aik = readResult.Buffer.ToArray();
        TpmPublic? ekPub = null;
        var seed = await otpSeedService.MakeSeedBasedCredential(aik, ekPub);
        
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(Convert.ToBase64String(seed));
        context.Response.StatusCode = 200;
    }
}