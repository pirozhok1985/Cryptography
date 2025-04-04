using Google.Protobuf;
using Grpc.Core;
using KeyAttestation.Server.Abstractions;
using OtpSeedV1;

namespace KeyAttestation.Server.Services.Grpc;

public class OtpSeedServiceGrpc : OtpSeedV1.OtpSeedService.OtpSeedServiceBase
{
    private readonly IOtpSeedService _otpSeedService;

    public OtpSeedServiceGrpc(IOtpSeedService otpSeedService)
    {
        _otpSeedService = otpSeedService;
    }
    public override Task<SeedResponse> GetOtpSeed(SeedRequest request, ServerCallContext context)
    {
        var aikName = request.AikName.ToByteArray();
        var ekPub = request.EkPub.ToByteArray();
        var credential = _otpSeedService.MakeSeedBasedCredential(aikName, ekPub);
        return credential == Array.Empty<byte>() 
            ? Task.FromResult(new SeedResponse()) 
            : Task.FromResult(new SeedResponse { IdObject = ByteString.CopyFrom(credential) });
    }
}