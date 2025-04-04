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
    public override async Task<SeedResponse> GetOtpSeed(SeedRequest request, ServerCallContext context)
    {
        var aikName = request.AikName.ToByteArray();
        var ekPub = request.EkPub.ToByteArray();
        var credential = await _otpSeedService.MakeSeedBasedCredential(aikName, ekPub);
        return new SeedResponse()
        {
            Credential = ByteString.CopyFrom(credential),
        };
    }
}