using Grpc.Core;
using KeyAttestationV1;

namespace KeyAttestation.Server.Services.Grpc;

public class KeyAttestationServiceGrpc : KeyAttestationV1.KeyAttestationService.KeyAttestationServiceBase
{
    private readonly IKeyAttestationService _keyAttestationService;

    public KeyAttestationServiceGrpc(IKeyAttestationService keyAttestationService)
    {
        _keyAttestationService = keyAttestationService;
    }
    public override async Task<AttestationResponse> Attest(AttestationRequest request, ServerCallContext context)
    {
        return await base.Attest(request, context);
    }
}