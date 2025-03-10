using Google.Protobuf;
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

    public override async Task<ActivationResponse> ActivateCredentials(ActivationRequest request, ServerCallContext context)
    {
        var attestData = await _keyAttestationService.GetAttestationDataAsync(request.Csr);
        var creds = await _keyAttestationService.MakeCredentialsAsync(attestData, request.EkPub.ToByteArray());
        return new ActivationResponse
        {
            EncryptedCredentials = ByteString.CopyFrom(creds),
            CorrelationId = 0
        };
    }
}