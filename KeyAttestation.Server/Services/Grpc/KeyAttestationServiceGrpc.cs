using System.Collections.Concurrent;
using Attestation.Shared.Entities;
using Google.Protobuf;
using Grpc.Core;
using KeyAttestationV1;

namespace KeyAttestation.Server.Services.Grpc;

public class KeyAttestationServiceGrpc : KeyAttestationV1.KeyAttestationService.KeyAttestationServiceBase
{
    private readonly IKeyAttestationService _keyAttestationService;
    private readonly ILogger<KeyAttestationService> _logger;
    private static ConcurrentDictionary<int, (AttestationData Data, byte[] CredentialBlob)> _attestCandidates = new();

    public KeyAttestationServiceGrpc(IKeyAttestationService keyAttestationService, ILogger<KeyAttestationService> logger)
    {
        _keyAttestationService = keyAttestationService;
        _logger = logger;
    }
    public override async Task<AttestationResponse> Attest(AttestationRequest request, ServerCallContext context)
    {
        if (!_attestCandidates.TryGetValue(request.CorrelationId, out var candidate))
        {
            var message = $"Attestation candidate id: {request.CorrelationId} does not exist!";
            _logger.LogError("Attestation candidate id: {Correlation_ID} does not exist!", request.CorrelationId);
            return await Task.FromResult(new AttestationResponse
            {
                IsAttested = false,
                Message = message,
                Certificate = null
            });
        }

        var attestResult = await _keyAttestationService.AttestAsync(candidate.Data, context.CancellationToken);
        
        // Should be a request to CA in order to get certificate

        return await Task.FromResult(new AttestationResponse
        {
            IsAttested = attestResult.Result,
            Message = "Success",
            Certificate = "-----BEGIN CERTIFICATE-----....."
        });
    }

    public override async Task<ActivationResponse> ActivateCredentials(ActivationRequest request, ServerCallContext context)
    {
        var attestData = await _keyAttestationService.GetAttestationDataAsync(request.Csr, context.CancellationToken);
        attestData.Csr = request.Csr;
        var creds = await _keyAttestationService.MakeCredentialsAsync(attestData, request.EkPub.ToByteArray(), context.CancellationToken);
        var activationResponse = new ActivationResponse
        {
            EncryptedCredentials = ByteString.CopyFrom(creds),
            CorrelationId = 0
        };
        if (!_attestCandidates.TryAdd(activationResponse.CorrelationId, (attestData,creds)))
        {
            _logger.LogError("Fail to save attestation data!");
            return new ActivationResponse();
        }
        
        return activationResponse;
    }
}