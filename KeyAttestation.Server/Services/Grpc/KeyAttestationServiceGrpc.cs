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
            _logger.LogError("Attestation candidate id: {Correlation_ID} does not exist!", request.CorrelationId);
            return await Task.FromResult(new AttestationResponse
            {
                IsAttested = false,
                Message = $"Attestation candidate id: {request.CorrelationId} does not exist!",
                Certificate = null
            });
        }

        if (_keyAttestationService.CheckActivatedCredentials(request.DecryptedCredentials.ToByteArray(),
                candidate.CredentialBlob))
        {
            _logger.LogError("Credential activation failed!");
            return await Task.FromResult(new AttestationResponse
            {
                IsAttested = false,
                Message = "Credential activation failed!",
                Certificate = null
            });
        }

        var attestResult = _keyAttestationService.AttestAsync(candidate.Data);
        
        // Should be a request to CA in order to get certificate

        return await Task.FromResult(new AttestationResponse
        {
            IsAttested = attestResult.Result,
            Message = attestResult.Message,
            Certificate = "-----BEGIN CERTIFICATE-----....."
        });
    }

    public override Task<ActivationResponse> MakeCredentials(ActivationRequest request, ServerCallContext context)
    {
        var attestData = _keyAttestationService.GetAttestationDataAsync(request.Csr);
        attestData.Csr = request.Csr;
        var creds = _keyAttestationService.MakeCredentialsAsync(attestData, request.EkPub.ToByteArray());
        var activationResponse = new ActivationResponse
        {
            EncryptedCredentials = ByteString.CopyFrom(creds),
            CorrelationId = 0
        };
        if (!_attestCandidates.TryAdd(activationResponse.CorrelationId, (attestData,creds)))
        {
            _logger.LogError("Fail to save attestation data!");
            return Task.FromResult(new ActivationResponse());
        }
        
        return Task.FromResult(activationResponse);
    }
}