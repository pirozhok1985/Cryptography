using System.Collections.Concurrent;
using Google.Protobuf;
using Grpc.Core;
using KeyAttestation.Server.Entities;
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
        _logger.LogInformation("Start processing Attestation request");
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

        _logger.LogInformation("Trying to compare decrypted cred with saved one");
        if (!_keyAttestationService.CheckActivatedCredentials(request.DecryptedCredentials.ToByteArray(),
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
        _logger.LogInformation("Activated credential has successfully been checked!");
        
        _logger.LogInformation("Start attesting certified data!");
        var attestResult = _keyAttestationService.Attest(candidate.Data);
        _logger.LogInformation("Attesting certified data finished! Data: {@AttestedData}", candidate.Data);
        
        // Should be a request to CA in order to get certificate
        
        _logger.LogInformation("Processing Attestation request finished!");
        return await Task.FromResult(new AttestationResponse
        {
            IsAttested = attestResult.Result,
            Message = attestResult.Message,
            Certificate = "-----BEGIN CERTIFICATE-----....."
        });
    }

    public override Task<ActivationResponse> MakeCredential(ActivationRequest request, ServerCallContext context)
    {
        _logger.LogInformation("Start processing MakeCredential request");
        var attestData = _keyAttestationService.GetAttestationData(request.Csr);
        if (attestData is null)
        {
            return Task.FromResult(new ActivationResponse());
        }
        
        attestData.Csr = request.Csr;
        
        var cred = _keyAttestationService.MakeCredential(attestData, request.EkPub.ToByteArray());
        if (cred is null)
        {
            return Task.FromResult(new ActivationResponse());
        }

        _logger.LogInformation("Making credential successfully finished! Result: {@Credential}", cred);
        var activationResponse = new ActivationResponse
        {
            EncryptedIdentity = ByteString.CopyFrom(cred.EncryptedIdentity),
            IntegrityHmac = ByteString.CopyFrom(cred.IntegrityHmac),
            EncryptedSecret = ByteString.CopyFrom(cred.EncryptedSecret),
            CorrelationId = 0
        };
        if (!_attestCandidates.TryAdd(activationResponse.CorrelationId, (attestData,cred.ClearSecret)))
        {
            _logger.LogError("Fail to save attestation data! Key is already exist!");
        }
        _logger.LogInformation("Processing MakeCredential request finished!");
        return Task.FromResult(activationResponse);
    }
}