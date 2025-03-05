using System.Formats.Asn1;
using KeyAttestation.Server.Entities;
using KeyAttestation.Server.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Tpm2Lib;

namespace KeyAttestation.Server.Services;

public class AttestationService : IAttestationService
{
    private readonly ILogger<AttestationService> _logger;

    public AttestationService(ILogger<AttestationService> logger)
    {
        _logger = logger;
    }
    public Task<AttestationResult> AttestAsync(string csr, CancellationToken cancellationToken = default)
    {
        var certificationRequest = Helpers.FromPemCsr(csr, _logger);
        if (certificationRequest is null)
        {
            return Task.FromResult(new AttestationResult
            {
                Result = false,
                Message = "Unable to parse PKCS#10 certificate request!"
            });
        }

        var info = certificationRequest.GetCertificationRequestInfo();
        var attestationStatement = (SignedData)info.Attributes
            .First(x => x.GetType() == typeof(DerSequence) 
                        && ((DerSequence)x).Parser.ReadObject() is SignedData);

        var content = attestationStatement.EncapContentInfo.Content as BerSequence;
        var attestBerOctetString = content!.Parser.ReadObject() as BerOctetString;
        var attestBytes = attestBerOctetString!.GetOctets();
        var result = AsnDecoder.ReadOctetString(attestBytes.AsSpan(), AsnEncodingRules.BER, out _);
        var attest = Marshaller.FromTpmRepresentation<Attest>(result);

        return Task.FromResult(new AttestationResult());
    }
}