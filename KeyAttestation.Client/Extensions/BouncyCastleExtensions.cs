using System.IO.Abstractions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;

namespace KeyAttestation.Client.Extensions;

public static class BouncyCastleExtensions
{
    public static async Task<string> ConvertPkcs10RequestToPem(this Pkcs10CertificationRequest request)
    {
        await using var textWriter = new StringWriter();
        using var pemWriter = new PemWriter(textWriter);
        pemWriter.WriteObject(request);
        return textWriter.ToString();
    }
    
    public static async Task WriteCsrAsync(
        this Pkcs10CertificationRequest request,
        string? fileName,
        IFile fileWriter,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        var requestPem =await request.ConvertPkcs10RequestToPem();
        await fileWriter.WriteAllTextAsync(fileName, requestPem, cancellationToken);
    }
}