using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Grpc.Net.Client;
using KeyAttestationV1;

namespace KeyAttestation.Client.Factories;

public class KeyAttestationGrpcClientFactory : IDisposable
{
    private readonly GrpcChannel? _channel;
    private bool _isDisposed;
    
    public KeyAttestationGrpcClientFactory(string address)
    {
        ArgumentNullException.ThrowIfNull(address);
        _channel = GrpcChannel.ForAddress(address, new GrpcChannelOptions()
        {
            HttpHandler = new SocketsHttpHandler
            {
                SslOptions = new SslClientAuthenticationOptions
                {
                    CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                    EnabledSslProtocols = SslProtocols.Tls12,
                    EncryptionPolicy = EncryptionPolicy.RequireEncryption,
                    RemoteCertificateValidationCallback = (_, _, _, _) => true,
                }
            }
        });
    }
    public KeyAttestationService.KeyAttestationServiceClient CreateClient()
    {
        return new KeyAttestationService.KeyAttestationServiceClient(_channel);
    }

    public void Dispose()
    {
        if (_isDisposed)
        {
            return;
        }
        _channel?.Dispose();
        _isDisposed = true;
    }
}