using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Grpc.Core;
using Grpc.Net.Client;
using KeyAttestationV1;

namespace KeyAttestation.Client.Factories;

public class GrpcClientFactoryCustom<TClient> : IDisposable where TClient : ClientBase<TClient>
{
    private readonly GrpcChannel? _channel;
    private bool _isDisposed;
    
    public GrpcClientFactoryCustom(string address)
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
    public TClient CreateClient(Func<GrpcChannel, TClient> factory)
    {
        return factory.Invoke(_channel!);
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