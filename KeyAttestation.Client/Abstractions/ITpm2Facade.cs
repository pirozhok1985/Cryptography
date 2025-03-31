using KeyAttestation.Client.Entities;
using KeyAttestation.Client.Utils;
using Tpm2Lib;

namespace KeyAttestation.Client.Abstractions;

public interface ITpm2Facade : IDisposable
{
    public Tpm2? Tpm { get; init; }
    
    /// <summary>
    /// Create regular 2048 bits Rsa key pair with Sha256
    /// </summary>
    /// <param name="parent">Parent key handle</param>
    /// <returns>TpmKey: TpmPublic, TpmPrivate, TpmHandle</returns>
    public Tpm2Key? CreateRsaKey(TpmHandle parent);
    
    /// <summary>
    /// Create Authority Identity Key using default AIK template
    /// </summary>
    /// <param name="parent">Parent key handle</param>
    /// <returns>TpmKey: TpmPublic, TpmPrivate, TpmHandle</returns>
    public Tpm2Key? CreateAk(TpmHandle parent);
    
    /// <summary>
    /// Create Endorsement Key using default endorsement key template
    /// </summary>
    /// <returns>TpmKey: TpmPublic, TpmHandle</returns>
    public Tpm2Key? CreateEk();
}