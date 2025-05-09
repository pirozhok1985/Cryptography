using Tpm2Lib;

namespace KeyAttestation.Client.Entities;

public class Tpm2Key(TpmPublic? pub, TpmHandle? handle, TpmPrivate? priv = null)
{
    public TpmPublic? Public { get; set; } = pub ?? throw new ArgumentNullException(nameof(pub));
    public TpmPrivate? Private { get; set; } = priv ?? null;
    public TpmHandle? Handle { get; set; } = handle ?? throw new ArgumentNullException(nameof(handle));
}