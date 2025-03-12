using Tpm2Lib;

namespace KeyAttestation.Client.Utils;

public class TpmKey(TpmPublic? pub, TpmHandle? handle, TpmPrivate? priv = null)
{
    public TpmPublic? Public { get; set; } = pub ?? throw new ArgumentNullException(nameof(pub));
    public TpmPrivate? Private { get; set; } = priv ?? null;
    public TpmHandle? Handle { get; set; } = handle ?? throw new ArgumentNullException(nameof(handle));
}