using KeyAttestation.Server.Entities;

namespace KeyAttestation.Server.Abstractions;

public interface IOtpSeedService
{
    public Credential? MakeSeedBasedCredential(byte[] aikName, byte[] ekPub);
}