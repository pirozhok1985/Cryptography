using Tpm2Lib;

namespace KeyAttestation.Server.Abstractions;

public interface IOtpSeedService
{
    public byte[] MakeSeedBasedCredential(byte[] aikName, byte[] ekPub);
}