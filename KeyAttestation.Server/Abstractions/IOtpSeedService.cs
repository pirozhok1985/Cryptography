using Tpm2Lib;

namespace KeyAttestation.Server.Abstractions;

public interface IOtpSeedService
{
    public Task<byte[]> MakeSeedBasedCredential(byte[] aikName, TpmPublic ekPub);
}