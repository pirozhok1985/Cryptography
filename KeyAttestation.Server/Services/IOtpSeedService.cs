using KeyAttestation.Server.Entities;
using Tpm2Lib;

namespace KeyAttestation.Server.Services;

public interface IOtpSeedService
{
    public Task<byte[]> MakeSeedBasedCredential(byte[] aikName, TpmPublic ekPub);
}