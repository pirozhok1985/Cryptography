using KeyAttestation.Client.Entities;
using Tpm2Lib;

namespace KeyAttestation.Client.Abstractions;

public interface ISeedTpmService
{
    public Tpm2Key? ImportSeedToTpm(ITpm2Facade tpm2Facade, byte[] seed, string pin);
}