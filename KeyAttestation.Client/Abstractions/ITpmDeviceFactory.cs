using KeyAttestation.Client.Entities;
using Tpm2Lib;

namespace KeyAttestation.Client.Abstractions;

public interface ITpm2DeviceFactory
{
    public Tpm2Device? CreateTpm2Device(Tpm2DeviceCreationProperties properties);
}