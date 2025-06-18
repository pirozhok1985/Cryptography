using KeyAttestation.Client.Abstractions;
using KeyAttestation.Client.Entities;
using Microsoft.Extensions.Logging;
using Tpm2Lib;

namespace KeyAttestation.Client.Factories;

public static class Tpm2DeviceFactory<TTpm2Device>
{
    public static Tpm2Device? CreateTpm2Device(Tpm2DeviceCreationProperties properties)
    {
        if (typeof(TTpm2Device) == typeof(LinuxTpmDevice))
        {
            return new LinuxTpmDevice(properties.DeviceName);
        }
        
        if (typeof(TTpm2Device) == typeof(TcpTpmDevice))
        {
            return new TcpTpmDevice(properties.ServerName, properties.ServerPort);
        }
        
        if (typeof(TTpm2Device) == typeof(TbsDevice))
        {
            return new TbsDevice();
        }

        return null;
    }
}