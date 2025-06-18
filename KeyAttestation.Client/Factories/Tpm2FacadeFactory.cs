using KeyAttestation.Client.Abstractions;
using KeyAttestation.Client.Entities;
using Microsoft.Extensions.Logging;
using Tpm2Lib;

namespace KeyAttestation.Client.Factories;

public static class Tpm2FacadeFactory
{
        public static ITpm2Facade CreateTpm2Facade(string deviceName, ILogger logger)
        => deviceName switch
        {
            "simulator" => new Tpm2Facade<TcpTpmDevice>(logger, new Tpm2DeviceCreationProperties()
            {
                ServerName = "localhost",
                ServerPort = 2322
            }),

            "linux" => new Tpm2Facade<LinuxTpmDevice>(logger, new Tpm2DeviceCreationProperties()
            {
                DeviceName = "/dev/tpmrm0"
            }),

            "windows" => new Tpm2Facade<TbsDevice>(logger, new Tpm2DeviceCreationProperties()),
            
            _ => throw new ArgumentOutOfRangeException(nameof(deviceName), deviceName, "Unrecognized device type")
        };
}
