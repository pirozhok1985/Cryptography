using Tpm2Lib;

namespace KeyAttestation.Client.Entities;

public class Tpm2DeviceCreationProperties
{
    public string? DeviceName { get; set; }
    public string? ServerName { get; set; }
    public int ServerPort { get; set; }
}