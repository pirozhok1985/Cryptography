namespace KeyAttestation.Client.Entities;

public static class TpmConstants
{
    public const uint StartNvIndex = 0x01 << 24;
    public const uint EndNvIndex = StartNvIndex + 0x01ffffff;
   public enum EkNvIndex {
        RsaEkCertNvIndex = 0x01C00002,
        EccEkCertNvIndex = 0x01C0000A,
        Rsa2048EkCertNvIndex = 0x01C00012,
        Rsa3072EkCertNvIndex = 0x01C0001C,
        Rsa4096EkCertNvIndex = 0x01C0001E,
        EccNistP256EkCertNvIndex = 0x01C00014,
        EccNistP384EkCertNvIndex = 0x01C00016,
        EccNistP521EkCertNvIndex = 0x01C00018,
        EccSm2P256EkCertNvIndex = 0x01C0001A,
    };
}