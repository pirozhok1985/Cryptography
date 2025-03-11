namespace Attestation.Shared.Entities;

public class Credendtial
{
   public byte[] EncryptedIdentity { get; init; }
   public byte[] IntegrityHmac { get; init; }
   public byte[] EncryptedSecret { get; init; }
   public byte[] ClearSecret { get; init; }

   public Credendtial(byte[] encryptedIdentity, byte[] encryptedSecret, byte[] clearSecret, byte[] integrityHmac)
   {
      EncryptedIdentity = encryptedIdentity;
      EncryptedSecret = encryptedSecret;
      ClearSecret = clearSecret;
      IntegrityHmac = integrityHmac;
   }
}