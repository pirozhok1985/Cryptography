namespace KeyAttestation.Server.Entities;

public class Credential
{
   public byte[] EncryptedIdentity { get; init; }
   public byte[] IntegrityHmac { get; init; }
   public byte[] EncryptedSecret { get; init; }
   public byte[] ClearSecret { get; init; }

   public Credential(byte[] encryptedIdentity, byte[] encryptedSecret, byte[] clearSecret, byte[] integrityHmac)
   {
      EncryptedIdentity = encryptedIdentity;
      EncryptedSecret = encryptedSecret;
      ClearSecret = clearSecret;
      IntegrityHmac = integrityHmac;
   }

   public override string ToString()
   {
      return $"Credential:\n\tEncryptedIdentity = {Convert.ToBase64String(EncryptedIdentity)}\n\tIntegrityHmac = {Convert.ToBase64String(IntegrityHmac)}\n\tEncryptedSecret = {Convert.ToBase64String(EncryptedSecret)}\n\tClearSecret = {Convert.ToBase64String(ClearSecret)}";
   }
}