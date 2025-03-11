namespace Attestation.Shared.Entities;

public class Credendtial
{
   public byte[] CredentialBlob { get; init; }
   public byte[] EncryptedSecret { get; init; }
   public byte[] ClearSecret { get; init; }

   public Credendtial(byte[] credentialBlob, byte[] encryptedSecret, byte[] clearSecret)
   {
      CredentialBlob = credentialBlob;
      EncryptedSecret = encryptedSecret;
      ClearSecret = clearSecret;
   }
}