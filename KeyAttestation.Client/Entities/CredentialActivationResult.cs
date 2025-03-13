namespace KeyAttestation.Client.Entities;

public class CredentialActivationResult
{
    public byte[] ActivatedCredentials { get; init; }
    
    public CredentialActivationResult(byte[] activatedCredentials)
    {
        ActivatedCredentials = activatedCredentials;
    }

    public override string ToString()
    {
        return $"Credential activation result: Activated credentials: {Convert.ToBase64String(ActivatedCredentials)}";
    }
}