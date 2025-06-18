namespace KeyAttestation.Client.Entities;

public class CredentialActivationResult
{
    public byte[] ActivatedCredentials { get; init; }
    public int CorrelationId { get; set; }
    
    public CredentialActivationResult(byte[] activatedCredentials)
    {
        ActivatedCredentials = activatedCredentials;
    }

    private CredentialActivationResult()
    {
        
    }

    public static CredentialActivationResult Empty => new();

    public override string ToString()
    {
        return $"Credential activation result: Activated credentials: {Convert.ToBase64String(ActivatedCredentials)}";
    }
}