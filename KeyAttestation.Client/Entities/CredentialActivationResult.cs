namespace KeyAttestation.Client.Entities;

public class CredentialActivationResult
{
    public byte[]? ActivatedCredentials { get; init; }
    
    public CredentialActivationResult(byte[]? activatedCredentials)
    {
        ActivatedCredentials = activatedCredentials;
    }

    private CredentialActivationResult()
    {
        
    }
    
    public static CredentialActivationResult Empty => new () ;
}