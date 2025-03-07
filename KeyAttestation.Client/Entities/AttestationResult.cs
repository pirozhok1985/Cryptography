namespace KeyAttestation.Client.Entities;

public class AttestationResult
{
    public bool Result { get; set; }
    
    public string? Message { get; set; }
    
    public string? Certificate { get; set; }
}