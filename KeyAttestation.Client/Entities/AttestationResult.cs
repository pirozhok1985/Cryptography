namespace KeyAttestation.Client.Entities;

public class AttestationResult(bool isAttested, string? message, string? certificate)
{
    public bool IsAttested { get; set; } = isAttested;
    public string? Message { get; set; } = message;
    public string? Certificate { get; set; } = certificate;
}