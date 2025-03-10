namespace Attestation.Shared.Entities;

public class Pksc10GenerationResult
{
    public string? Csr { get; set; }
    public TpmKey? Ek { get; set; }
    public TpmKey? Aik { get; set; }
}