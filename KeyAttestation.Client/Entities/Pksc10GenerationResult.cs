using KeyAttestation.Client.Utils;

namespace KeyAttestation.Client.Entities;

public class Pksc10GenerationResult
{
    public string? Csr { get; set; }
    public Tpm2Key? Ek { get; set; }
    public Tpm2Key? Aik { get; set; }

    public static Pksc10GenerationResult Empty => new();
}