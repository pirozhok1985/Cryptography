using KeyAttestation.Server.Entities;
using KeyAttestation.Server.Services;
using Microsoft.AspNetCore.Mvc;

namespace KeyAttestation.Server.Controllers;

public class AttestationController : ControllerBase
{
    [HttpPost("/csr")]
    public async Task<ActionResult<AttestationResult>> ValidateCertificationRequest(string request, IAttestationService attestationService)
    {
       var attestationResult = await attestationService.AttestAsync(request);
       if (attestationResult.Result)
       {
           return Ok(attestationResult);
       }

       return ValidationProblem(new ValidationProblemDetails
       {
           Type = "https://tools.ietf.org/html/rfc7231#section-6.5.1",
           Title = "Validation Error",
           Status = 400,
           Detail = attestationResult.Message,
       });
    }
}