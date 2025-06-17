using System;
using Microsoft.Extensions.Logging;

namespace KeyAttestation.Client.Abstractions;

public interface ITpm2FacadeFactory
{
    public ITpm2Facade CreateTpm2Facade(string deviceName, ILogger logger);
}
