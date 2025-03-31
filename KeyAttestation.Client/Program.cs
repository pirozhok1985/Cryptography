// See https://aka.ms/new-console-template for more information

using System.CommandLine;
using KeyAttestation.Client;

var tpmDeviceNameOption = new Option<string>("--tpmDevice")
{
    Description = "Tpm device to use. Could be on of the following : simulator, linux, windows",
    Arity = ArgumentArity.ExactlyOne,
    IsRequired = true
};

var csrFilePathOption = new Option<string>("--csrFilePath")
{
    Description = "Path to save CSR file.",
    Arity = ArgumentArity.ExactlyOne,
    IsRequired = false
};

var endpointOption = new Option<string>("--endpoint")
{
    Description = "Grpc endpoint to connect to.",
    Arity = ArgumentArity.ExactlyOne,
    IsRequired = true
};

var rootCommand = new RootCommand("PoC KeyAttestationClient");
rootCommand.AddOption(tpmDeviceNameOption);
rootCommand.AddOption(csrFilePathOption);
rootCommand.AddOption(endpointOption);

rootCommand.SetHandler(async (tpmDevice, csrFilePath, endPoint) =>
{
    await Worker.DoWork(tpmDevice, csrFilePath, endPoint);
}, tpmDeviceNameOption, csrFilePathOption, endpointOption);

await rootCommand.InvokeAsync(args);