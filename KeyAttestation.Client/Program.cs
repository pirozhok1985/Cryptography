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

var commandAttest = new Command("attest", "PoC KeyAttestationClient");
commandAttest.AddOption(tpmDeviceNameOption);
commandAttest.AddOption(csrFilePathOption);
commandAttest.AddOption(endpointOption);
commandAttest.SetHandler(async (tpmDevice, csrFilePath, endPoint) =>
{
    await WorkerAttest.DoWork(tpmDevice, csrFilePath, endPoint);
}, tpmDeviceNameOption, csrFilePathOption, endpointOption);

var commandOtp = new Command("otp", "PoC Store seed in tpm device");
commandOtp.AddOption(endpointOption);
commandOtp.AddOption(tpmDeviceNameOption);
commandOtp.SetHandler(async (tpmDevice, endPoint) =>
{
    await WorkerOtp.DoWork(tpmDevice,endPoint);
}, tpmDeviceNameOption, endpointOption);

var rootCommand = new RootCommand("Cli testing util")
{
    commandAttest,
    commandOtp
};

await rootCommand.InvokeAsync(args);