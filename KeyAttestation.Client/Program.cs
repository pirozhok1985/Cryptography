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

var seedPrivateOption = new Option<string>("--seedPrivate")
{
    Description = "Private portion of imported seed",
    Arity = ArgumentArity.ExactlyOne,
    IsRequired = false
};

var seedPublicOption = new Option<string>("--seedPublic")
{
    Description = "Public portion of imported seed",
    Arity = ArgumentArity.ExactlyOne,
    IsRequired = false
};

var seedPinOption = new Option<string>("--pin")
{
    Description = "Pin required to import seed to tpm",
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
commandOtp.AddOption(seedPrivateOption);
commandOtp.AddOption(seedPublicOption);
commandOtp.AddOption(seedPinOption);
commandOtp.SetHandler(async (tpmDevice, endPoint, seedPublic, seedPrivate, seedPin) =>
{
    await WorkerOtp.DoWork(tpmDevice,endPoint, seedPin, seedPublic, seedPrivate);
}, tpmDeviceNameOption, endpointOption, seedPublicOption, seedPrivateOption, seedPinOption);

var rootCommand = new RootCommand("Cli testing util")
{
    commandAttest,
    commandOtp
};

await rootCommand.InvokeAsync(args);