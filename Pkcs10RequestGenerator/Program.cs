using System.CommandLine;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Pkcs10;

public static class Program
{
    static async Task Main(string[] args)
    {
        var csrSubjectOption = new Option<string>("--subject", description: "Certificate request subject")
        {
            IsRequired = true
        };

        var csrNameOption = new Option<string>("--csr-name", description: "Csr file name")
        {
            IsRequired = true
        };
        
        var keyNameOption = new Option<string>("--key-name", description: "Key file name")
        {
            IsRequired = true
        };
        
        var hostNameOption = new Option<string>("--host-name", description: "Hostname")
        {
            IsRequired = true
        };
        
        var userNameOption = new Option<string>("--user-name", description: "Username")
        {
            IsRequired = true
        };

        var rootCommand = new RootCommand("Pkcs10 request generator");
        rootCommand.AddOption(csrSubjectOption);
        rootCommand.AddOption(csrNameOption);
        rootCommand.AddOption(keyNameOption);
        rootCommand.AddOption(hostNameOption);
        rootCommand.AddOption(userNameOption);

        rootCommand.SetHandler(async (subject, csrName, keyName, hostName, userName) =>
        {
            await Pkcs10Generator.Generate(subject, csrName, keyName, hostName, userName);
        }, csrSubjectOption, csrNameOption, keyNameOption, hostNameOption, userNameOption);
        await rootCommand.InvokeAsync(args);
    }
}