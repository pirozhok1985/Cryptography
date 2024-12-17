using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.X509;

namespace Pkcs10;

public static class Pkcs10Generator
{
    public static async Task Generate(string subject, string csrName, string keyName, string hostName, string userName)
    {
        var keyRandomGenerator = new CryptoApiRandomGenerator();
        var keyPairGenerator = new RsaKeyPairGenerator();
        var keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(keyRandomGenerator), 2048);
        keyPairGenerator.Init(keyGenerationParameters);
        var keyPair = keyPairGenerator.GenerateKeyPair();
        
        var x509Name = new X509Name(subject);
        
        var publicKey = keyPair.Public;
        var privateKey = keyPair.Private;
        var osVersion = new DerSequence(new DerObjectIdentifier("1.3.6.1.4.1.311.13.2.3"),
            new DerSet(new DerIA5String(Environment.OSVersion.VersionString)));
        var clientInfo = new DerSequence(new DerObjectIdentifier("1.3.6.1.4.1.311.21.20"),
            new DerSet(
                new DerSequence(
                    new DerInteger(09),
                    new DerUtf8String(hostName),
                    new DerUtf8String($"SIGMA\\{userName}"),
                    new DerUtf8String("certreq.exe"))));
        var enrollmentCsp = new DerSequence(new DerObjectIdentifier("1.3.6.1.4.1.311.13.2.2"),
            new DerSet(
                new DerSequence(
                    new DerInteger(01),
                    new DerBmpString("Microsoft Base Smart Card Crypto Provider"),
                    new DerBitString(0))));
        var subjectPubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
        var certificateExtensions = new DerSequence(
            new DerObjectIdentifier("1.2.840.113549.1.9.14"),
            new DerSet(
                new DerSequence(
                    new DerSequence(
                        X509Extensions.SubjectKeyIdentifier,
                        new DerOctetString(SubjectKeyIdentifier.CreateSha1KeyIdentifier(subjectPubInfo))),
                    new DerSequence(
                        X509Extensions.KeyUsage,
                        DerBoolean.True,
                        new DerOctetString(new KeyUsage(KeyUsage.KeyEncipherment))))));
        var attributes = new DerSet(osVersion, clientInfo, enrollmentCsp, certificateExtensions);
        var signatureAlg = "SHA256WITHRSA";

        var request = new Pkcs10CertificationRequest(signatureAlg, x509Name, publicKey, attributes, privateKey);
        
        await CreatePemFile(csrName, request);
        await CreatePemFile(keyName, keyPair);
    }

    private static async Task CreatePemFile(string fileName, object content)
    {
        await using var stringWriter = new StringWriter();
        using var pemWriter = new PemWriter(stringWriter);
        pemWriter.WriteObject(content);
        await File.WriteAllTextAsync(fileName, stringWriter.ToString());
    }
}