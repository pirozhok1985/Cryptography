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
    static void Main(string[] args)
    {
        if (args.Length < 5)
        {
            Console.WriteLine("Usage: Pkcs10RequestGenerator <subject> <csr_name> <key_name> <hostname> <username>");
            return;
        }

        var keyRandomGenerator = new CryptoApiRandomGenerator();
        var keyPairGenerator = new RsaKeyPairGenerator();
        var keyGenerationParameters = new KeyGenerationParameters(new SecureRandom(keyRandomGenerator), 2048);
        keyPairGenerator.Init(keyGenerationParameters);
        var keyPair = keyPairGenerator.GenerateKeyPair();

        X509Name subject;
        try
        {
            subject = new X509Name(args[0]);
        }
        catch (Exception e)
        {
            Console.WriteLine("X509Name format is incorrect!");
            return;
        }
        
        var publicKey = keyPair.Public;
        var privateKey = keyPair.Private;
        var osVersionAttr = new DerSequence(new DerObjectIdentifier("1.3.6.1.4.1.311.13.2.3"),
            new DerSet(new DerIA5String("10.0.19045.2")));
        var clientInfo = new DerSequence(new DerObjectIdentifier("1.3.6.1.4.1.311.21.20"),
            new DerSet(
                new DerSequence(
                    new DerInteger(09),
                    new DerUtf8String(args[3]),
                    new DerUtf8String($"SIGMA\\{args[4]}"),
                    new DerUtf8String("certreq.exe"))));
        var enrollmentCsp = new DerSequence(new DerObjectIdentifier("1.3.6.1.4.1.311.13.2.2"),
            new DerSet(
                new DerSequence(
                    new DerInteger(01),
                    new DerBmpString("Microsoft Base Smart Card Crypto Provider"))));
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
        var attributes = new DerSet(osVersionAttr, clientInfo, enrollmentCsp, certificateExtensions);
        var signatureAlg = "SHA1WITHRSA";

        var request = new Pkcs10CertificationRequest(signatureAlg, subject, publicKey, attributes, privateKey);
        using var csrWriter = new StringWriter();
        using var keyWriter = new StringWriter();
        using var pemCsrWriter = new PemWriter(csrWriter);
        using var pemKeyWriter = new PemWriter(keyWriter);
        pemCsrWriter.WriteObject(request);
        File.WriteAllText(args[1], csrWriter.ToString());
        pemCsrWriter.Writer.Flush();
        pemKeyWriter.WriteObject(keyPair);
        File.WriteAllText(args[2], keyWriter.ToString());
        pemKeyWriter.Writer.Flush();
    }
}