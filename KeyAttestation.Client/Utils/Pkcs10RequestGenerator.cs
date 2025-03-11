using System.Security.Cryptography;
using Attestation.Shared;
using Attestation.Shared.Entities;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using ContentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo;
using SignedData = Org.BouncyCastle.Asn1.Cms.SignedData;
using SignerInfo = Org.BouncyCastle.Asn1.Cms.SignerInfo;

namespace KeyAttestation.Client.Utils;

public static class Pkcs10RequestGenerator
{
    public static Pkcs10CertificationRequest Generate(AsymmetricKeyParameter publicKey, AsymmetricKeyParameter privateKey,  SignedData signedData)
    {
        var x509Name =
            new X509Name("CN=18497320,OU=Users,OU=LinuxUser,E=eeanisimov@sberbank.ru,DC=sigma,DC=sbrf,DC=ru");
        var osVersionAttr = new DerSequence(new DerObjectIdentifier("1.3.6.1.4.1.311.13.2.3"),
            new DerSet(new DerIA5String("10.0.19045.2")));
        var clientInfo = new DerSequence(new DerObjectIdentifier("1.3.6.1.4.1.311.21.20"),
            new DerSet(
                new DerSequence(
                    new DerInteger(09),
                    new DerUtf8String(Environment.MachineName),
                    new DerUtf8String($"SIGMA\\{Environment.UserName}"),
                    new DerUtf8String("attestation_generator.exe"))));
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
        var attestationStatement = new DerSequence(
            new DerObjectIdentifier("1.3.6.1.4.1.311.21.24"),
            new DerSet(
                new DerSequence(new DerObjectIdentifier("1.2.840.113549.1.7.2"), signedData)));
        var attributes = new DerSet(osVersionAttr, clientInfo, enrollmentCsp, certificateExtensions, attestationStatement);
        var signatureAlg = "SHA1WITHRSA";
        return new Pkcs10CertificationRequest(signatureAlg, x509Name, publicKey, attributes, privateKey);
    }

    public static SignedData GenerateCms(byte[] sigData, byte[] attestationStatement, byte[] publicKey, TpmKey aik)
    {
        var aikPublicKey = Helpers.ToAsymmetricKeyParameter(aik, false);
        var subjectPubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(aikPublicKey);
        var ski = new SubjectKeyIdentifier(subjectPubInfo);
        var signerId = new SignerIdentifier(ski.ToAsn1Object());
        var signerInfoDgstAlg = new AlgorithmIdentifier(new DerObjectIdentifier("2.16.840.1.101.3.4.2.1"));
        var sigAlg = new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption);
        var signature = new DerOctetString(sigData);
        var signedAttributes = new DerSet();
        var unsignedAttributes = new DerSet();
        var signerInfo = new SignerInfo(signerId, signerInfoDgstAlg, Asn1Set.GetInstance(signedAttributes), sigAlg, signature, Asn1Set.GetInstance(unsignedAttributes));
        
        var digestAlgId = new DerObjectIdentifier("2.16.840.1.101.3.4.2.1");
        return new SignedData(
            new DerSet(digestAlgId),
            new ContentInfo(
                new DerObjectIdentifier("1.2.840.113549.1.7.1"),
                    new DerOctetString(attestationStatement)),
            new DerSet(                    
                new DerSequence(new DerObjectIdentifier("2.23.133.8.12"), new DerOctetString(publicKey)), // tcg-at-tpmSecurityTarget
                new DerSequence(new DerObjectIdentifier("2.23.133.8.3"), new DerOctetString(aik.Public))), // tcg-kp-AIKCertificate,
            new DerSet(),
            new DerSet(signerInfo));
    }
}