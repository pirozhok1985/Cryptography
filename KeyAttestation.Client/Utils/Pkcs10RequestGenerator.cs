using KeyAttestation.Client.Entities;
using KeyAttestation.Client.Extensions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using SignedData = Org.BouncyCastle.Asn1.Cms.SignedData;

namespace KeyAttestation.Client.Utils;

public static class Pkcs10RequestGenerator
{
    public static Pkcs10CertificationRequestDelaySigned Generate(Tpm2Key clientKey, Tpm2Key aik, Tpm2Key ek, SignedData signedData)
    {
        var clientRsaPubKey = clientKey.ToRsaKeyParameter();
        var x509Name =
            new X509Name("CN=test_user,OU=Users,OU=LinuxUser,E=test_user@lab.local,DC=lab,DC=local");
        var osVersionAttr = new DerSequence(new DerObjectIdentifier("1.3.6.1.4.1.311.13.2.3"),
            new DerSet(new DerIA5String("10.0.19045.2")));
        var clientInfo = new DerSequence(new DerObjectIdentifier("1.3.6.1.4.1.311.21.20"),
            new DerSet(
                new DerSequence(
                    new DerInteger(09),
                    new DerUtf8String(Environment.MachineName),
                    new DerUtf8String($"LAB\\{Environment.UserName}"),
                    new DerUtf8String("attestation_generator.exe"))));
        var enrollmentCsp = new DerSequence(new DerObjectIdentifier("1.3.6.1.4.1.311.13.2.2"),
            new DerSet(
                new DerSequence(
                    new DerInteger(01),
                    new DerBmpString("Microsoft Base Smart Card Crypto Provider"))));
        var subjectPubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(clientRsaPubKey);
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
                new DerSequence(
                    new ContentInfo(new DerObjectIdentifier("1.2.840.113549.1.7.2"), signedData),
                    new DerSequence(
                        new SubjectPublicKeyInfo(
                            new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption),
                            new DerBitString(ek.Public)),
                        new SubjectPublicKeyInfo(
                            new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption),
                            new DerBitString(aik.Public)),
                        new SubjectPublicKeyInfo(
                            new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption),
                            new DerBitString(clientKey.Public)))))); 
        var attributes = new DerSet(osVersionAttr, clientInfo, enrollmentCsp, certificateExtensions, attestationStatement);
        var signatureAlg = "SHA1WITHRSAANDMGF1";
        return new Pkcs10CertificationRequestDelaySigned(signatureAlg, x509Name, clientRsaPubKey, attributes);
    }
}