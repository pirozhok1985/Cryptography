using KeyAttestation.Client.Entities;
using KeyAttestation.Client.Extensions;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using ContentInfo = Org.BouncyCastle.Asn1.Cms.ContentInfo;
using SignedData = Org.BouncyCastle.Asn1.Cms.SignedData;
using SignerInfo = Org.BouncyCastle.Asn1.Cms.SignerInfo;

namespace KeyAttestation.Client.Utils;

public static class SignedDataGenerator
{
    public static SignedData GenerateCms(byte[] sigData, byte[] attestationStatement, byte[] ekCert, Tpm2Key aik)
    {
        var aikKey = aik.ToRsaKeyParameter();
        var subjectPubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(aikKey);
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
                new DerSequence(new DerObjectIdentifier("2.23.133.8.1"), new DerOctetString(ekCert))),
            new DerSet(),
            new DerSet(signerInfo));
    }
}