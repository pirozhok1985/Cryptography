// See https://aka.ms/new-console-template for more information


using System.Security.Cryptography;
using KeyAttestation;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

// 000bbde287c900462221f35201fd747a1f0863e2ae09c37089b7395e0bc5a649c867 - name
// 000bbc5bafb389803013c2d0b9a81cf2a000afa5e649052942024b49fffd225adcfc - qname
// 000b48c9535f2b0329637be4c31f2d9c35d1d68b83fa90a05f3c705674e6b6a05cb5 - pqname

// var pqname = File.ReadAllBytes("/home/sigma.sbrf.ru@18497320/temp/openssl_test/pk.name");
// var nameHash = SHA256.HashData(File.ReadAllBytes("/home/sigma.sbrf.ru@18497320/temp/openssl_test/test-key.pub"));
// var name = new byte[34];
// nameHash.CopyTo(name, 2);
// for (int i = 0; i < 2; i++)
// {
//     name[i] = pqname[i];
// }
// var qname = new byte[pqname.Length + name.Length];
// pqname.CopyTo(qname, 0);
// name.CopyTo(qname, pqname.Length);
// var hash = SHA256.HashData(qname);
// Console.WriteLine(string.Concat("000B",Convert.ToHexString(hash)));
using var textReader = new StringReader(File.ReadAllText(@"/home/sigma.sbrf.ru@18497320/temp/openssl_test/ak.pub"));
using var pemReader = new PemReader(textReader);
var pubKey = (AsymmetricKeyParameter)pemReader.ReadObject();

var sigData = File.ReadAllBytes("/home/sigma.sbrf.ru@18497320/temp/openssl_test/attestation_test.sign");
var attestationStatement = File.ReadAllBytes("/home/sigma.sbrf.ru@18497320/temp/openssl_test/attestation_test");

var cms = Pkcs10RequestGenerator.GenerateCms(sigData, attestationStatement, pubKey);
var csr = Pkcs10RequestGenerator.Generate(cms);
await using var csrWriter = new StringWriter();
using var pemCsrWriter = new PemWriter(csrWriter);
pemCsrWriter.WriteObject(csr);
await File.WriteAllTextAsync("/home/sigma.sbrf.ru@18497320/temp/openssl_test/test.csr", csrWriter.ToString());

