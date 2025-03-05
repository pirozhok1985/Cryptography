// See https://aka.ms/new-console-template for more information

using System.IO.Abstractions;
using KeyAttestation;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Tpm2Lib;

using var tpmFacade = new TpmFacade();
tpmFacade.InitialiseTpm("/dev/tpmrm0");
var ek = tpmFacade.CreateEk();
var ak = tpmFacade.CreateAk(ek.Handle!);
var srkHandlePersistent = TpmHandle.Persistent(5);
var key = tpmFacade.CreateKey(srkHandlePersistent);
var clientKeyHandle = tpmFacade.Tpm!.Load(srkHandlePersistent, key.Private, key.Public);
var attestation = tpmFacade.Tpm!.Certify(clientKeyHandle, ak.Handle, null, new SchemeRsassa(TpmAlgId.Sha256),
    out var signature);

var rawRsa = new RawRsaCustom();
rawRsa.Init(key.Public!, key.Private!);

var keyPair = new AsymmetricCipherKeyPair(
    new RsaKeyParameters(false, rawRsa.N.ToBigIntegerBc(), rawRsa.E.ToBigIntegerBc()),
    new RsaKeyParameters(true, rawRsa.N.ToBigIntegerBc(), rawRsa.D.ToBigIntegerBc()));

var cms = Pkcs10RequestGenerator.GenerateCms(((SignatureRsassa)signature).sig, attestation.GetTpmRepresentation(), keyPair.Public, ak.Public);
var csr = Pkcs10RequestGenerator.Generate(keyPair.Public, keyPair.Private, cms);

var fileWriter = new FileSystem().File;
await Helpers.WriteCsrAsync(csr, "/home/sigma.sbrf.ru@18497320/temp/openssl_test/client.csr", fileWriter);
