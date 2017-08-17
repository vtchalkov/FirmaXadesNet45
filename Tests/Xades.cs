using FirmaXadesNet.Clients;
using FirmaXadesNet.Crypto;
using FirmaXadesNet.Signature.Parameters;
using FirmaXadesNet.Upgraders;
using FirmaXadesNet.Upgraders.Parameters;
using FirmaXadesNet.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Xunit;
using Xunit.Sdk;

namespace Tests
{
    public class Xades
    {
        X509Certificate2 _signCertificate;
        AsymmetricKeyParameter _caPrivKey;
        X509Certificate2 _rootCert;
        string rootDirectory;
        public Xades()
        {
            _caPrivKey = GenerateCACertificate("CN=root ca", out _rootCert);
            _signCertificate = GenerateSelfSignedCertificate("CN=127.0.0.1", "CN=root ca", _caPrivKey);
            //To get the location the assembly normally resides on disk or the install directory
            var rootPath = System.Reflection.Assembly.GetExecutingAssembly().CodeBase;
            //once you have the path you get the directory with:
            rootDirectory = System.IO.Path.GetDirectoryName(new Uri(rootPath).LocalPath);
        }
        [Theory]
        [Repeat(10)]
        public void SimpleXadesTSign(object input)
        {
            Console.WriteLine(input.ToString());
            Assert.True(CertUtil.VerifyCertificate(_signCertificate, _rootCert, X509RevocationMode.NoCheck));
            using (var inputStream = System.IO.File.OpenRead(Path.Combine(rootDirectory, @"Sample.xml")))
            {
                var result = SignDocument(_signCertificate, inputStream, new SignatureProductionPlace
                {
                    City = "Sofia",
                    CountryName = "Bulgaria",
                    PostalCode = "1303",
                    StateOrProvince = "Sofia"
                }, "https://freetsa.org/tsr");
                ValidateDocument(result);
                ValidateDocumentSignatureOnly(result);
            }
        }

        [Fact]
        public void SimpleXadesTSignWithFile()
        {
            Assert.True(CertUtil.VerifyCertificate(_signCertificate, _rootCert, X509RevocationMode.NoCheck));
            using (var inputStream = System.IO.File.OpenRead(Path.Combine(rootDirectory, @"SampleWithFile.xml")))
            {
                var result = SignDocument(_signCertificate, inputStream, new SignatureProductionPlace
                {
                    City = "Sofia",
                    CountryName = "Bulgaria",
                    PostalCode = "1303",
                    StateOrProvince = "Sofia"
                }, "https://freetsa.org/tsr");
                ValidateDocument(result);
                ValidateDocumentSignatureOnly(result);
            }
        }

        //C:\Work\IMEONTFS\Imeon\ElectronicDocuments\External

        [Fact]
        public void TestWithedoc1cert()
        {
            using (var inputStream = System.IO.File.OpenRead(Path.Combine(rootDirectory, @"SampleWithFile.xml")))
            {
                var result = SignDocument(new X509Certificate2(@"C:\Work\IMEONTFS\Imeon\ElectronicDocuments\External\eDoc2.pfx", "pass@word1"), inputStream, new SignatureProductionPlace
                {
                    City = "Sofia",
                    CountryName = "Bulgaria",
                    PostalCode = "1303",
                    StateOrProvince = "Sofia"
                }, "https://freetsa.org/tsr");
                //ValidateDocument(result);
                //ValidateDocumentSignatureOnly(result);
            }
        }

        string SignDocument(X509Certificate2 signCertificate, System.IO.Stream inputStream, SignatureProductionPlace signatureProductionPlace, string timeStampUrl = "https://freetsa.org/tsr")
        {
            FirmaXadesNet.XadesService svc = new FirmaXadesNet.XadesService();

            var parameters = new FirmaXadesNet.Signature.Parameters.SignatureParameters()
            {
                SignatureMethod = SignatureMethod.RSAwithSHA256,
                SigningDate = DateTime.Now,
                SignaturePackaging = SignaturePackaging.ENVELOPED,
                InputMimeType = "text/xml",
                SignatureProductionPlace = signatureProductionPlace
            };
            parameters.SignatureCommitments.Add(new SignatureCommitment(SignatureCommitmentType.ProofOfOrigin));

            using (parameters.Signer = new Signer(signCertificate))
            {
                var signedDocument = svc.Sign(inputStream, parameters);
                signedDocument.Document.PreserveWhitespace = true;
                UpgradeParameters xadesTparameters = new UpgradeParameters()
                {
                    TimeStampClient = new TimeStampClient(timeStampUrl)
                };
                XadesUpgraderService upgrader = new XadesUpgraderService();
                upgrader.Upgrade(signedDocument, SignatureFormat.XAdES_T, xadesTparameters);

                return signedDocument.Document.OuterXml;

            }

        }

        void ValidateDocument(string xml)
        {
            FirmaXadesNet.XadesService svc = new FirmaXadesNet.XadesService();
            XmlDocument doc = new XmlDocument
            {
                PreserveWhitespace = true
            };
            doc.LoadXml(xml);
            var resultDoc = svc.Load(doc);


            var result2 = svc.Validate(resultDoc[0]);
            Assert.True(result2.IsValid);
        }
        void ValidateDocumentSignatureOnly(string xml)
        {
            //signedDocument.Save(@"c:\temp\xades.xml");
            FirmaXadesNet.XadesService svc = new FirmaXadesNet.XadesService();
            XmlDocument doc = new XmlDocument
            {
                PreserveWhitespace = true
            };
            doc.LoadXml(xml);
            var resultDoc = svc.Load(doc);

            var result = resultDoc[0].XadesSignature.XadesCheckSignature(Microsoft.Xades.XadesCheckSignatureMasks.AllChecks);
            Assert.True(result);

        }
        X509Certificate2 GenerateSelfSignedCertificate(string subjectName, string issuerName, AsymmetricKeyParameter issuerPrivKey, int keyStrength = 2048)
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Signature Algorithm
            const string signatureAlgorithm = "SHA256WithRSA";

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = new X509Name(issuerName);
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);


            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;

            // create key factory
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issuerPrivKey, random);

            // selfsign certificate
            var certificate = certificateGenerator.Generate(signatureFactory);

            // correcponding private key
            PrivateKeyInfo info = PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);

            // merge into X509Certificate2
            var x509 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded());

            var seq = (Asn1Sequence)Asn1Object.FromByteArray(info.ParsePrivateKey().GetDerEncoded());
            if (seq.Count != 9)
                throw new PemException("malformed sequence in RSA private key");

            var rsa = RsaPrivateKeyStructure.GetInstance(seq);
            RsaPrivateCrtKeyParameters rsaparams = new RsaPrivateCrtKeyParameters(
                rsa.Modulus, rsa.PublicExponent, rsa.PrivateExponent, rsa.Prime1, rsa.Prime2, rsa.Exponent1, rsa.Exponent2, rsa.Coefficient);

            x509.PrivateKey = DotNetUtilities.ToRSA(rsaparams);
            return x509;
        }


        AsymmetricKeyParameter GenerateCACertificate(string subjectName, out X509Certificate2 rootCertificate, int keyStrength = 2048)
        {
            // Generating Random Numbers
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);

            // The Certificate Generator
            var certificateGenerator = new X509V3CertificateGenerator();

            // Serial Number
            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            // Signature Algorithm
            const string signatureAlgorithm = "SHA256WithRSA";

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            // Valid For
            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            // Subject Public Key
            AsymmetricCipherKeyPair subjectKeyPair;
            var keyGenerationParameters = new KeyGenerationParameters(random, keyStrength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            // Generating the Certificate
            var issuerKeyPair = subjectKeyPair;

            // create key factory
            ISignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithm, issuerKeyPair.Private, random);

            // selfsign certificate
            var certificate = certificateGenerator.Generate(signatureFactory);
            rootCertificate = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate.GetEncoded());
            return issuerKeyPair.Private;
        }
    }

    public sealed class RepeatAttribute : DataAttribute
    {
        private readonly int _count;

        public RepeatAttribute(int count)
        {
            if (count < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(count),
                      "Repeat count must be greater than 0.");
            }
            _count = count;
        }

        public override IEnumerable<object[]> GetData(MethodInfo testMethod)
        {
            return Enumerable.Range(0, _count).Select(item => new object[] { (object)item });
        }
    }
}
