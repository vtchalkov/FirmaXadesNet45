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
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace Tests
{
    public class Xades
    {
        [Fact]
        public void Test1()
        {
            var caPrivKey = GenerateCACertificate("CN=root ca", out X509Certificate2 res);
            var cert = GenerateSelfSignedCertificate("CN=127.0.01", "CN=root ca", caPrivKey);

            Assert.True(CertUtil.VerifyCertificate(cert, res, X509RevocationMode.NoCheck));

            //To get the location the assembly normally resides on disk or the install directory
            string path = System.Reflection.Assembly.GetExecutingAssembly().CodeBase;

            //once you have the path you get the directory with:
            var directory = System.IO.Path.GetDirectoryName(new Uri(path).LocalPath);

            var SignCertificate = cert;

            FirmaXadesNet.XadesService svc = new FirmaXadesNet.XadesService();
            using (var inputStream = System.IO.File.OpenRead(Path.Combine(directory, @"Sample.xml")))
            {
                var parameters = new FirmaXadesNet.Signature.Parameters.SignatureParameters()
                {
                    SignatureMethod = SignatureMethod.RSAwithSHA256,
                    SigningDate = DateTime.Now,
                    SignaturePackaging = SignaturePackaging.ENVELOPED,
                    InputMimeType = "text/xml",
                    SignatureProductionPlace = new SignatureProductionPlace
                    {
                        City = "Sofia",
                        CountryName = "Bulgaria",
                        PostalCode = "1303",
                        StateOrProvince = "Sofia"
                    }
                };
                parameters.SignatureCommitments.Add(new SignatureCommitment(SignatureCommitmentType.ProofOfOrigin));

                using (parameters.Signer = new Signer(SignCertificate))
                {
                    var signedDocument = svc.Sign(inputStream, parameters);
                    signedDocument.Document.PreserveWhitespace = true;
                    UpgradeParameters xadesTparameters = new UpgradeParameters()
                    {
                        TimeStampClient = new TimeStampClient("https://freetsa.org/tsr")
                    };
                    XadesUpgraderService upgrader = new XadesUpgraderService();
                    upgrader.Upgrade(signedDocument, SignatureFormat.XAdES_T, xadesTparameters);
                    signedDocument.Save(@"c:\temp\xades.xml");

                    var resultDoc = svc.Load(@"c:\temp\xades.xml");

                    var result = resultDoc[0].XadesSignature.XadesCheckSignature(Microsoft.Xades.XadesCheckSignatureMasks.AllChecks);
                    Assert.True(result);
                    var result2 = svc.Validate(resultDoc[0]);
                    Assert.True(result2.IsValid);
                }
            }
            
          
        }

        public static X509Certificate2 GenerateSelfSignedCertificate(string subjectName, string issuerName, AsymmetricKeyParameter issuerPrivKey, int keyStrength = 2048)
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
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            // Issuer and Subject Name
            var subjectDN = new X509Name(subjectName);
            var issuerDN = new X509Name (issuerName);
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

            // selfsign certificate
            var certificate = certificateGenerator.Generate(issuerPrivKey, random);

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


        public static AsymmetricKeyParameter GenerateCACertificate(string subjectName, out X509Certificate2 rootCertificate, int keyStrength = 2048)
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
}
