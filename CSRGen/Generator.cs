using System.Text;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.OpenSsl;
using System.IO;
using Org.BouncyCastle.Asn1.Pkcs;
using System.Collections;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.X9;

namespace CSRGen
{
    class Generator
    {

        public string PrivateKey { get; set; }
        public string PublicKey { get; set; }
        public string Csr { get; set; }

        public static string pkey;
        public static string csR;
        public static int pstat = 100;

        public enum RsaKeyLength
        {
            Length2048Bits = 2048, Length3072Bits = 3072, Length4096Bits = 4096
        }

        public enum SignatureAlgorithm
        {
            SHA1, SHA256, SHA512
        }



        public static Generator GenPki(string cn, string org, string orgun, string city, string state, string country,
                                       SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.SHA256,
                                       RsaKeyLength rsaKeyLength = RsaKeyLength.Length2048Bits)
        {


            Generator generator = new Generator();


            // Determines Signature Algorithm
            string signatureAlgorithmStr;
            switch (signatureAlgorithm)
            {
                case SignatureAlgorithm.SHA1:
                    signatureAlgorithmStr = PkcsObjectIdentifiers.Sha1WithRsaEncryption.Id;
                    break;

                case SignatureAlgorithm.SHA256:
                    signatureAlgorithmStr = PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id;
                    break;

                case SignatureAlgorithm.SHA512:
                    signatureAlgorithmStr = PkcsObjectIdentifiers.Sha512WithRsaEncryption.Id;
                    break;

                default:
                    signatureAlgorithmStr = PkcsObjectIdentifiers.Sha256WithRsaEncryption.Id;
                    break;
            }

            // Cert Info


            IDictionary attrs = new Hashtable();

            attrs.Add(X509Name.CN, cn);
            attrs.Add(X509Name.O, org);
            attrs.Add(X509Name.OU, orgun);
            attrs.Add(X509Name.L, city);
            attrs.Add(X509Name.ST, state);
            attrs.Add(X509Name.C, country);

            X509Name subject = new X509Name(new ArrayList(attrs.Keys), attrs);


            //Key Generator
            //ECKeyPairGenerator ecKeyPairGenerator = new ECKeyPairGenerator();
            //ecKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), (int)rsaKeyLength));
            //AsymmetricCipherKeyPair pair = ecKeyPairGenerator.GenerateKeyPair();

            X9ECParameters curve = ECNamedCurveTable.GetByName("secp256k1");
            ECDomainParameters ecParam = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
            ECKeyPairGenerator ecKeyPairGenerator = new ECKeyPairGenerator();
            ecKeyPairGenerator.Init(new ECKeyGenerationParameters(ecParam, new SecureRandom()));
            AsymmetricCipherKeyPair pair = ecKeyPairGenerator.GenerateKeyPair();

            //RsaKeyPairGenerator rsaKeyPairGenerator = new RsaKeyPairGenerator();
            //rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), (int)rsaKeyLength));
            //AsymmetricCipherKeyPair pair = rsaKeyPairGenerator.GenerateKeyPair();

            //CSR Generator

            //Asn1SignatureFactory signatureFactory = new Asn1SignatureFactory(signatureAlgorithmStr, pair.Private);
            Asn1SignatureFactory signatureFactory = new Asn1SignatureFactory("SHA256WITHECDSA", pair.Private);

            Pkcs10CertificationRequest csr = new Pkcs10CertificationRequest(signatureFactory, subject, pair.Public, null, pair.Private);



            /***************************
            ****************************
            **Convert to PEM and Output*
            ****************************
            ***************************/

            //Private Key

            StringBuilder privateKeyStrBuilder = new StringBuilder();
            PemWriter privateKeyPemWriter = new PemWriter(new StringWriter(privateKeyStrBuilder));
            privateKeyPemWriter.WriteObject(pair.Private);
            privateKeyPemWriter.Writer.Flush();

            pkey = privateKeyStrBuilder.ToString();

            //Public Key

            StringBuilder publicKeyStrBuilder = new StringBuilder();
            PemWriter publicKeyPemWriter = new PemWriter(new StringWriter(publicKeyStrBuilder));
            publicKeyPemWriter.WriteObject(pair.Private);
            publicKeyPemWriter.Writer.Flush();

            generator.PublicKey = publicKeyStrBuilder.ToString();


            //CSR

            StringBuilder csrStrBuilder = new StringBuilder();
            PemWriter csrPemWriter = new PemWriter(new StringWriter(csrStrBuilder));

            csrPemWriter.WriteObject(csr);
            csrPemWriter.Writer.Flush();

            csR = csrStrBuilder.ToString();

            return generator;
        }

        public static string privKey()
        {
            return pkey;
        }

        public static string csr()
        {
            return csR;
        }

        public static int status()
        {
            return pstat;
        }

    }//end Generator
}
