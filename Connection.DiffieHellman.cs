using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Networking
{
    public partial class Connection
    {
        X9ECParameters x9EC;
        ECDomainParameters ecDomain;
        AsymmetricCipherKeyPair keyPair;
        BigInteger bobX;
        BigInteger bobY;


        private static AsymmetricCipherKeyPair GenerateKeyPair(ECDomainParameters ecDomain)
        {
            ECKeyPairGenerator g = GeneratorUtilities.GetKeyPairGenerator("ECDH") as ECKeyPairGenerator;
            g.Init(new ECKeyGenerationParameters(ecDomain, new SecureRandom()));

            AsymmetricCipherKeyPair aliceKeyPair = g.GenerateKeyPair();
            return aliceKeyPair;
        }

        public void InitializeDiffieHellman()
        {
            x9EC = NistNamedCurves.GetByName("P-521");
            ecDomain = new ECDomainParameters(x9EC.Curve, x9EC.G, x9EC.N, x9EC.H, x9EC.GetSeed());
            keyPair = GenerateKeyPair(ecDomain);
        }

        public ECPublicKeyParameters GetPublicKey()
        {
            return keyPair.Public as ECPublicKeyParameters;
        }


        private static byte[] GenerateAESKey(ECPublicKeyParameters bobPublicKey,
                          AsymmetricKeyParameter alicePrivateKey)
        {
            IBasicAgreement aKeyAgree = AgreementUtilities.GetBasicAgreement("ECDH");
            aKeyAgree.Init(alicePrivateKey);
            BigInteger sharedSecret = aKeyAgree.CalculateAgreement(bobPublicKey);
            byte[] sharedSecretBytes = sharedSecret.ToByteArray();

            IDigest digest = new Sha256Digest();
            byte[] symmetricKey = new byte[32];
            digest.BlockUpdate(sharedSecretBytes, 0, sharedSecretBytes.Length);
            digest.DoFinal(symmetricKey, 0);

            return symmetricKey;
        }

        public void SetBobPoints(BigInteger x, BigInteger y)
        {
            bobX = x;
            bobY = y;
        }


        public void SwapEncryptionKey()
        {
            var point = x9EC.Curve.CreatePoint(bobX, bobY);

            var bobPublicKey = new ECPublicKeyParameters("ECDH", point, SecObjectIdentifiers.SecP521r1);

            EncryptionKey = GenerateAESKey(bobPublicKey, keyPair.Private);
#if !UNITY_5_3_OR_NEWER
            AesEncryptor = new AesGcm(EncryptionKey);
#endif

        }
    }
}
