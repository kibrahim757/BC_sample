namespace Cmce
{
    //using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
    using Org.BouncyCastle.Pqc.Crypto.Hqc;
    using Org.BouncyCastle.Pqc.Crypto.Saber;
    using Org.BouncyCastle.Pqc.Crypto.Ntru;
    using Org.BouncyCastle.Pqc.Crypto.Bike;
    using Org.BouncyCastle.Security;
    using System.IO;

    class Program
    {
        static void Main(string[] args)
        {
            using (var writer = new StreamWriter("C:\\QC\\PQC\\samples\\test_results.txt"))
            {
                Console.SetOut(writer);

                TestHqc(args);
                TestKyber(args);
                //TestSaber(args);
                //TestNtru(args);
                //TestBike(args);
            }
        }

        static void TestHqc(string[] args)
        {
            try {
                var size = "hqc128";
                string? cipherTextHex = null;

                if (args.Length > 0) size = args[0];
                if (args.Length > 1) cipherTextHex = args[1];

                var random = new SecureRandom();
                var keyGenParameters = new HqcKeyGenerationParameters(random, HqcParameters.hqc128);

                if (size == "hqc192") keyGenParameters = new HqcKeyGenerationParameters(random, HqcParameters.hqc192);
                else if (size == "hqc256") keyGenParameters = new HqcKeyGenerationParameters(random, HqcParameters.hqc256);

                var hqcKeyPairGenerator = new HqcKeyPairGenerator();
                hqcKeyPairGenerator.Init(keyGenParameters);

                var aKeyPair = hqcKeyPairGenerator.GenerateKeyPair();

                var aPublic = (HqcPublicKeyParameters)aKeyPair.Public;
                var aPrivate = (HqcPrivateKeyParameters)aKeyPair.Private;

                var pubEncoded = aPublic.GetEncoded();
                var privateEncoded = aPrivate.GetEncoded();

                byte[] cipherText;
                byte[]? bobSecret;

                if (cipherTextHex == null)
                {
                    var bobHqcKemGenerator = new HqcKemGenerator(random);
                    var encapsulatedSecret = bobHqcKemGenerator.GenerateEncapsulated(aPublic);
                    bobSecret = encapsulatedSecret.GetSecret();
                    cipherText = encapsulatedSecret.GetEncapsulation();
                }
                else
                {
                    cipherText = Convert.FromHexString(cipherTextHex);
                    bobSecret = null; // Bob's secret is not generated in this case
                }

                var aliceKemExtractor = new HqcKemExtractor(aPrivate);
                var aliceSecret = aliceKemExtractor.ExtractSecret(cipherText);

                Console.WriteLine("HQC-{0}", size);
                Console.WriteLine("Private key length:\t\t{0} bytes", aPrivate.GetEncoded().Length);
                Console.WriteLine("Public key length:\t\t{0} bytes", aPublic.GetEncoded().Length);
                Console.WriteLine("Ciphertext length:\t\t{0} bytes", cipherText.Length);

                Console.WriteLine("\nAlice private (first 50 bytes):\t{0}", Convert.ToHexString(aPrivate.GetEncoded())[..100]);
                Console.WriteLine("Alice public (first 50 bytes):\t{0}", Convert.ToHexString(aPublic.GetEncoded())[..100]);
                Console.WriteLine("\nCipher (first 50 bytes):\t{0}", Convert.ToHexString(cipherText)[..100]);
                if (bobSecret != null)
                {
                    Console.WriteLine("\nBob secret:\t\t{0}", Convert.ToHexString(bobSecret));
                }
                Console.WriteLine("Alice secret:\t\t{0}", Convert.ToHexString(aliceSecret));

            } catch (Exception e) {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }

        /*static void TestKyber(string[] args)
        {
            try {
                var size = "kyber512";
                string? cipherTextHex = null;

                if (args.Length > 0) size = args[0];
                if (args.Length > 1) cipherTextHex = args[1];

                var random = new SecureRandom();
                var keyGenParameters = new KyberKeyGenerationParameters(random, KyberParameters.kyber512);

                if (size == "kyber768") keyGenParameters = new KyberKeyGenerationParameters(random, KyberParameters.kyber768);
                else if (size == "kyber1024") keyGenParameters = new KyberKeyGenerationParameters(random, KyberParameters.kyber1024);

                var kyberKeyPairGenerator = new KyberKeyPairGenerator();
                kyberKeyPairGenerator.Init(keyGenParameters);

                var aKeyPair = kyberKeyPairGenerator.GenerateKeyPair();

                var aPublic = (KyberPublicKeyParameters)aKeyPair.Public;
                var aPrivate = (KyberPrivateKeyParameters)aKeyPair.Private;

                var pubEncoded = aPublic.GetEncoded();
                var privateEncoded = aPrivate.GetEncoded();

                byte[] cipherText;
                byte[]? bobSecret;

                if (cipherTextHex == null)
                {
                    var bobKyberKemGenerator = new KyberKemGenerator(random);
                    var encapsulatedSecret = bobKyberKemGenerator.GenerateEncapsulated(aPublic);
                    bobSecret = encapsulatedSecret.GetSecret();
                    cipherText = encapsulatedSecret.GetEncapsulation();
                }
                else
                {
                    cipherText = Convert.FromHexString(cipherTextHex);
                    bobSecret = null; // Bob's secret is not generated in this case
                }

                var aliceKemExtractor = new KyberKemExtractor(aPrivate);
                var aliceSecret = aliceKemExtractor.ExtractSecret(cipherText);

                Console.WriteLine("Kyber-{0}", size);
                Console.WriteLine("Private key length:\t\t{0} bytes", aPrivate.GetEncoded().Length);
                Console.WriteLine("Public key length:\t\t{0} bytes", aPublic.GetEncoded().Length);
                Console.WriteLine("Ciphertext length:\t\t{0} bytes", cipherText.Length);

                Console.WriteLine("\nAlice private (first 50 bytes):\t{0}", Convert.ToHexString(aPrivate.GetEncoded())[..100]);
                Console.WriteLine("Alice public (first 50 bytes):\t{0}", Convert.ToHexString(aPublic.GetEncoded())[..100]);
                Console.WriteLine("\nCipher (first 50 bytes):\t{0}", Convert.ToHexString(cipherText)[..100]);
                if (bobSecret != null)
                {
                    Console.WriteLine("\nBob secret:\t\t{0}", Convert.ToHexString(bobSecret));
                }
                Console.WriteLine("Alice secret:\t\t{0}", Convert.ToHexString(aliceSecret));

            } catch (Exception e) {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }*/

        static void TestSaber(string[] args)
        {
            try {
                var size = "lightsaber";
                string? cipherTextHex = null;

                if (args.Length > 0) size = args[0];
                if (args.Length > 1) cipherTextHex = args[1];

                var random = new SecureRandom();
                var keyGenParameters = new SaberKeyGenerationParameters(random, SaberParameters.ulightsaberkemr3);

                if (size == "saber") keyGenParameters = new SaberKeyGenerationParameters(random, SaberParameters.usaberkemr3);
                else if (size == "firesaber") keyGenParameters = new SaberKeyGenerationParameters(random, SaberParameters.ufiresaberkemr3);

                var saberKeyPairGenerator = new SaberKeyPairGenerator();
                saberKeyPairGenerator.Init(keyGenParameters);

                var aKeyPair = saberKeyPairGenerator.GenerateKeyPair();

                var aPublic = (SaberPublicKeyParameters)aKeyPair.Public;
                var aPrivate = (SaberPrivateKeyParameters)aKeyPair.Private;

                var pubEncoded = aPublic.GetEncoded();
                var privateEncoded = aPrivate.GetEncoded();

                byte[] cipherText;
                byte[]? bobSecret;

                if (cipherTextHex == null)
                {
                    var bobSaberKemGenerator = new SaberKemGenerator(random);
                    var encapsulatedSecret = bobSaberKemGenerator.GenerateEncapsulated(aPublic);
                    bobSecret = encapsulatedSecret.GetSecret();
                    cipherText = encapsulatedSecret.GetEncapsulation();
                }
                else
                {
                    cipherText = Convert.FromHexString(cipherTextHex);
                    bobSecret = null; // Bob's secret is not generated in this case
                }

                var aliceKemExtractor = new SaberKemExtractor(aPrivate);
                var aliceSecret = aliceKemExtractor.ExtractSecret(cipherText);

                Console.WriteLine("Saber-{0}", size);
                Console.WriteLine("Private key length:\t\t{0} bytes", aPrivate.GetEncoded().Length);
                Console.WriteLine("Public key length:\t\t{0} bytes", aPublic.GetEncoded().Length);
                Console.WriteLine("Ciphertext length:\t\t{0} bytes", cipherText.Length);

                Console.WriteLine("\nAlice private (first 50 bytes):\t{0}", Convert.ToHexString(aPrivate.GetEncoded())[..100]);
                Console.WriteLine("Alice public (first 50 bytes):\t{0}", Convert.ToHexString(aPublic.GetEncoded())[..100]);
                Console.WriteLine("\nCipher (first 50 bytes):\t{0}", Convert.ToHexString(cipherText)[..100]);
                if (bobSecret != null)
                {
                    Console.WriteLine("\nBob secret:\t\t{0}", Convert.ToHexString(bobSecret));
                }
                Console.WriteLine("Alice secret:\t\t{0}", Convert.ToHexString(aliceSecret));

            } catch (Exception e) {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }

        static void TestNtru(string[] args)
        {
            try {
                var size = "ntruhrss701";
                string? cipherTextHex = null;

                if (args.Length > 0) size = args[0];
                if (args.Length > 1) cipherTextHex = args[1];

                var random = new SecureRandom();
                var keyGenParameters = new NtruKeyGenerationParameters(random, NtruParameters.NtruHrss701);

                if (size == "ntruhps2048509") keyGenParameters = new NtruKeyGenerationParameters(random, NtruParameters.NtruHps2048509);
                else if (size == "ntruhps2048677") keyGenParameters = new NtruKeyGenerationParameters(random, NtruParameters.NtruHps2048677);
                else if (size == "ntruhps4096821") keyGenParameters = new NtruKeyGenerationParameters(random, NtruParameters.NtruHps4096821);

                var ntruKeyPairGenerator = new NtruKeyPairGenerator();
                ntruKeyPairGenerator.Init(keyGenParameters);

                var aKeyPair = ntruKeyPairGenerator.GenerateKeyPair();

                var aPublic = (NtruPublicKeyParameters)aKeyPair.Public;
                var aPrivate = (NtruPrivateKeyParameters)aKeyPair.Private;

                var pubEncoded = aPublic.GetEncoded();
                var privateEncoded = aPrivate.GetEncoded();

                byte[] cipherText;
                byte[]? bobSecret;

                if (cipherTextHex == null)
                {
                    var bobNtruKemGenerator = new NtruKemGenerator(random);
                    var encapsulatedSecret = bobNtruKemGenerator.GenerateEncapsulated(aPublic);
                    bobSecret = encapsulatedSecret.GetSecret();
                    cipherText = encapsulatedSecret.GetEncapsulation();
                }
                else
                {
                    cipherText = Convert.FromHexString(cipherTextHex);
                    bobSecret = null; // Bob's secret is not generated in this case
                }

                var aliceKemExtractor = new NtruKemExtractor(aPrivate);
                var aliceSecret = aliceKemExtractor.ExtractSecret(cipherText);

                Console.WriteLine("NTRU-{0}", size);
                Console.WriteLine("Private key length:\t\t{0} bytes", aPrivate.GetEncoded().Length);
                Console.WriteLine("Public key length:\t\t{0} bytes", aPublic.GetEncoded().Length);
                Console.WriteLine("Ciphertext length:\t\t{0} bytes", cipherText.Length);

                Console.WriteLine("\nAlice private (first 50 bytes):\t{0}", Convert.ToHexString(aPrivate.GetEncoded())[..100]);
                Console.WriteLine("Alice public (first 50 bytes):\t{0}", Convert.ToHexString(aPublic.GetEncoded())[..100]);
                Console.WriteLine("\nCipher (first 50 bytes):\t{0}", Convert.ToHexString(cipherText)[..100]);
                if (bobSecret != null)
                {
                    Console.WriteLine("\nBob secret:\t\t{0}", Convert.ToHexString(bobSecret));
                }
                Console.WriteLine("Alice secret:\t\t{0}", Convert.ToHexString(aliceSecret));

            } catch (Exception e) {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }

        static void TestBike(string[] args)
        {
            try {
                var size = "bike128";
                string? cipherTextHex = null;

                if (args.Length > 0) size = args[0];
                if (args.Length > 1) cipherTextHex = args[1];

                var random = new SecureRandom();
                var keyGenParameters = new BikeKeyGenerationParameters(random, BikeParameters.bike128);

                if (size == "bike192") keyGenParameters = new BikeKeyGenerationParameters(random, BikeParameters.bike192);
                else if (size == "bike256") keyGenParameters = new BikeKeyGenerationParameters(random, BikeParameters.bike256);

                var bikeKeyPairGenerator = new BikeKeyPairGenerator();
                bikeKeyPairGenerator.Init(keyGenParameters);

                var aKeyPair = bikeKeyPairGenerator.GenerateKeyPair();

                var aPublic = (BikePublicKeyParameters)aKeyPair.Public;
                var aPrivate = (BikePrivateKeyParameters)aKeyPair.Private;

                var pubEncoded = aPublic.GetEncoded();
                var privateEncoded = aPrivate.GetEncoded();

                byte[] cipherText;
                byte[]? bobSecret;

                if (cipherTextHex == null)
                {
                    var bobBikeKemGenerator = new BikeKemGenerator(random);
                    var encapsulatedSecret = bobBikeKemGenerator.GenerateEncapsulated(aPublic);
                    bobSecret = encapsulatedSecret.GetSecret();
                    cipherText = encapsulatedSecret.GetEncapsulation();
                }
                else
                {
                    cipherText = Convert.FromHexString(cipherTextHex);
                    bobSecret = null; // Bob's secret is not generated in this case
                }

                var aliceKemExtractor = new BikeKemExtractor(aPrivate);
                var aliceSecret = aliceKemExtractor.ExtractSecret(cipherText);

                Console.WriteLine("BIKE-{0}", size);
                Console.WriteLine("Private key length:\t\t{0} bytes", aPrivate.GetEncoded().Length);
                Console.WriteLine("Public key length:\t\t{0} bytes", aPublic.GetEncoded().Length);
                Console.WriteLine("Ciphertext length:\t\t{0} bytes", cipherText.Length);

                Console.WriteLine("\nAlice private (first 50 bytes):\t{0}", Convert.ToHexString(aPrivate.GetEncoded())[..100]);
                Console.WriteLine("Alice public (first 50 bytes):\t{0}", Convert.ToHexString(aPublic.GetEncoded())[..100]);
                Console.WriteLine("\nCipher (first 50 bytes):\t{0}", Convert.ToHexString(cipherText)[..100]);
                if (bobSecret != null)
                {
                    Console.WriteLine("\nBob secret:\t\t{0}", Convert.ToHexString(bobSecret));
                }
                Console.WriteLine("Alice secret:\t\t{0}", Convert.ToHexString(aliceSecret));

            } catch (Exception e) {
                Console.WriteLine("Error: {0}", e.Message);
            }
        }
    }
}