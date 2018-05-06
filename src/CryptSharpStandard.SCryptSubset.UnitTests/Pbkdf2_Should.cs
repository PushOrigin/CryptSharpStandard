using CryptSharpStandard.Utility;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace CryptSharpStandard.SCryptSubset.UnitTests
{
    [TestClass]
    public class Pbkdf2_Should
    {
        [TestMethod]
        public void Return_Correct_SHA1_Derived_Key_With_Length_20_And_1_Iteration()
        {
            var expectedResult = "0C60C80F961F0E71F3A9B524AF6012062FE037A6";


            byte[] keyBytes = Encoding.ASCII.GetBytes("password");
            byte[] saltBytes = Encoding.ASCII.GetBytes("salt");
            byte[] derivedBytes = Pbkdf2.ComputeDerivedKey(hmacAlgorithm: new HMACSHA1(keyBytes),
                salt: saltBytes, iterations: 1, derivedKeyLength: 20);
            var result = Base16Encoding.Hex.GetString(derivedBytes);

            result.Should().Be(expectedResult);
        }

        [TestMethod]
        public void Return_Correct_SHA1_Derived_Key_With_Length_20_And_2_Iterations()
        {
            var expectedResult = "EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957";

            byte[] keyBytes = Encoding.ASCII.GetBytes("password");
            byte[] saltBytes = Encoding.ASCII.GetBytes("salt");
            byte[] derivedBytes = Pbkdf2.ComputeDerivedKey(hmacAlgorithm: new HMACSHA1(keyBytes),
                salt: saltBytes, iterations: 2, derivedKeyLength: 20);
            var result = Base16Encoding.Hex.GetString(derivedBytes);

            result.Should().Be(expectedResult);
        }

        [TestMethod]
        public void Return_Correct_SHA1_Derived_Key_With_Length_20_And_4096_Iterations()
        {
            var expectedResult = "4B007901B765489ABEAD49D926F721D065A429C1";

            byte[] keyBytes = Encoding.ASCII.GetBytes("password");
            byte[] saltBytes = Encoding.ASCII.GetBytes("salt");
            byte[] derivedBytes = Pbkdf2.ComputeDerivedKey(hmacAlgorithm: new HMACSHA1(keyBytes),
                salt: saltBytes, iterations: 4096, derivedKeyLength: 20);
            var result = Base16Encoding.Hex.GetString(derivedBytes);

            result.Should().Be(expectedResult);
        }

        [TestMethod]
        public void Return_Correct_SHA1_Derived_Key_With_Length_25_And_4096_Iterations()
        {
            var expectedResult = "3D2EEC4FE41C849B80C8D83662C0E44A8B291A964CF2F07038";

            byte[] keyBytes = Encoding.ASCII.GetBytes("passwordPASSWORDpassword");
            byte[] saltBytes = Encoding.ASCII.GetBytes("saltSALTsaltSALTsaltSALTsaltSALTsalt");
            byte[] derivedBytes = Pbkdf2.ComputeDerivedKey(hmacAlgorithm: new HMACSHA1(keyBytes),
                salt: saltBytes, iterations: 4096, derivedKeyLength: 25);
            var result = Base16Encoding.Hex.GetString(derivedBytes);

            result.Should().Be(expectedResult);
        }

        [TestMethod]
        public void Return_Correct_SHA1_Derived_Key_With_Length_16_And_4096_Iterations()
        {
            var expectedResult = "56FA6AA75548099DCC37D7F03425E0C3";

            byte[] keyBytes = Encoding.ASCII.GetBytes("pass\0word");
            byte[] saltBytes = Encoding.ASCII.GetBytes("sa\0lt");
            byte[] derivedBytes = Pbkdf2.ComputeDerivedKey(hmacAlgorithm: new HMACSHA1(keyBytes),
                salt: saltBytes, iterations: 4096, derivedKeyLength: 16);
            var result = Base16Encoding.Hex.GetString(derivedBytes);

            result.Should().Be(expectedResult);
        }

        [TestMethod]
        public void Return_Expected_Results_From_TestVectors_File()
        {
            using (Stream stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("CryptSharpStandard.SCryptSubset.UnitTests.TestVectors-PBKDF2.txt"))
            {
                using (StreamReader reader = new StreamReader(stream))
                {
                    int startTime = Environment.TickCount;

                    string line; int count = 0;
                    while ((line = reader.ReadLine()) != null)
                    {

                        string[] parts = line.Split(new[] { ',' }, 4);
                        if (parts.Length != 4) { continue; }

                        byte[] key = Convert.FromBase64String(parts[0]);
                        byte[] salt = Convert.FromBase64String(parts[1]);
                        int iterations = int.Parse(parts[2]);
                        byte[] expectedKey = Convert.FromBase64String(parts[3]);
                        byte[] derivedKey = Pbkdf2.ComputeDerivedKey(new HMACSHA256(key), salt, iterations, 128);

                        for (int i = 0; i < expectedKey.Length; i++)
                        {
                            if (expectedKey[i] != derivedKey[i])
                            {
                                derivedKey[i].Should().Be(expectedKey[i], "PBKDF2 entry #{0} does not match.", count + 1);
                                break;
                            }
                        }
                        count++;
                    }
                }
            }
        }
    }
}
