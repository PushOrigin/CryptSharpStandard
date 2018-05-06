using CryptSharpStandard.Utility;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Text;

namespace CryptSharp.SCryptSubset.UnitTests
{
    [TestClass]
    public class SCrypt_Should
    {
        [TestMethod]
        public void Return_Correct_DerivedKey_With_N_Of_16()
        {
            var expectedDerivedKey =
                @"77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
                  f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
                  fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
                  e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06";
            var expectedResult = FormatExpectedResult(expectedDerivedKey);

            byte[] derivedBytes = SCrypt.ComputeDerivedKey
                (key: Encoding.ASCII.GetBytes(string.Empty), salt: Encoding.ASCII.GetBytes(string.Empty),
                 cost: 16, blockSize: 1, parallel: 1, maxThreads: null, derivedKeyLength: 64);
            var result = Base16Encoding.Hex.GetString(derivedBytes);

            result.Should().Be(expectedResult);
        }

        [TestMethod]
        public void Return_Correct_DerivedKey_With_N_Of_1024()
        {
            var expectedDerivedKey =
                @"fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
                  7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
                  2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
                  c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40";
            var expectedResult = FormatExpectedResult(expectedDerivedKey);

            byte[] derivedBytes = SCrypt.ComputeDerivedKey
                (key: Encoding.ASCII.GetBytes("password"), salt: Encoding.ASCII.GetBytes("NaCl"),
                 cost: 1024, blockSize: 8, parallel: 16, maxThreads: null, derivedKeyLength: 64);
            var result = Base16Encoding.Hex.GetString(derivedBytes);

            result.Should().Be(expectedResult);
        }

        [TestMethod]
        public void Return_Correct_DerivedKey_With_N_Of_16384()
        {
            var expectedDerivedKey =
                @"70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
                  fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
                  d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
                  e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87";
            var expectedResult = FormatExpectedResult(expectedDerivedKey);

            byte[] derivedBytes = SCrypt.ComputeDerivedKey
                (key: Encoding.ASCII.GetBytes("pleaseletmein"), salt: Encoding.ASCII.GetBytes("SodiumChloride"),
                 cost: 16384, blockSize: 8, parallel: 1, maxThreads: null, derivedKeyLength: 64);
            var result = Base16Encoding.Hex.GetString(derivedBytes);

            result.Should().Be(expectedResult);
        }

        [TestMethod, Ignore]
        public void Return_Correct_DerivedKey_With_N_Of_1048576()
        {
            // Ignored because this needs 1GB of RAM and 30 seconds or more to run.
            var expectedDerivedKey =
                @"21 01 cb 9b 6a 51 1a ae ad db be 09 cf 70 f8 81
                  ec 56 8d 57 4a 2f fd 4d ab e5 ee 98 20 ad aa 47
                  8e 56 fd 8f 4b a5 d0 9f fa 1c 6d 92 7c 40 f4 c3
                  37 30 40 49 e8 a9 52 fb cb f4 5c 6f a7 7a 41 a4";
            var expectedResult = FormatExpectedResult(expectedDerivedKey);

            byte[] derivedBytes = SCrypt.ComputeDerivedKey
                (key: Encoding.ASCII.GetBytes("pleaseletmein"), salt: Encoding.ASCII.GetBytes("SodiumChloride"),
                 cost: 1048576, blockSize: 8, parallel: 1, maxThreads: null, derivedKeyLength: 64);
            var result = Base16Encoding.Hex.GetString(derivedBytes);

            result.Should().Be(expectedResult);
        }

        private static string FormatExpectedResult(string expectedDerivedKey)
        {
            return expectedDerivedKey.Replace(" ", string.Empty).Replace("\r", string.Empty).Replace("\n", string.Empty).Replace("\t", string.Empty).ToUpper();
        }
    }
}
