using System;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using NUnit.Framework;
using BitCoinSharp;

namespace CSharpKeyUtils
{
	[TestFixture]
	public class KeyUtilsTest
	{
		public KeyUtilsTest ()
		{
		}

		static string pemPattern = "-----BEGIN EC PRIVATE KEY-----\nMHQCA.*SuBBAAK\noUQDQ.*\n.*\n.*END EC PRIVATE KEY-----\n"; 

		static string pem1 = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEICg7E4NN53YkaWuAwpoqjfAofjzKI7Jq1f532dX+0O6QoAcGBSuBBAAK\noUQDQgAEjZcNa6Kdz6GQwXcUD9iJ+t1tJZCx7hpqBuJV2/IrQBfue8jh8H7Q/4vX\nfAArmNMaGotTpjdnymWlMfszzXJhlw==\n-----END EC PRIVATE KEY-----\n";
		static string pubKeyCompressed1 = "038D970D6BA29DCFA190C177140FD889FADD6D2590B1EE1A6A06E255DBF22B4017";
		static string privateKey1 = "283B13834DE77624696B80C29A2A8DF0287E3CCA23B26AD5FE77D9D5FED0EE90";
		static string sin1 = "TeyN4LPrXiG5t2yuSamKqP3ynVk3F52iHrX";
		static string msg1 = "Test message 1";

		static string pem2 = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEINMwkuB8YAtSTJzUNals8F2lXxsLIncL3rOc8dqRdps8oAcGBSuBBAAK\noUQDQgAEn0OPHdZ0hx+tLRobqDMbC5U12k+BAzynN/wMjzG3axbkgNIFGLim30pf\nh1Lvp4eFVHUydkbP250fTOrJ4zo7RQ==\n-----END EC PRIVATE KEY-----\n";
		static string pubKeyCompressed2 = "039F438F1DD674871FAD2D1A1BA8331B0B9535DA4F81033CA737FC0C8F31B76B16";
		static string privateKey2 = "D33092E07C600B524C9CD435A96CF05DA55F1B0B22770BDEB39CF1DA91769B3C";
		static string sin2 = "TfFW1ePJ5q6EZKBsYUrMGQEbb6z4fBmx6BW";
		static string msg2 = "Test";

		static string pem3 = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIGxJZ/H8cJ6rTejjSL/jg+bmvV6P1bh+oQyElxQfztbqoAcGBSuBBAAK\noUQDQgAEAJiwjbqNtzFoL1HvdRRWQgzEDMwN08PJC2bdqTmGHmZ0FfX5t+pOy4Ai\nOuluV4VbIFWZ64onGHXu0A7ejWY/jg==\n-----END EC PRIVATE KEY-----\n";
		static string pubKeyCompressed3 = "020098B08DBA8DB731682F51EF751456420CC40CCC0DD3C3C90B66DDA939861E66";
		static string privateKey3 = "6C4967F1FC709EAB4DE8E348BFE383E6E6BD5E8FD5B87EA10C8497141FCED6EA";
		static string sin3 = "Tf3goZsaKmYcD5YWGv2bz2yifbrM3ogkbMd";
		static string msg3 = "This is test message number 3";


		public static void Main() 
		{
			testGeneratePem ();
			testCompressedKeyFromPem ();
			testPrivateKeyFromPem ();
			testSinFromPem ();
			testSignMessageWithPem ();

			testGeneratePem2 ();
			testCompressedKeyFromPem2 ();
			testPrivateKeyFromPem2 ();
			testSinFromPem2 ();
			testSignMessageWithPem2 ();

			testGeneratePem3 ();
			testCompressedKeyFromPem3 ();
			testPrivateKeyFromPem3 ();
			testSinFromPem3 ();
			testSignMessageWithPem3 ();

		}


		// ********************************
		// *       1st set of tests       *
		// ********************************

		[Test]
		public static void testGeneratePem()
		{
			string pemTest = KeyUtils.generatePem ();
			Assert.That(Regex.IsMatch(pemTest, pemPattern));
		}

		[Test]
		public static void testCompressedKeyFromPem()
		{
			string compPubKey = KeyUtils.getCompressedPubKeyFromPem (pem1);
			Assert.AreEqual (pubKeyCompressed1, compPubKey);
		}

		[Test]
		public static void testPrivateKeyFromPem()
		{
			string privKey = KeyUtils.getPrivKeyFromPem (pem1);
			Assert.AreEqual (privateKey1, privKey);
		}

		[Test]
		public static void testSinFromPem()
		{
			string sinTest = KeyUtils.getSinFromPem (pem1);
			Assert.AreEqual (sin1, sinTest);

		}

		[Test]
		public static void testSignMessageWithPem()
		{
			string signedMsg = KeyUtils.signMsgWithPem (msg1, pem1);

			byte[] msgBytes = Encoding.UTF8.GetBytes (msg1);
			SHA256Managed hashstring = new SHA256Managed();
			byte[] msgHash = hashstring.ComputeHash(msgBytes);

			byte[] signedMsgBytes = hexToBytes (signedMsg);
			byte[] pubKeyBytes = hexToBytes (KeyUtils.getCompressedPubKeyFromPem (pem1));

			Assert.That(BitCoinSharp.EcKey.Verify (msgHash, signedMsgBytes, pubKeyBytes));
		}


		// ********************************
		// *       2nd set of tests       *
		// ********************************

		[Test]
		public static void testGeneratePem2()
		{
			string pemTest2 = KeyUtils.generatePem ();
			Assert.That(Regex.IsMatch(pemTest2, pemPattern));
		}

		[Test]
		public static void testCompressedKeyFromPem2()
		{
			string compPubKey2 = KeyUtils.getCompressedPubKeyFromPem (pem2);
			Assert.AreEqual (pubKeyCompressed2, compPubKey2);
		}

		[Test]
		public static void testPrivateKeyFromPem2()
		{
			string privKey2 = KeyUtils.getPrivKeyFromPem (pem2);
			Assert.AreEqual (privateKey2, privKey2);
		}

		[Test]
		public static void testSinFromPem2()
		{
			string sinTest2 = KeyUtils.getSinFromPem (pem2);
			Assert.AreEqual (sin2, sinTest2);

		}

		[Test]
		public static void testSignMessageWithPem2()
		{
			string signedMsg2 = KeyUtils.signMsgWithPem (msg2, pem2);

			byte[] msgBytes2 = Encoding.UTF8.GetBytes (msg2);
			SHA256Managed hashstring2 = new SHA256Managed();
			byte[] msgHash2 = hashstring2.ComputeHash(msgBytes2);

			byte[] signedMsgBytes2 = hexToBytes (signedMsg2);
			byte[] pubKeyBytes2 = hexToBytes (KeyUtils.getCompressedPubKeyFromPem (pem2));

			Assert.That(BitCoinSharp.EcKey.Verify (msgHash2, signedMsgBytes2, pubKeyBytes2));
		}


		// ********************************
		// *       3rd set of tests       *
		// ********************************

		[Test]
		public static void testGeneratePem3()
		{
			string pemTest3 = KeyUtils.generatePem ();
			Assert.That(Regex.IsMatch(pemTest3, pemPattern));
		}

		[Test]
		public static void testCompressedKeyFromPem3()
		{
			string compPubKey3 = KeyUtils.getCompressedPubKeyFromPem (pem3);
			Assert.AreEqual (pubKeyCompressed3, compPubKey3);
		}

		[Test]
		public static void testPrivateKeyFromPem3()
		{
			string privKey3 = KeyUtils.getPrivKeyFromPem (pem3);
			Assert.AreEqual (privateKey3, privKey3);
		}

		[Test]
		public static void testSinFromPem3()
		{
			string sinTest3 = KeyUtils.getSinFromPem (pem3);
			Assert.AreEqual (sin3, sinTest3);

		}

		[Test]
		public static void testSignMessageWithPem3()
		{
			string signedMsg3 = KeyUtils.signMsgWithPem (msg3, pem3);

			byte[] msgBytes3 = Encoding.UTF8.GetBytes (msg3);
			SHA256Managed hashstring3 = new SHA256Managed();
			byte[] msgHash3 = hashstring3.ComputeHash(msgBytes3);

			byte[] signedMsgBytes3 = hexToBytes (signedMsg3);
			byte[] pubKeyBytes3 = hexToBytes (KeyUtils.getCompressedPubKeyFromPem (pem3));

			Assert.That(BitCoinSharp.EcKey.Verify (msgHash3, signedMsgBytes3, pubKeyBytes3));
		}



		// ****************************************************************
		// *      Private Methods to convert hex string to byte array      *
		// ****************************************************************

		private static int getHexVal(char hex)
		{
			int val = (int)hex;
			return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
		}


		private static byte[] hexToBytes(String hex) 
		{
			char[] hexArray = hex.ToCharArray();

			if (hex.Length % 2 == 1) {
				throw new ArgumentException("Error: The binary key cannot have an odd number of digits");
			}

			byte[] arr = new byte[hex.Length >> 1];

			for (int i = 0; i < hex.Length >> 1; ++i) {
				arr[i] = (byte)((getHexVal(hexArray[i << 1]) << 4) + (getHexVal(hexArray[(i << 1) + 1])));
			}

			return arr;
		}


	}
}
