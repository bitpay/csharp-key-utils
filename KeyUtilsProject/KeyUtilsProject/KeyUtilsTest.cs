using System;
using System.Text.RegularExpressions;
using NUnit.Framework;

namespace KeyUtilsProject
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
//		static string sin1 = "TeyN4LPrXiG5t2yuSamKqP3ynVk3F52iHrX";
//		static string msg1 = "This is a test message.";
//
//		static string pem2 = "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEINMwkuB8YAtSTJzUNals8F2lXxsLIncL3rOc8dqRdps8oAcGBSuBBAAK\noUQDQgAEn0OPHdZ0hx+tLRobqDMbC5U12k+BAzynN/wMjzG3axbkgNIFGLim30pf\nh1Lvp4eFVHUydkbP250fTOrJ4zo7RQ==\n-----END EC PRIVATE KEY-----\n";
//		static string pubKeyCompressed2 = "039F438F1DD674871FAD2D1A1BA8331B0B9535DA4F81033CA737FC0C8F31B76B16";
//		static string privateKey2 = "D33092E07C600B524C9CD435A96CF05DA55F1B0B22770BDEB39CF1DA91769B3C";
//		static string sin2 = "TfFW1ePJ5q6EZKBsYUrMGQEbb6z4fBmx6BW";
//		static string msg2 = "Testing by using this message.";

		public static void Main() 
		{
			testGeneratePem();
			testCompressedKeyFromPem ();
			testPrivateKeyFromPem ();
		}


		[Test]
		public static void testGeneratePem()
		{
			string pemTest = KeyUtils.generatePem ();
			Console.WriteLine ("Generated Pem: \n" + pemTest);
			Assert.That(Regex.IsMatch(pemTest, pemPattern));
		}

		[Test]
		public static void testCompressedKeyFromPem()
		{
			string compPubKey = KeyUtils.getCompressedPubKeyFromPem (pem1);
			Console.WriteLine ("Comp Pub Key 1: \n" + compPubKey);
			Assert.AreEqual (pubKeyCompressed1, compPubKey);
		}

		[Test]
		public static void testPrivateKeyFromPem()
		{
			string privKey = KeyUtils.getPrivKeyFromPem (pem1);
			Console.WriteLine ("Private Key 1: \n" + privKey);
			Assert.AreEqual (privateKey1, privKey);
		}

	}
}

