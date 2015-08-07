using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Globalization;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Math;

using BitCoinSharp;

namespace CSharpKeyUtils
{
	public class KeyUtils
	{
		private static string pemPattern = "-----BEGIN EC PRIVATE KEY-----\nMHQCA.*SuBBAAK\noUQDQ.*\n.*\n.*END EC PRIVATE KEY-----\n"; 

		public static String generatePem()
		{
			// Create a new key
			BitCoinSharp.EcKey keys = new BitCoinSharp.EcKey();

			StringWriter stringWriter = new StringWriter ();
			PemWriter pemWriter = new PemWriter (stringWriter);

			const string DER1 = "30740201010420";

			string privKey = (privKeyFromKeyPair (keys));

			// Make sure private key is in correct format
			privKey = checkHas64 (privKey); 

			const string DER2 = "a0070605";
			const string DER3 = "2b8104000a";
			const string DER4 = "a144034200";
			string pubKey = uncompressedPubKeyFromKeyPair (keys);

			string fullDER = DER1 + privKey + DER2 + DER3 + DER4 + pubKey;

			PemObject pemObj = new PemObject("EC PRIVATE KEY", hexToBytes(fullDER));
			pemWriter.WriteObject(pemObj);

			string pem = stringWriter.ToString ();

			return pem;
		}



		public static string getCompressedPubKeyFromPem (string pem)
		{
			string[] keyInfo = keysFromPem (pem);
			string compressedPubKey = keyInfo[1];

			return compressedPubKey;
		}

		public static string getPrivKeyFromPem (string pem)
		{
			string[] keyInfo = keysFromPem (pem);
			string privKey = keyInfo[2];

			return privKey;
		}


		public static string getSinFromPem (string pem)
		{
			string[] keyInfo = keysFromPem (pem);
			string hexPubKey = keyInfo [1];

			// Step 1 and 2
			// Hex to Bytes, SHA-256 and RIPEMD-160		
			byte[] bytesPubKey1 = hexToBytes(hexPubKey);
			byte[] bytesPubKey2 = Utils.Sha256Hash160(bytesPubKey1);
			String shaAndRipe = Utils.BytesToHexString(bytesPubKey2);

			// Step 3
			// Add 0F02 to Hex of Step 2
			String step3 = "0F02" + shaAndRipe;

			// Step 4
			// Hex to Bytes, Double SHA-256
			byte[] bytesPubKey3 = hexToBytes(step3);
			byte[] bytesPubKey4 = Utils.DoubleDigest(bytesPubKey3); //Utils.doubleDigest(bytesPubKey3);

			// Step 5
			// Substring of first 4 bytes (first 8 characters)
			String step4Hex = Utils.BytesToHexString(bytesPubKey4);
			String step5 = step4Hex.Substring(0, 8);

			// Step 6
			// Combine step 3 and step 5
			String step6 = step3 + step5;

			// Convert to base 58
			byte[] step6bytes = hexToBytes(step6);
			String sin = Base58.Encode(step6bytes);

			return sin;
		}

		public static string signMsgWithPem (string msg, string pem)
		{
			if (msg == null || msg.Length == 0)
				throw new ArgumentException("Message cannot be empty.");

			string[] keyInfo = keysFromPem (pem);
			string privKey = keyInfo [2];
			//			Console.WriteLine ("Uncomp PubKey: " + keyInfo[0]);

			BigInteger privKeyNum = new BigInteger(privKey, 16);
			BitCoinSharp.EcKey keys = new BitCoinSharp.EcKey (privKeyNum);

			byte[] msgBytes = Encoding.UTF8.GetBytes (msg);

			SHA256Managed hashstring = new SHA256Managed();
			byte[] msgHash = hashstring.ComputeHash(msgBytes);

			byte[] signedMsgBytes = keys.Sign (msgHash);
			string signedMsg = Utils.BytesToHexString (signedMsgBytes);

			return signedMsg;
		}


		// *************************************
		// *          Private Methods          *
		// *************************************

		private static string uncompressedPubKeyFromKeyPair(BitCoinSharp.EcKey keys)
		{
			string keyString = keys.ToString ();

			int indexPubKeyStart = keyString.IndexOf ("pub:") + 4; // to account for the actual chars "pub:"
			int indexPubKeyEnd = keyString.LastIndexOf ("priv:") - 1; // to account for the space char before "priv:"

			string pubKeyString = keyString.Substring (indexPubKeyStart, indexPubKeyEnd - indexPubKeyStart);
			pubKeyString = checkHas64 (pubKeyString);

			return pubKeyString;
		}

		private static string privKeyFromKeyPair(BitCoinSharp.EcKey keys)
		{
			string keyString = keys.ToString ();

			int indexPrivKeyStart = keyString.IndexOf ("priv:") + 5; // to account for the actual chars "priv:"

			string privKeyString = keyString.Substring (indexPrivKeyStart);
			privKeyString = checkHas64 (privKeyString);
			return privKeyString;
		}


		private static string[] keysFromPem(string pem)
		{
			checkValidPEM (pem);
			StringReader stringReader = new StringReader (pem);
			PemReader pemReader = new PemReader (stringReader);

			PemObject pemObj = pemReader.ReadPemObject ();

			string DERfromPEM = BitCoinSharp.Utils.BytesToHexString (pemObj.Content);

			string uncompPubKey = DERfromPEM.Substring (DERfromPEM.Length - 128);
			string compPubKey = compPubKeyFromUncompPubKey (uncompPubKey);
			string privKey = DERfromPEM.Substring (14, 64);

			compPubKey = checkHas64 (compPubKey);
			privKey = checkHas64 (privKey);

			string[] keyInfo = {uncompPubKey.ToUpper (), compPubKey.ToUpper (), privKey.ToUpper ()};
			return keyInfo;

		}

		private static string compPubKeyFromUncompPubKey(string uncompPubKey)
		{
			string xAndY = uncompPubKey; // removes leading "04"
			string xVal = xAndY.Substring(0, 64);
			int endOfY = int.Parse(xAndY.Substring (124), NumberStyles.AllowHexSpecifier);

			string prefix;
			if (endOfY % 2 == 1) {
				prefix = "03";
			} else {
				prefix = "02";
			}

			string compPubKey = prefix + xVal;
			return compPubKey;
		}


		private static void checkValidPEM(String pem) {
			Boolean validPem = Regex.IsMatch (pem, pemPattern);
			if (!validPem) {
				throw new ArgumentException("PEM is not in a valid format.");
			}

		}

		private static string checkHas64(String str) {
			string str2 = str;
			if (str2.Length % 2 == 1 && str2.Length < 64)
				str2 = "0" + str2;

			while (str2.Length > 64 && str2.Substring (0, 2) == "00") 
				str2 = str2.Substring (2);

			while (str2.Length < 64)
				str2 = "00" + str2;

			return str2;
		}

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
