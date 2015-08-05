using System;
using System.IO;
using System.Text;
using System.Globalization;
using NUnit.Framework;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Utilities.IO.Pem;
using BitCoinSharp;

namespace KeyUtilsProject
{
	public class KeyUtils
	{

		public static String generatePem()
		{
			BitCoinSharp.EcKey keys = new BitCoinSharp.EcKey();
			Console.WriteLine (keys.ToString());
			StringWriter stringWriter = new StringWriter ();
			PemWriter pemWriter = new PemWriter (stringWriter);

	//		byte[] bArray = Encoding.UTF8.GetBytes (inputString);

			const string DER1 = "30740201010420";


			string privKey = (privKeyFromKeyPair (keys));
			Console.WriteLine (privKey);
			if (privKey.Length > 64 && privKey.Substring (0, 2) == "00") {
				privKey = privKey.Substring (2);
			}

			const string DER2 = "a0070605";
			const string DER3 = "2b8104000a";
			const string DER4 = "a144034200";
			string pubKey = uncompressedPubKeyFromKeyPair (keys);

			string fullDER = DER1 + privKey + DER2 + DER3 + DER4 + pubKey;

			PemObject pemObj = new PemObject("EC PRIVATE KEY", hexToBytes(fullDER));
			pemWriter.WriteObject(pemObj);
			
			return stringWriter.ToString ();
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

		private static string createKeyPair()
		{
			BitCoinSharp.EcKey key = new BitCoinSharp.EcKey();
			return key.ToString();
			
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

		private static byte[] GetBytes(string str)
		{
			byte[] bytes = new byte[str.Length * sizeof(char)];
			System.Buffer.BlockCopy(str.ToCharArray(), 0, bytes, 0, bytes.Length);
			return bytes;
		}

		private static string uncompressedPubKeyFromKeyPair(BitCoinSharp.EcKey keys)
		{
			string keyString = keys.ToString ();

			int indexPubKeyStart = keyString.IndexOf ("pub:") + 4; // to account for the actual chars "pub:"
			int indexPubKeyEnd = keyString.LastIndexOf ("priv:") - 1; // to account for the space char before "priv:"

			string pubKeyString = keyString.Substring (indexPubKeyStart, indexPubKeyEnd - indexPubKeyStart);
			return pubKeyString;
		}

		private static string privKeyFromKeyPair(BitCoinSharp.EcKey keys)
		{
			string keyString = keys.ToString ();

			int indexPrivKeyStart = keyString.IndexOf ("priv:") + 5; // to account for the actual chars "priv:"

			string privKeyString = keyString.Substring (indexPrivKeyStart);
			return privKeyString;
		}


		private static string[] keysFromPem(string pem)
		{

			StringReader stringReader = new StringReader (pem);
			PemReader pemReader = new PemReader (stringReader);

			PemObject pemObj = pemReader.ReadPemObject ();

			string DERfromPEM = BitCoinSharp.Utils.BytesToHexString (pemObj.Content);

			string uncompPubKey = DERfromPEM.Substring (DERfromPEM.Length - 128);
			string compPubKey = compPubKeyFromUncompPubKey (uncompPubKey);
			string privKey = DERfromPEM.Substring (14, 64);

			string[] keyInfo = {uncompPubKey.ToUpper (), compPubKey.ToUpper (), privKey.ToUpper ()};
			return keyInfo;

		}

		private static string compPubKeyFromUncompPubKey(string uncompPubKey)
		{
			string xAndY = uncompPubKey; // removes leading "04"
			string xVal = xAndY.Substring(0, 64);
			int endOfY = int.Parse(xAndY.Substring (124), NumberStyles.AllowHexSpecifier);

//			Console.WriteLine ("Full: " + xAndY);
//			Console.WriteLine ("X: " + xVal);
//			Console.WriteLine ("Y ending: " + endOfY);

			string prefix;
			if (endOfY % 2 == 1) {
				prefix = "03";
			} else {
				prefix = "02";
			}

			string compPubKey = prefix + xVal;
			return compPubKey;
		}

		
	}
}

