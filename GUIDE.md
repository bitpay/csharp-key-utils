# Using the BitPay C# Key Utilities Library

## Quick Start
### Installation

To use the C# Key Utilities, you need to create a new C# project that can compile with Mono. In the References folder within your project, add the following dependencies, which can be downloaded from [GitHub](https://github.com/bitpay/csharp-key-utils) or [CodePlex](https://bitpaycsharpkeyutils.codeplex.com/SourceControl/latest#README.md). (_Note: if you are downloading from GitHub, the CSharpKeyUtils.dll is available in the ["releases" section here](https://github.com/bitpay/csharp-key-utils/releases) while the other .dll files can be found in the source folder._):

* `CSharpKeyUtils.dll`
* `BitCoinSharp.dll`
* `BouncyCastle.Crypto.dll`
* `nunit.framework.dll`

Once you have these, you will need to make sure that you have the following "using..." statements at the top of you C# file.

* `using System;`
* `using CSharpKeyUtils;`

## Using the Functions
To use the C# Key Utilities functions, make sure to complete the steps above. To use a function, type in `KeyUtils.function_name()` (for example: `KeyUtils.generatePem()`, `KeyUtils.getSinFromPem(pemVariableName)`).
The following functions are provided (all functions return a string):

* `generatePem()` - creates a new set of public/private keys and returns the PEM string associated with those keys.
* `getCompressedPubKeyFromPem(string pem)` - uses the PEM to retrieve the compressed public key.
* `getPrivKeyFromPem(string pem)` - uses the PEM to retrieve the private key.
* `getSinFromPem(string pem)` - uses the PEM to generate the associated SIN.
* `signMsgWithPem(string msg, string pem)` - uses the PEM to sign a string message. This signature can be used later with the BitPay API.

## API Documentation

API Documentation is available on the [BitPay site](https://bitpay.com/api).

## Running the Tests
Once you have completed the installation steps, you can run the test class with `KeyUtilsTest.Main();`. However, you will not receive any feedback if all the tests pass. You will only get a message if one or more tests fail.
