using System;
using Xunit;

using Com.Tozny.Crypto.Android;
using System.Text;
using Android.Content;
using Xamarin.Droid.AesCrypto.Util;
using System.Linq;

namespace AesCryptoSample
{
  public class AesTest
  {
    public static Context context;
    public const string UnitTestAlias = "Unit Test";

    public AesTest ()
    {
    }

    [Fact]
    public void TestAesCbcWithIntegrityRoundTrip ()
    {
      var privateKey = AesCbcWithIntegrity.GenerateKey ();
      var mySecretText = "This is my secret";
      var mySecretBytes = Encoding.UTF8.GetBytes (mySecretText);
      var cipherText = AesCbcWithIntegrity.Encrypt (mySecretBytes, privateKey);

      Assert.False (AesCbcWithIntegrity.ConstantTimeEq (mySecretBytes, cipherText.GetCipherText ()));

      var decryptedBytes = AesCbcWithIntegrity.Decrypt (cipherText, privateKey);
      var decryptedText = Encoding.UTF8.GetString (decryptedBytes);

      Assert.True (mySecretText == decryptedText, 
                   string.Format("Expect {0} but got {1}", mySecretText, decryptedText));
    }

    [Fact]
    public void TestSecretKeyWrapperRoundTrip ()
    {
      var secretKeyWrapper = new SecretKeyWrapper (context, UnitTestAlias);
      var secretKeys = AesCbcWithIntegrity.GenerateKey ();
      var wrappedKey = secretKeyWrapper.Wrap (secretKeys.ConfidentialityKey);

      Assert.False (AesCbcWithIntegrity.ConstantTimeEq (secretKeys.ConfidentialityKey.GetEncoded (),
                                                      wrappedKey));

      var unwrappedKey = secretKeyWrapper.Unwrap (wrappedKey);

      Assert.True (AesCbcWithIntegrity.ConstantTimeEq (secretKeys.ConfidentialityKey.GetEncoded (),
                                                       unwrappedKey.GetEncoded()));
    }

    [Fact]
    public void CompleteExample ()
    {
      var mySecretText = "This is my secret";
      const string completeExampleAlias = "CompleteExample";
      var encryptedBundle = EncryptionUtil.Encrypt (context, completeExampleAlias, mySecretText);

      Assert.False (mySecretText == encryptedBundle.EncryptedText);

      var decryptedText = EncryptionUtil.Decrypt (context, completeExampleAlias, encryptedBundle);

      Assert.True (mySecretText == decryptedText,
                   string.Format ("Expect {0} but got {1}", mySecretText, decryptedText));
    }
  }
}

