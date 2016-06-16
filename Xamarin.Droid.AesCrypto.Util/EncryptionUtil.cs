using System;
using System.Text;
using Android.Content;
using Com.Tozny.Crypto.Android;

namespace Xamarin.Droid.AesCrypto.Util
{
  public class EncryptionUtil
  {
    public EncryptionUtil ()
    {
    }

    public static EncryptedTuple Encrypt (Context context, string alias, string clearText)
    {
      var secretKeys = AesCbcWithIntegrity.GenerateKey ();
      var confidentialKeyWrapper = new SecretKeyWrapper (context, alias + "-confidential");
      var integrityKeyWrapper = new SecretKeyWrapper (context, alias + "-integrity");
      var wrappedConfidentialKey = confidentialKeyWrapper.Wrap (secretKeys.ConfidentialityKey);
      var wrappedIntegrityKey = integrityKeyWrapper.Wrap (secretKeys.IntegrityKey);

      var encryptedBundle = AesCbcWithIntegrity.Encrypt (Encoding.UTF8.GetBytes (clearText), secretKeys);
      return new EncryptedTuple (encryptedBundle.ToString (), Convert.ToBase64String (wrappedConfidentialKey), Convert.ToBase64String (wrappedIntegrityKey));
    }

    public static string Decrypt (Context context, string alias, EncryptedTuple encryptedTuple)
    {
      var confidentialKeyWrapper = new SecretKeyWrapper (context, alias + "-confidential");
      var integrityKeyWrapper = new SecretKeyWrapper (context, alias + "-integrity");
      var confidentialKey = confidentialKeyWrapper.Unwrap (Convert.FromBase64String(encryptedTuple.EncryptedSymmetricKey));
      var integrityKey = integrityKeyWrapper.Unwrap (Convert.FromBase64String (encryptedTuple.EncryptedIntegrityKey));
      var secretKeys = new AesCbcWithIntegrity.SecretKeys (confidentialKey, integrityKey);

      return AesCbcWithIntegrity.DecryptString (new AesCbcWithIntegrity.CipherTextIvMac(encryptedTuple.EncryptedText), secretKeys);
    }
  }
}

